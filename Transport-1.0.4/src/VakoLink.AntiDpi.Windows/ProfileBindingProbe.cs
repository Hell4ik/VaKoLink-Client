using System.Diagnostics;
using System.Security.Cryptography;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public sealed record ProcessBindingEvidence(
    string ProfileId,
    uint ProcessId,
    DateTimeOffset CreationUtc,
    string? ImageSha256,
    string HashState,
    string BindingSource, string? ComponentFileName = null, string? VersionDirectory = null,
    uint? ParentProcessId = null, DateTimeOffset? ParentCreationUtc = null);

public sealed record ProfileBindingEvidence(string ProfileId, IReadOnlyList<ProcessBindingEvidence> Identities);

/// <summary>Exact-image process probe only. It opens no interception handles and makes no traffic attribution claim.</summary>
public static class ProfileBindingProbe
{
    public static IReadOnlyList<ProfileBindingEvidence> CaptureProfileBindings(IReadOnlyList<AppProfile> profiles, IReadOnlyList<AppProfile>? approvedProfiles = null)
    {
        ArgumentNullException.ThrowIfNull(profiles);
        var selectedProfiles = profiles.ToArray();
        if (selectedProfiles.Length == 0) return Array.Empty<ProfileBindingEvidence>();
        if (ConfigurationValidator.Validate(selectedProfiles, Array.Empty<ScenarioDefinition>(), TimeSpan.FromMinutes(1)).Count != 0)
            throw new ArgumentException("PROFILE_BINDING_CONFIGURATION_INVALID", nameof(profiles));
        var approved = approvedProfiles ?? new ApprovedApplicationComponents(selectedProfiles).Profiles;
        var collector = new ProfileBindingCollector(selectedProfiles, approvedProfiles: () => approved);
        var parents = ProcessLineage.Capture();
        var processes = Process.GetProcesses();
        try
        {
            foreach (var process in processes.Take(8192))
            {
                try
                {
                    var identity = ProcessOwnership.ReadIdentity(unchecked((uint)process.Id));
                    if (identity is null) continue;
                    var profile = OwnershipPolicy.MatchImage(approved, identity);
                    if (profile is not null)
                    {
                        var parentId = parents.GetValueOrDefault(identity.ProcessId);
                        var parent = parentId == 0 ? null : ProcessOwnership.ReadIdentity(parentId);
                        collector.Record(profile.Id, identity, "exact approved image+birth; parent snapshot NOT authorization; not packet attribution",
                            parent is not null && parent.CreationTime <= identity.CreationTime ? parent : null);
                    }
                }
                catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
                { /* Inaccessible processes are not evidence of a binding. */ }
            }
        }
        finally { foreach (var process in processes) process.Dispose(); }
        return collector.Snapshot();
    }
}

internal sealed record ImageHashEvidence(string? Sha256, string State);

internal sealed class BoundedImageHashCache
{
    internal const int MaximumEntries = 64;
    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private long _sequence;
    internal int Count { get { lock (_gate) return _entries.Count; } }

    internal ImageHashEvidence GetOrAdd(string normalizedPath, long length, DateTime modifiedUtc, Func<ImageHashEvidence> factory)
    {
        lock (_gate)
        {
            if (_entries.TryGetValue(normalizedPath, out var found) && found.Length == length && found.ModifiedUtc == modifiedUtc)
            {
                _entries[normalizedPath] = found with { Sequence = ++_sequence };
                return found.Hash;
            }
            // Hash once under the cache lock, including concurrent probes of the same metadata.
            var hash = factory();
            if (!_entries.ContainsKey(normalizedPath) && _entries.Count >= MaximumEntries)
                _entries.Remove(_entries.MinBy(pair => pair.Value.Sequence).Key);
            _entries[normalizedPath] = new(length, modifiedUtc, hash, ++_sequence);
            return hash;
        }
    }

    private sealed record Entry(long Length, DateTime ModifiedUtc, ImageHashEvidence Hash, long Sequence);
}

/// <summary>At most eight image hashes computed once before interception, and at most 32 immutable identities.</summary>
internal sealed class ProfileBindingCollector
{
    internal const int MaximumIdentities = 32;
    internal const long MaximumImageBytes = 512L * 1024 * 1024;
    private static readonly BoundedImageHashCache ImageHashes = new();
    private readonly object _gate = new();
    private readonly AppProfile[] _profiles;
    private readonly Dictionary<(string Id, string Path), ImageHashEvidence> _hashes = new();
    private readonly Func<IReadOnlyList<AppProfile>>? _approvedProfiles;
    private readonly Dictionary<(string ProfileId, uint ProcessId, long Creation), ProcessBindingEvidence> _identities = new();
    private long _dropped;

    internal ProfileBindingCollector(IReadOnlyList<AppProfile> profiles, Func<AppProfile, ImageHashEvidence>? hash = null, Func<IReadOnlyList<AppProfile>>? approvedProfiles = null)
    {
        if (profiles.Count > 8) throw new ArgumentOutOfRangeException(nameof(profiles));
        _profiles = profiles.ToArray();
        _approvedProfiles = approvedProfiles;
        PrepareHashes(hash);
    }

    internal void PrepareHashes(Func<AppProfile, ImageHashEvidence>? hash = null)
    {
        var profiles = (_approvedProfiles?.Invoke() ?? _profiles).Take(64).ToArray();
        lock (_gate)
            foreach (var key in _hashes.Keys.Where(key => !profiles.Any(profile => profile.Id == key.Id && profile.ExecutablePath.Equals(key.Path, StringComparison.OrdinalIgnoreCase))).ToArray())
                _hashes.Remove(key);
        foreach (var profile in profiles)
        {
            // Hashing never occurs in the network packet loop.
            var value = (hash ?? HashImage)(profile);
            lock (_gate) _hashes[(profile.Id, Path.GetFullPath(profile.ExecutablePath).ToUpperInvariant())] = value;
        }
    }

    internal long Dropped { get { lock (_gate) return _dropped; } }

    internal void Record(string profileId, ProcessIdentity identity, string source, ProcessIdentity? parent = null)
    {
        lock (_gate)
        {
            if (!_hashes.TryGetValue((profileId, Path.GetFullPath(identity.ImagePath).ToUpperInvariant()), out var hash)) return;
            if (identity.ProcessId == 0 || identity.CreationTime <= 0
                || OwnershipPolicy.MatchImage(_approvedProfiles?.Invoke() ?? _profiles, identity)?.Id != profileId) return;
            var key = (profileId, identity.ProcessId, identity.CreationTime);
            if (_identities.ContainsKey(key)) return;
            if (_identities.Count >= MaximumIdentities) { _dropped++; return; }
            DateTimeOffset created;
            try { created = DateTimeOffset.FromFileTime(identity.CreationTime).ToUniversalTime(); }
            catch (ArgumentOutOfRangeException) { return; }
            _identities[key] = new(profileId, identity.ProcessId, created, hash.Sha256, hash.State, source,
                Path.GetFileName(identity.ImagePath), Path.GetFileName(Path.GetDirectoryName(identity.ImagePath)), parent?.ProcessId,
                parent is null ? null : DateTimeOffset.FromFileTime(parent.CreationTime));
        }
    }

    internal IReadOnlyList<ProfileBindingEvidence> Snapshot()
    {
        lock (_gate)
        {
            return Array.AsReadOnly(_profiles.Select(profile => new ProfileBindingEvidence(profile.Id,
                Array.AsReadOnly(_identities.Values.Where(identity => identity.ProfileId == profile.Id)
                    .OrderBy(identity => identity.ProcessId).ThenBy(identity => identity.CreationUtc).ToArray()))).ToArray());
        }
    }

    internal static ImageHashEvidence HashImage(AppProfile profile)
    {
        try
        {
            var file = new FileInfo(profile.ExecutablePath);
            if (!file.Exists || file.Length is <= 0 or > MaximumImageBytes
                || (file.Attributes & FileAttributes.ReparsePoint) != 0) return new(null, "IMAGE_HASH_UNAVAILABLE_OR_OUT_OF_BOUNDS");
            var originalLength = file.Length;
            var originalModified = file.LastWriteTimeUtc;
            return ImageHashes.GetOrAdd(file.FullName, originalLength, originalModified,
                () => HashUncachedFile(file, originalLength, originalModified));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        { return new(null, "IMAGE_HASH_UNAVAILABLE"); }
    }

    private static ImageHashEvidence HashUncachedFile(FileInfo file, long originalLength, DateTime originalModified)
    {
        try
        {
            using var stream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 65536, FileOptions.SequentialScan);
            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[65536];
            var hashStarted = Stopwatch.GetTimestamp();
            long consumed = 0;
            int received;
            while ((received = stream.Read(buffer)) != 0)
            {
                consumed += received;
                if (consumed > MaximumImageBytes) return new(null, "IMAGE_HASH_OUT_OF_BOUNDS");
                if (Stopwatch.GetElapsedTime(hashStarted) > TimeSpan.FromSeconds(2)) return new(null, "IMAGE_HASH_DEADLINE");
                hasher.AppendData(buffer, 0, received);
            }
            file.Refresh();
            return consumed == originalLength && file.Exists && file.Length == originalLength && file.LastWriteTimeUtc == originalModified
                ? new(Convert.ToHexString(hasher.GetHashAndReset()), "SHA256_DISK_FILE_PATH_SIZE_MTIME_CACHE_NOT_LOADED_MEMORY")
                : new(null, "IMAGE_CHANGED_DURING_HASH");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        { return new(null, "IMAGE_HASH_UNAVAILABLE"); }
    }
}
