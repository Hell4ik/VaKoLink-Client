using System.Security.Cryptography.X509Certificates;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public sealed record ApplicationComponentEvidence(string ProfileId, string FileName, string VersionDirectory,
    string Decision, string? ImageSha256, string SignatureBasis);

// Resolves a finite set of exact images outside packet workers. No arbitrary descendants,
// path-prefix mutation authorization, command-line capture or executable-name-only matching.
public sealed class ApprovedApplicationComponents
{
    private readonly IReadOnlyList<AppProfile> _selected;
    private IReadOnlyList<AppProfile> _approved;
    private IReadOnlyList<ApplicationComponentEvidence> _evidence = [];
    private readonly string _root;
    private readonly Func<string, bool>? _trustFixture;
    private readonly HashSet<string> _installationAnchors = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, (long Length, DateTime Modified, bool Trusted)> _signatures = new(StringComparer.OrdinalIgnoreCase);
    public IReadOnlyList<AppProfile> Profiles => Volatile.Read(ref _approved);
    public IReadOnlyList<ApplicationComponentEvidence> Evidence => Volatile.Read(ref _evidence);
    private string[] _publishedTrustedIds = [];
    internal bool IsTrustedDiscordProfile(string id) => Volatile.Read(ref _publishedTrustedIds).Contains(id, StringComparer.OrdinalIgnoreCase);
    public ApprovedApplicationComponents(IReadOnlyList<AppProfile> profiles) : this(profiles,
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Discord"), null)
    { }
    internal ApprovedApplicationComponents(IReadOnlyList<AppProfile> profiles, string root, Func<string, bool>? trustFixture)
    {
        _selected = profiles.ToArray(); _approved = _selected;
        _root = root; _trustFixture = trustFixture;
        Refresh();
    }
    internal static bool IsCandidate(AppProfile selected, string path, string root)
    {
        if (!Path.GetFileName(selected.ExecutablePath).Equals("Discord.exe", StringComparison.OrdinalIgnoreCase)) return false;
        var prefix = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var chosen = Path.GetFullPath(selected.ExecutablePath);
        var candidate = Path.GetFullPath(path);
        if (!chosen.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) || !candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
        var relative = Path.GetRelativePath(root, candidate).Split(Path.DirectorySeparatorChar);
        return relative.Length == 1 && (relative[0].Equals("Update.exe", StringComparison.OrdinalIgnoreCase) || relative[0].Equals("Discord.exe", StringComparison.OrdinalIgnoreCase))
            || relative.Length == 2 && System.Text.RegularExpressions.Regex.IsMatch(relative[0], @"\Aapp-[0-9]+\.[0-9]+\.[0-9]+\z")
                && (relative[1].Equals("Discord.exe", StringComparison.OrdinalIgnoreCase) || relative[1].Equals("updater_launcher.exe", StringComparison.OrdinalIgnoreCase));
    }
    private bool Trusted(string path)
    {
        if (_trustFixture is not null) return File.Exists(path) && _trustFixture(path); // Internal offline test only.
        var file = new FileInfo(path);
        if (!file.Exists || file.Length is <= 0 or > ProfileBindingCollector.MaximumImageBytes) return false;
        for (FileSystemInfo? current = file; current is not null; current = current is FileInfo f ? f.Directory : ((DirectoryInfo)current).Parent)
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0) return false;
        if (_signatures.TryGetValue(path, out var old) && old.Length == file.Length && old.Modified == file.LastWriteTimeUtc) return old.Trusted;
        bool trusted = false;
        try
        {
            if (AuthenticodeVerifier.IsTrusted(path))
            {
                using var signed = X509Certificate.CreateFromSignedFile(path);
                using var certificate = new X509Certificate2(signed);
                trusted = certificate.GetNameInfo(X509NameType.SimpleName, false) == "Discord Inc.";
            }
        }
        catch (Exception error) when (error is System.Security.Cryptography.CryptographicException or IOException or UnauthorizedAccessException) { }
        if (_signatures.Count >= 64) _signatures.Clear();
        _signatures[path] = (file.Length, file.LastWriteTimeUtc, trusted);
        return trusted;
    }
    public void Refresh()
    {
        var approved = _selected.Where(profile => !IsCandidate(profile, profile.ExecutablePath, _root) || Trusted(profile.ExecutablePath)).ToList();
        var evidence = new List<ApplicationComponentEvidence>();
        foreach (var profile in _selected)
        {
            evidence.Add(new(profile.Id, Path.GetFileName(profile.ExecutablePath), Path.GetFileName(Path.GetDirectoryName(profile.ExecutablePath))!,
                approved.Contains(profile) ? "EXPLICIT_SELECTED_IMAGE" : "REJECTED_SELECTED_DISCORD_IMAGE_UNTRUSTED_OR_MISSING",
                ProfileBindingCollector.HashImage(profile).Sha256, "Explicit user image; Discord installation additionally requires publisher trust; not an implicit child process grant"));
            if (!IsCandidate(profile, profile.ExecutablePath, _root)) continue;
            try
            {
                if (Trusted(profile.ExecutablePath)) _installationAnchors.Add(profile.Id);
                // A verified installation anchor lasts only this bounded session/catalog, never persisted.
                // An updater may remove the originally selected old version while a new trusted version appears.
                if (!_installationAnchors.Contains(profile.Id)) continue;
                var candidates = new List<string> { Path.Combine(_root, "Update.exe"), Path.Combine(_root, "Discord.exe") };
                foreach (var directory in Directory.EnumerateDirectories(_root, "app-*")
                    .OrderByDescending(directory => Version.TryParse(Path.GetFileName(directory)[4..], out var version) ? version : null).Take(6))
                { candidates.Add(Path.Combine(directory, "Discord.exe")); candidates.Add(Path.Combine(directory, "updater_launcher.exe")); }
                foreach (var path in candidates.Take(14))
                {
                    if (path.Equals(profile.ExecutablePath, StringComparison.OrdinalIgnoreCase) || !File.Exists(path) || !IsCandidate(profile, path, _root)) continue;
                    var trusted = Trusted(path);
                    evidence.Add(new(profile.Id, Path.GetFileName(path), Path.GetFileName(Path.GetDirectoryName(path))!,
                        trusted ? "APPROVED_SIGNED_DISCORD_COMPONENT" : "REJECTED_UNTRUSTED_COMPONENT", trusted ? ProfileBindingCollector.HashImage(profile with { ExecutablePath = path }).Sha256 : null,
                        "Verified selected-installation anchor + WinVerifyTrust cache-only + signer Discord Inc. + fixed root/name + no reparse points"));
                    if (trusted) approved.Add(profile with { ExecutablePath = Path.GetFullPath(path) });
                }
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException) { }
        }
        // No overlapping selected profiles may authorize a component ambiguously.
        Volatile.Write(ref _approved, approved.Take(64).ToArray());
        Volatile.Write(ref _evidence, evidence.Take(64).ToArray());
        Volatile.Write(ref _publishedTrustedIds, _installationAnchors.ToArray());
    }
}
