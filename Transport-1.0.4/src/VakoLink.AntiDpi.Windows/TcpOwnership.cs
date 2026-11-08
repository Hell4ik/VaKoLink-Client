using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

internal sealed record TcpBinding(TcpFlow Flow, uint ProcessId, uint State);
public sealed record TcpComponentObservation(string ProfileId, string FileName, string VersionDirectory,
    long ConnectEvents, long EstablishedEvents, long CloseEvents, DateTimeOffset FirstObservedUtc, DateTimeOffset LastObservedUtc);

internal sealed class TcpOwnership
{
    private readonly IReadOnlyList<AppProfile> _profiles;
    private readonly Func<IReadOnlyList<AppProfile>>? _approvedProfiles;
    private readonly ConcurrentDictionary<TcpFlow, FlowObservation> _flows = new();
    private readonly Action<string, ProcessIdentity> _bound;
    private readonly ConcurrentDictionary<string, long> _resolutionCalls = new();
    private readonly object _componentGate = new();
    private readonly Dictionary<(string, string, string), TcpComponentObservation> _componentEvents = new();
    internal IReadOnlyDictionary<string, long> ResolutionCounts() => _resolutionCalls.ToDictionary(pair => pair.Key, pair => pair.Value);
    internal IReadOnlyList<TcpComponentObservation> ComponentEvents() { lock (_componentGate) return _componentEvents.Values.ToArray(); }
    private void ObserveComponent(string profileId, ProcessIdentity identity, int eventId)
    {
        lock (_componentGate)
        {
            var file = Path.GetFileName(identity.ImagePath); var version = Path.GetFileName(Path.GetDirectoryName(identity.ImagePath))!;
            var key = (profileId, file, version); var now = DateTimeOffset.UtcNow;
            if (!_componentEvents.TryGetValue(key, out var entry))
            { if (_componentEvents.Count >= 64) return; entry = new(profileId, file, version, 0, 0, 0, now, now); }
            _componentEvents[key] = entry with
            {
                ConnectEvents = entry.ConnectEvents + (eventId == 4 ? 1 : 0),
                EstablishedEvents = entry.EstablishedEvents + (eventId == 1 ? 1 : 0),
                CloseEvents = entry.CloseEvents + (eventId is 2 or 7 ? 1 : 0),
                LastObservedUtc = now
            };
        }
    }
    internal TcpOwnership(IReadOnlyList<AppProfile> profiles, Action<string, ProcessIdentity> bound, Func<IReadOnlyList<AppProfile>>? approvedProfiles = null)
    { _profiles = profiles.ToArray(); _bound = bound; _approvedProfiles = approvedProfiles; }
    internal static TcpFlow EventFlow(DivertAddress address) => new(
        address.IPv6 ? new(address.Local3, address.Local2, address.Local1, address.Local0, true) : new(address.Local0, 0, 0, 0, false), address.LocalPort,
        address.IPv6 ? new(address.Remote3, address.Remote2, address.Remote1, address.Remote0, true) : new(address.Remote0, 0, 0, 0, false), address.RemotePort);

    internal void Observe(DivertAddress address)
    {
        if (address.Protocol != 6 || !address.Outbound || address.Endpoint == 0) return;
        var flow = EventFlow(address);
        if (address.Event is 2 or 7)
        {
            foreach (var entry in _flows.Where(entry => entry.Value.Endpoint == address.Endpoint))
            {
                var closedProfile = OwnershipPolicy.MatchImage(_approvedProfiles?.Invoke() ?? _profiles, entry.Value.Identity);
                if (closedProfile is not null) ObserveComponent(closedProfile.Id, entry.Value.Identity, address.Event);
                ((ICollection<KeyValuePair<TcpFlow, FlowObservation>>)_flows).Remove(entry);
            }
            return;
        }
        if (address.Event is not (1 or 4) || flow.LocalPort == 0 || flow.RemotePort == 0) return;
        var identity = ProcessOwnership.ReadIdentity(address.ProcessId);
        if (identity is null || OwnershipPolicy.MatchImage(_approvedProfiles?.Invoke() ?? _profiles, identity) is not { } profile) return;
        ObserveComponent(profile.Id, identity, address.Event);
        NativeMethods.GetSystemTimePreciseAsFileTime(out var fileTime);
        if (!NativeMethods.QueryPerformanceCounter(out var now) || !NativeMethods.QueryPerformanceFrequency(out var frequency)
            || !OwnershipPolicy.ProcessExistedAt(identity.CreationTime, fileTime, address.Timestamp, now, frequency)) return;
        foreach (var entry in _flows.Where(entry => Environment.TickCount64 - entry.Value.Seen > 60_000))
            ((ICollection<KeyValuePair<TcpFlow, FlowObservation>>)_flows).Remove(entry);
        if (_flows.Count >= 4096 && !_flows.ContainsKey(flow)) return;
        // CONNECT then ESTABLISHED must not move birth forward past a queued ClientHello.
        _flows.AddOrUpdate(flow, new FlowObservation(identity, address.Timestamp, Environment.TickCount64, address.Endpoint), (_, old) =>
            old.Endpoint == address.Endpoint && OwnershipPolicy.SameIdentity(old.Identity, identity)
                ? old with { Timestamp = Math.Min(old.Timestamp, address.Timestamp) }
                : new(identity, address.Timestamp, Environment.TickCount64, address.Endpoint));
        _bound(profile.Id, identity);
    }

    internal OwnedPacket? Resolve(TcpFlow flow, long captured, bool mutation)
    {
        try
        {
            _flows.TryGetValue(flow, out var history);
            // Never query a system-wide table for every foreign TCP copy. Only selected FLOW/CONNECT histories enter this slow path.
            // Pre-existing flows are sampled separately as read-only table evidence, not retroactively attributed captures.
            if (history is null) return Refuse("NO_SELECTED_CAPTURE_HISTORY", mutation);
            if (history.Timestamp > captured) return Refuse("HISTORY_AFTER_CAPTURE", mutation);
            var firstOwner = UniqueOwner(ReadBindings(flow.Local.V6), flow);
            if (firstOwner is null) return Refuse("NO_UNIQUE_CURRENT_TABLE_OWNER", mutation);
            var identity = ProcessOwnership.ReadIdentity(firstOwner.Value);
            if (identity is null) return Refuse("IDENTITY_UNAVAILABLE", mutation);
            if (OwnershipPolicy.MatchImage(_approvedProfiles?.Invoke() ?? _profiles, identity) is not { } profile) return Refuse("IMAGE_NOT_APPROVED", mutation);
            if (mutation && !OwnershipPolicy.AuthorizesCapturedPacket(history!, identity, captured, Environment.TickCount64)) return Refuse("CAPTURE_AUTHORIZATION_REJECTED", mutation);
            if (UniqueOwner(ReadBindings(flow.Local.V6), flow) != firstOwner) return Refuse("TABLE_OWNER_CHANGED", mutation);
            var again = ProcessOwnership.ReadIdentity(firstOwner.Value);
            if (again is null || !OwnershipPolicy.SameIdentity(identity, again)) return Refuse("IDENTITY_CHANGED", mutation);
            NativeMethods.GetSystemTimePreciseAsFileTime(out var fileTime);
            if (!NativeMethods.QueryPerformanceCounter(out var counter) || !NativeMethods.QueryPerformanceFrequency(out var frequency)
                || !OwnershipPolicy.ProcessExistedAt(identity.CreationTime, fileTime, captured, counter, frequency)) return Refuse("BIRTH_OR_CLOCK_REJECTED", mutation);
            var owned = new OwnedPacket(profile, identity, mutation ? "tcp-flow+capture+two-current-tables+image+birth" : "tcp-copy+two-current-tables+image+birth")
            { Endpoint = history?.Endpoint ?? 0 };
            if (mutation && history is not null)
            {
                var refreshed = OwnershipPolicy.RefreshAfterAuthorizedOutbound(history, owned, captured, Environment.TickCount64, counter, frequency);
                if (refreshed is not null) _flows.TryUpdate(flow, refreshed, history);
            }
            _bound(profile.Id, identity);
            CountResolution("AUTHORIZED", mutation);
            return owned;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or System.ComponentModel.Win32Exception) { return Refuse("TABLE_OR_IDENTITY_READ_FAILED", mutation); }
    }
    private void CountResolution(string reason, bool mutation) => _resolutionCalls.AddOrUpdate((mutation ? "MUTATION_" : "COPY_") + reason, 1, (_, count) => count + 1);
    private OwnedPacket? Refuse(string reason, bool mutation) { CountResolution(reason, mutation); return null; }
    internal static uint? UniqueOwner(IReadOnlyList<TcpBinding> bindings, TcpFlow flow)
    {
        var owners = bindings.Where(row => row.Flow == flow && row.State is >= 3 and <= 10)
            .Select(row => row.ProcessId).Distinct().Take(2).ToArray();
        return owners.Length == 1 && owners[0] != 0 ? owners[0] : null;
    }
    internal static IReadOnlyList<TcpBinding> ReadBindings(bool v6)
    {
        uint size = 0;
        var error = NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref size, false, v6 ? 23u : 2u, 5, 0);
        if (error != 122 || size < 4 || size > 4_000_000) throw new InvalidOperationException("TCP_TABLE_SIZE");
        var table = Marshal.AllocHGlobal((int)size);
        try
        {
            uint allocated = size;
            error = NativeMethods.GetExtendedTcpTable(table, ref size, false, v6 ? 23u : 2u, 5, 0);
            if (error != 0 || size > allocated) throw new System.ComponentModel.Win32Exception((int)error);
            var bytes = new byte[size]; Marshal.Copy(table, bytes, 0, bytes.Length);
            return DecodeTable(bytes, v6);
        }
        finally { Marshal.FreeHGlobal(table); }
    }
    internal static IReadOnlyList<TcpBinding> DecodeTable(ReadOnlySpan<byte> bytes, bool v6)
    {
        int rowSize = v6 ? 56 : 24;
        if (bytes.Length < 4) throw new InvalidOperationException("TCP_TABLE_ROWS");
        var count = BinaryPrimitives.ReadUInt32LittleEndian(bytes);
        if (count > 100_000 || 4L + (long)count * rowSize > bytes.Length) throw new InvalidOperationException("TCP_TABLE_ROWS");
        var rows = new List<TcpBinding>();
        for (var i = 0; i < count; i++)
        {
            var row = bytes.Slice(4 + i * rowSize, rowSize);
            // IPv6 link-local scope is not part of a wire tuple. Do not guess across scoped interfaces.
            if (v6 && (BinaryPrimitives.ReadUInt32LittleEndian(row[16..]) != 0 || BinaryPrimitives.ReadUInt32LittleEndian(row[40..]) != 0)) continue;
            var local = PacketAddress.Read(v6 ? row : row[4..], v6);
            var remote = PacketAddress.Read(v6 ? row[24..] : row[12..], v6);
            var lp = BinaryPrimitives.ReadUInt16BigEndian(v6 ? row[20..] : row[8..]);
            var rp = BinaryPrimitives.ReadUInt16BigEndian(v6 ? row[44..] : row[16..]);
            rows.Add(new(new(local, lp, remote, rp), BinaryPrimitives.ReadUInt32LittleEndian(v6 ? row[52..] : row[20..]),
                BinaryPrimitives.ReadUInt32LittleEndian(v6 ? row[48..] : row)));
        }
        return rows;
    }
}
