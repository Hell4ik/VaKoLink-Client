using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using VakoLink.AntiDpi.Core;

namespace VakoLink.AntiDpi.Windows;

public record UdpBinding(uint Address, ushort Port, uint ProcessId);
public record ProcessIdentity(uint ProcessId, long CreationTime, string ImagePath);
public record OwnedPacket(AppProfile Profile, ProcessIdentity Identity, string Evidence)
{
    // Internal endpoint identity is never exported in telemetry or logs.
    internal ulong Endpoint { get; init; }
}
public record FlowObservation(ProcessIdentity Identity, long Timestamp, long Seen, ulong Endpoint, long LastAuthorizedCapture = 0);

public static class OwnershipPolicy
{
    public static uint? UniqueOwner(IReadOnlyList<UdpBinding> bindings, uint address, ushort port)
    {
        var owners = bindings.Where(b => b.Port == port && (b.Address == 0 || b.Address == address))
            .Select(b => b.ProcessId).Distinct().Take(2).ToArray();
        return owners.Length == 1 && owners[0] != 0 ? owners[0] : null;
    }
    public static AppProfile? MatchImage(IReadOnlyList<AppProfile> profiles, ProcessIdentity identity)
    {
        var matches = profiles.Where(p => string.Equals(Path.GetFullPath(p.ExecutablePath),
            identity.ImagePath, StringComparison.OrdinalIgnoreCase)).Take(2).ToArray();
        return matches.Length == 1 ? matches[0] : null;
    }
    public static bool SameIdentity(ProcessIdentity left, ProcessIdentity right) =>
        left.ProcessId == right.ProcessId && left.CreationTime == right.CreationTime
        && string.Equals(left.ImagePath, right.ImagePath, StringComparison.OrdinalIgnoreCase);

    public static bool AuthorizesCapturedPacket(FlowObservation observed, ProcessIdentity current,
        long packetTimestamp, long nowMilliseconds) => observed.Endpoint != 0 && observed.Timestamp <= packetTimestamp
        && nowMilliseconds >= observed.Seen && nowMilliseconds - observed.Seen <= 60_000
        && SameIdentity(observed.Identity, current);

    public static bool ProcessExistedAt(long creationFileTime, long currentFileTime, long capturedCounter,
        long currentCounter, long frequency)
    {
        if (frequency <= 0 || creationFileTime <= 0 || creationFileTime > currentFileTime
            || capturedCounter <= 0 || capturedCounter > currentCounter) return false;
        // Calibrate FILETIME process birth against the QPC used by WinDivert. A 50ms guard
        // deliberately passes very young/uncertain processes unchanged rather than guessing.
        var processAgeSeconds = ((double)currentFileTime - creationFileTime) / 10_000_000;
        var eventAgeSeconds = ((double)currentCounter - capturedCounter) / frequency;
        return processAgeSeconds >= eventAgeSeconds + 0.050;
    }

    internal static FlowObservation? RefreshAfterAuthorizedOutbound(FlowObservation observed, OwnedPacket authorized,
        long capturedCounter, long nowMilliseconds, long nowCounter, long frequency)
    {
        if (frequency <= 0 || capturedCounter <= 0 || capturedCounter > nowCounter
            || authorized.Endpoint == 0 || observed.Endpoint != authorized.Endpoint
            || capturedCounter < observed.LastAuthorizedCapture
            || !AuthorizesCapturedPacket(observed, authorized.Identity, capturedCounter, nowMilliseconds)) return null;
        var captureAge = ((double)nowCounter - capturedCounter) * 1000 / frequency;
        if (!double.IsFinite(captureAge) || captureAge > 60_000) return null;
        // Refresh from the REAL outgoing capture time, not queue-processing time. Birth and
        // endpoint stay unchanged; fake sends and inbound copies never call this method.
        var seen = Math.Max(observed.Seen, nowMilliseconds - (long)Math.Ceiling(captureAge));
        return observed with { Seen = seen, LastAuthorizedCapture = capturedCounter };
    }
}

internal sealed class ProcessOwnership
{
    private readonly IReadOnlyList<AppProfile> _profiles;
    private readonly Func<IReadOnlyList<AppProfile>>? _approvedProfiles;
    private readonly ConcurrentDictionary<FlowKey, FlowObservation> _flows = new();
    private readonly ConcurrentDictionary<FlowKey, FlowObservation> _notSelectedFlows = new();
    private readonly Action<string, ProcessIdentity>? _bindingObserved;
    internal ProcessOwnership(IReadOnlyList<AppProfile> profiles, Action<string, ProcessIdentity>? bindingObserved = null, Func<IReadOnlyList<AppProfile>>? approvedProfiles = null)
    {
        _profiles = profiles.ToArray();
        _bindingObserved = bindingObserved;
        _approvedProfiles = approvedProfiles;
    }

    internal void Observe(DivertAddress address)
    {
        if (address.Protocol != 17 || address.IPv6 || !address.Outbound) return;
        var key = new FlowKey(address.Local0, address.LocalPort, address.Remote0, address.RemotePort);
        if (address.Event == 2 && _flows.TryGetValue(key, out var previous) && previous.Endpoint == address.Endpoint)
            _flows.TryRemove(key, out _);
        else if (address.Event == 2 && _notSelectedFlows.TryGetValue(key, out var notSelected) && notSelected.Endpoint == address.Endpoint)
            _notSelectedFlows.TryRemove(key, out _);
        else if (address.Event == 1)
        {
            foreach (var old in _flows.Where(f => Environment.TickCount64 - f.Value.Seen > 60_000)) _flows.TryRemove(old.Key, out _);
            foreach (var old in _notSelectedFlows.Where(f => Environment.TickCount64 - f.Value.Seen > 60_000)) _notSelectedFlows.TryRemove(old.Key, out _);
            var identity = ReadIdentity(address.ProcessId);
            NativeMethods.GetSystemTimePreciseAsFileTime(out var nowFile);
            var calibrated = NativeMethods.QueryPerformanceCounter(out var counter)
                && NativeMethods.QueryPerformanceFrequency(out var frequency)
                && identity is not null && OwnershipPolicy.ProcessExistedAt(identity.CreationTime, nowFile, address.Timestamp, counter, frequency);
            if (identity is not null && calibrated)
            {
                var profile = OwnershipPolicy.MatchImage(_approvedProfiles?.Invoke() ?? _profiles, identity);
                var table = profile is not null ? _flows : _notSelectedFlows;
                if (table.Count < 4096 || table.ContainsKey(key))
                    table[key] = new FlowObservation(identity, address.Timestamp, Environment.TickCount64, address.Endpoint);
                if (profile is not null) _bindingObserved?.Invoke(profile.Id, identity);
            }
        }
        else if (address.Event == 7)
        {
            foreach (var candidate in _flows.Where(f => f.Value.Identity.ProcessId == address.ProcessId && f.Key.SourcePort == address.LocalPort))
                _flows.TryRemove(candidate.Key, out _);
            foreach (var candidate in _notSelectedFlows.Where(f => f.Value.Identity.ProcessId == address.ProcessId && f.Key.SourcePort == address.LocalPort))
                _notSelectedFlows.TryRemove(candidate.Key, out _);
        }
    }

    internal OwnedPacket? Resolve(FlowKey flow, long packetTimestamp)
        => ResolveDetailed(flow, packetTimestamp).Owned;

    internal bool RecordAuthorizedOutbound(FlowKey flow, OwnedPacket authorized, long capturedCounter)
    {
        if (!_flows.TryGetValue(flow, out var observed)
            || !NativeMethods.QueryPerformanceCounter(out var nowCounter)
            || !NativeMethods.QueryPerformanceFrequency(out var frequency)) return false;
        var refreshed = OwnershipPolicy.RefreshAfterAuthorizedOutbound(observed, authorized, capturedCounter,
            Environment.TickCount64, nowCounter, frequency);
        // Compare-and-update cannot revive a removed endpoint or overwrite a newer FLOW generation.
        return refreshed is not null && _flows.TryUpdate(flow, refreshed, observed);
    }

    internal (OwnedPacket? Owned, PacketAttribution Attribution) ResolveDetailed(FlowKey flow, long packetTimestamp)
    {
        try
        {
            // Unknown flows remain unknown: do not query every UDP table merely to guess an owner.
            if ((!_flows.TryGetValue(flow, out var observed) && !_notSelectedFlows.TryGetValue(flow, out observed))
                || observed.Timestamp > packetTimestamp) return (null, PacketAttribution.Unknown);
            // Never authorize a mutation from a stale port cache. Query the current table twice.
            var owner = OwnershipPolicy.UniqueOwner(ReadBindings(), flow.SourceAddress, flow.SourcePort);
            if (owner is null) return (null, PacketAttribution.Unknown);
            var first = ReadIdentity(owner.Value);
            if (first is null) return (null, PacketAttribution.Unknown);
            var profile = OwnershipPolicy.MatchImage(_approvedProfiles?.Invoke() ?? _profiles, first);
            // A table snapshot alone describes current ownership, not the owner of a queued packet.
            // Preexisting/unobserved flows are deliberately not attributed or modified.
            if (!OwnershipPolicy.AuthorizesCapturedPacket(observed, first, packetTimestamp, Environment.TickCount64))
                return (null, PacketAttribution.Unknown);
            var secondOwner = OwnershipPolicy.UniqueOwner(ReadBindings(), flow.SourceAddress, flow.SourcePort);
            var second = ReadIdentity(owner.Value);
            if (secondOwner != owner || second is null || !OwnershipPolicy.SameIdentity(first, second))
                return (null, PacketAttribution.Unknown);
            return profile is not null
                ? (new OwnedPacket(profile, first, "exact-flow+capture-time+current-udp-table+image+creation-time") { Endpoint = observed.Endpoint }, PacketAttribution.Authorized)
                : (null, PacketAttribution.NotSelected);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        { return (null, PacketAttribution.Unknown); }
    }

    internal static IReadOnlyList<UdpBinding> ReadBindings()
    {
        uint size = 0;
        var result = NativeMethods.GetExtendedUdpTable(IntPtr.Zero, ref size, false, 2, 1, 0);
        if (result != 122 || size < 4 || size > 4_000_000) throw new InvalidOperationException("UDP_TABLE_SIZE");
        var table = Marshal.AllocHGlobal((int)size);
        try
        {
            var allocated = size;
            result = NativeMethods.GetExtendedUdpTable(table, ref size, false, 2, 1, 0);
            if (result != 0 || size > allocated) throw new System.ComponentModel.Win32Exception((int)result);
            var count = Marshal.ReadInt32(table);
            if (count < 0 || (long)count * 12 + 4 > allocated) throw new InvalidOperationException("UDP_TABLE_ROWS");
            var bindings = new List<UdpBinding>(count);
            for (var index = 0; index < count; index++)
            {
                var row = table + 4 + index * 12;
                var networkAddress = unchecked((uint)Marshal.ReadInt32(row));
                var address = BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(networkAddress) : networkAddress;
                var networkPort = unchecked((ushort)Marshal.ReadInt32(row, 4));
                var port = BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(networkPort) : networkPort;
                bindings.Add(new UdpBinding(address, port, unchecked((uint)Marshal.ReadInt32(row, 8))));
            }
            return bindings;
        }
        finally { Marshal.FreeHGlobal(table); }
    }

    internal static ProcessIdentity? ReadIdentity(uint pid)
    {
        using var process = NativeMethods.OpenProcess(0x1000 | 0x100000, false, pid);
        if (process.IsInvalid || NativeMethods.WaitForSingleObject(process, 0) != 258) return null;
        var text = new StringBuilder(32768);
        uint length = (uint)text.Capacity;
        if (!NativeMethods.QueryFullProcessImageName(process, 0, text, ref length)
            || !NativeMethods.GetProcessTimes(process, out var creation, out _, out _, out _)) return null;
        return new ProcessIdentity(pid, creation, Path.GetFullPath(text.ToString()));
    }
}
