using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace VakoLink.AntiDpi.Windows;

public sealed record OriginalZapretEvidence(string Configuration, string ExecutableSha256, string ConfigurationSha256,
    string InputsSha256, bool Started, bool Running, bool StopSignalSent, bool ProcessExited, bool ForcedTermination,
    bool CleanupConfirmed, string Scope = "Original ALT13 broad port/host/ipset rules, NOT process-bound; external native counts and queue drain not measured.",
    string StopMechanism = "PrivateConPTYCtrlC+owned-kill-on-close-job");

public sealed class OriginalZapretReference : IAsyncDisposable
{
    public const string PinnedWinwsSha256 = "AFFB4F69D2EA302A7ABCCD5325D81826E140DDAE014F1E070BC4A6C0DD555188";
    public const string PinnedAlt13Sha256 = "0EF7279F222CED580F002C4073CC431307A368D6A70016489FC09E7A1741B0F8";
    private readonly List<IDisposable> _locks = new();
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Process? _process;
    private OwnedConsoleProcess? _terminal;
    private ProcessIdentity? _identity;
    private IDisposable? _lease;
    private CancellationTokenRegistration _cancel;
    private CancellationTokenSource? _deadline;
    private bool _signaled, _forced, _exited, _started;
    private bool _falseFilter;
    public const string PinnedCygwinSha256 = "103104A52E5293CE418944725DF19E2BF81AD9269B9A120D71D39028E821499B";
    private string _configurationHash = "", _inputsHash = "";
    public bool Running => _process is not null && !_process.HasExited;
    public ReferenceConfigurationEvidence? Configuration { get; private set; }
    public OriginalZapretEvidence Evidence => new("general (ALT13)", PinnedWinwsSha256, _configurationHash, _inputsHash,
        _started, Running, _signaled, _exited, _forced, (!_started || _exited) && _terminal is null && _locks.Count == 0 && _lease is null,
        _falseFilter ? "Owned winws process lifecycle with wf-raw=false; NOT an ALT13 efficacy test; no traffic matches" : "Original ALT13 broad port/host/ipset rules, NOT process-bound; external native counts and queue drain not measured.");

    public Task StartAsync(string engineDirectory, TimeSpan remainingBudget, CancellationToken token) => StartCoreAsync(engineDirectory, remainingBudget, token, false);
    public Task StartFalseFilterControlSmokeAsync(string directory, CancellationToken token = default) => StartCoreAsync(directory, TimeSpan.FromSeconds(8), token, true);
    private async Task StartCoreAsync(string engineDirectory, TimeSpan remainingBudget, CancellationToken token, bool falseFilter)
    {
        await _gate.WaitAsync(token);
        try
        {
            if (_started || _process is not null) throw new InvalidOperationException("REFERENCE_ALREADY_STARTED");
            if (!RuntimePreflight.IsAdministrator()) throw new InvalidOperationException("ADMIN_REQUIRED");
            if (remainingBudget <= TimeSpan.Zero || remainingBudget > TimeSpan.FromMinutes(20)) throw new ArgumentOutOfRangeException(nameof(remainingBudget));
            _deadline = CancellationTokenSource.CreateLinkedTokenSource(token); _deadline.CancelAfter(remainingBudget); token = _deadline.Token;
            RuntimePreflight.VerifyPackage(engineDirectory, token);
            if (RuntimePreflight.GetConflicts().Count != 0) throw new InvalidOperationException("CONFLICTING_ENGINE_ACTIVE");
            _lease = new SessionDependencies().AcquireLease();
            var root = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(Path.GetFullPath(engineDirectory)))!;
            var batPath = Path.Combine(root, "general (ALT13).bat");
            var winwsPath = Path.Combine(engineDirectory, "winws.exe");
            RuntimePreflight.VerifyFile(winwsPath, PinnedWinwsSha256);
            RuntimePreflight.VerifyFile(Path.Combine(engineDirectory, "cygwin1.dll"), PinnedCygwinSha256);
            Lock(batPath); Lock(winwsPath); Lock(Path.Combine(engineDirectory, "WinDivert.dll")); Lock(Path.Combine(engineDirectory, "WinDivert64.sys"));
            Lock(Path.Combine(engineDirectory, "cygwin1.dll"));
            var bat = File.ReadAllText(batPath); _configurationHash = Hash(File.ReadAllBytes(batPath));
            if (_configurationHash != PinnedAlt13Sha256) throw new InvalidOperationException("ALT13_CONFIGURATION_CHANGED_REAUDIT_REQUIRED");
            var flag = Path.Combine(root, "utils", "game_filter.enabled");
            string? flagText = null;
            if (File.Exists(flag)) { Lock(flag); flagText = File.ReadAllText(flag); }
            var arguments = ParseArguments(bat, root, flagText); _falseFilter = falseFilter;
            var paths = arguments.Where(arg => arg.Contains('=')).Select(arg => arg[(arg.IndexOf('=') + 1)..])
                .Where(Path.IsPathFullyQualified).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray();
            var fingerprint = new StringBuilder();
            foreach (var path in paths)
            {
                Lock(path); var info = new FileInfo(path);
                if (info.Length > 16_000_000) throw new InvalidOperationException("REFERENCE_INPUT_SIZE");
                fingerprint.Append(Path.GetRelativePath(root, path)).Append(':').Append(Hash(File.ReadAllBytes(path))).Append(';');
            }
            fingerprint.Append(flagText ?? "game-filter-disabled"); _inputsHash = Hash(Encoding.UTF8.GetBytes(fingerprint.ToString()));
            Configuration = new ReferenceConfiguration(root, arguments, _configurationHash,
                falseFilter ? "OWNED_FALSE_FILTER_LIFECYCLE_NOT_ALT13" : "OWNED_ACTUAL_LAUNCH_ARGV").Evidence;
            RuntimePreflight.VerifyFile(winwsPath, PinnedWinwsSha256); RuntimePreflight.VerifyPackage(engineDirectory, token);
            token.ThrowIfCancellationRequested();
            _terminal = OwnedConsoleProcess.Start(winwsPath, falseFilter ? new[] { "--wf-raw=false" } : arguments, engineDirectory);
            _process = _terminal.Process;
            _started = true; _identity = ProcessOwnership.ReadIdentity((uint)_process.Id);
            if (_identity is null || !string.Equals(_identity.ImagePath, Path.GetFullPath(winwsPath), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("REFERENCE_IDENTITY_UNCONFIRMED");
            _cancel = token.Register(() => _ = Task.Run(StopAsync));
            // Token owned by the wizard provides the hard overall bound, not a renewed deadline here.
            await Task.Delay(500, token);
            if (!Running) throw new InvalidOperationException("REFERENCE_EXITED_EARLY");
        }
        catch { await StopInternalAsync(); throw; }
        finally { _gate.Release(); }
    }
    public static Task<OriginalZapretEvidence> InspectAsync(string directory, CancellationToken token = default) => Task.Run(() =>
    {
        RuntimePreflight.VerifyPackage(directory, token);
        RuntimePreflight.VerifyFile(Path.Combine(directory, "winws.exe"), PinnedWinwsSha256);
        RuntimePreflight.VerifyFile(Path.Combine(directory, "cygwin1.dll"), PinnedCygwinSha256);
        var root = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory)))!;
        var batPath = Path.Combine(root, "general (ALT13).bat");
        var hash = Hash(File.ReadAllBytes(batPath));
        if (hash != PinnedAlt13Sha256) throw new InvalidOperationException("ALT13_CONFIGURATION_CHANGED_REAUDIT_REQUIRED");
        var flag = Path.Combine(root, "utils", "game_filter.enabled"); var flagText = File.Exists(flag) ? File.ReadAllText(flag) : null;
        var arguments = ParseArguments(File.ReadAllText(batPath), root, flagText);
        var inputs = new StringBuilder();
        foreach (var path in arguments.Where(arg => arg.Contains('=')).Select(arg => arg[(arg.IndexOf('=') + 1)..])
            .Where(Path.IsPathFullyQualified).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase))
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > 16_000_000 || (info.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("REFERENCE_INPUT_INVALID");
            inputs.Append(Path.GetRelativePath(root, path)).Append(':').Append(Hash(File.ReadAllBytes(path))).Append(';');
        }
        inputs.Append(flagText ?? "game-filter-disabled");
        return new OriginalZapretEvidence("general (ALT13)", PinnedWinwsSha256, hash, Hash(Encoding.UTF8.GetBytes(inputs.ToString())), false, false, false, false, false, true);
    }, token);
    internal static IReadOnlyList<string> ParseArguments(string bat, string root, string? gameFlag)
    {
        var offset = bat.IndexOf("--wf-tcp=", StringComparison.Ordinal);
        if (offset < 0) throw new InvalidOperationException("ALT13_ARGUMENTS_MISSING");
        var arguments = bat[offset..].Replace("^\r\n", " ").Replace("^\n", " ").Trim();
        if (arguments.Contains('\n') || arguments.Contains('\r') || arguments.IndexOfAny(['&', '|', '<', '>', '`']) >= 0)
            throw new InvalidOperationException("ALT13_UNSAFE_COMMAND_TEXT");
        var (tcp, udp) = GameFilter(gameFlag);
        arguments = arguments.Replace("%BIN%", Path.Combine(root, "bin") + Path.DirectorySeparatorChar)
            .Replace("%LISTS%", Path.Combine(root, "lists") + Path.DirectorySeparatorChar)
            .Replace("%GameFilterTCP%", tcp).Replace("%GameFilterUDP%", udp);
        if (arguments.Contains('%')) throw new InvalidOperationException("ALT13_UNRESOLVED_VARIABLE");
        var tokens = Regex.Matches(arguments, "(?:[^\\s\"]+|\"[^\"]*\")+").Select(match => match.Value.Replace("\"", "")).ToArray();
        if (tokens.Length is < 20 or > 200 || tokens.Any(token => !token.StartsWith("--", StringComparison.Ordinal)))
            throw new InvalidOperationException("ALT13_ARGUMENTS_INVALID");
        foreach (var token in tokens)
        {
            if (token is "--new") continue;
            var at = token.IndexOf('='); if (at <= 2) throw new InvalidOperationException("ALT13_ARGUMENTS_INVALID");
            var option = token[..at];
            if (!(option.StartsWith("--dpi-desync", StringComparison.Ordinal) || option is "--wf-tcp" or "--wf-udp" or "--filter-tcp" or "--filter-udp" or "--filter-l7"
                or "--hostlist" or "--hostlist-domains" or "--hostlist-exclude" or "--ipset" or "--ipset-exclude")) throw new InvalidOperationException("ALT13_OPTION_NOT_ALLOWED");
            var value = token[(at + 1)..];
            if (Path.IsPathFullyQualified(value))
            {
                var full = Path.GetFullPath(value);
                var prefix = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) + Path.DirectorySeparatorChar;
                if (!full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("ALT13_INPUT_OUTSIDE_PACKAGE");
            }
        }
        return tokens;
    }
    private static (string, string) GameFilter(string? text)
    {
        if (text is null) return ("12", "12");
        if (text.Length > 1024) throw new InvalidOperationException("ALT13_GAME_FLAG_INVALID");
        string mode = "disabled", tcp = "1024-65535", udp = tcp;
        foreach (var line in text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var pair = line.Split('=', 2); var key = pair[0].ToLowerInvariant(); var value = pair.Length == 2 ? pair[1] : "";
            if (key == "mode") mode = value.ToLowerInvariant();
            else if (key is "all" or "tcp" or "udp" && value == "") mode = key;
            else if (key is "tcp" or "udp" && Regex.IsMatch(value, @"\A[0-9]{1,5}-[0-9]{1,5}\z")
                && int.TryParse(value.Split('-')[0], out var from) && int.TryParse(value.Split('-')[1], out var to) && from >= 1 && from <= to && to <= 65535)
            { if (key == "tcp") tcp = value; else udp = value; }
            else throw new InvalidOperationException("ALT13_GAME_FLAG_INVALID");
        }
        return mode switch { "all" => (tcp, udp), "tcp" => (tcp, "12"), "udp" => ("12", udp), "disabled" => ("12", "12"), _ => throw new InvalidOperationException("ALT13_GAME_FLAG_INVALID") };
    }
    private void Lock(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("REFERENCE_REPARSE_INPUT");
        _locks.Add(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read));
    }
    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));
    public async Task StopAsync()
    { await _gate.WaitAsync(); try { await StopInternalAsync(); } finally { _gate.Release(); } }
    private async Task StopInternalAsync()
    {
        _cancel.Unregister();
        if (_process is not null)
        {
            if (!_process.HasExited)
            {
                var current = ProcessOwnership.ReadIdentity((uint)_process.Id);
                if (_identity is null || current is null || !OwnershipPolicy.SameIdentity(_identity, current))
                    throw new InvalidOperationException("REFERENCE_STOP_IDENTITY_UNCONFIRMED");
                _signaled = _terminal?.SendInterrupt() ?? false;
                try { await _process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); }
                catch (TimeoutException) { _forced = true; _process.Kill(); await _process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); }
            }
            _exited = _process.HasExited;
            if (!_exited) throw new InvalidOperationException("REFERENCE_PROCESS_RETAINED");
            if (_terminal is not null) { await _terminal.DisposeAfterExitAsync(); _terminal = null; }
            _process.Dispose(); _process = null;
        }
        foreach (var file in _locks) file.Dispose(); _locks.Clear(); _lease?.Dispose(); _lease = null;
        _deadline?.Dispose(); _deadline = null;
    }
    public async ValueTask DisposeAsync() => await StopAsync();
}
