param(
    [Parameter(Mandatory)][string]$TransportPackage,
    [string]$Dotnet = 'dotnet',
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$package = (Resolve-Path -LiteralPath $TransportPackage).Path
$artifacts = Join-Path $repo 'artifacts'
$staged = Join-Path $artifacts ('transport-1.0.4-src-' + [guid]::NewGuid().ToString('N'))
$output = if ($OutputDirectory) { [IO.Path]::GetFullPath($OutputDirectory, $repo) } else { Join-Path $artifacts 'vakolink-transport-win-x64' }
$sourceArchive = Join-Path $package 'SOURCE.zip'
$core = Join-Path $package 'core/sing-box.exe'

function Assert-Sha256([string]$Path, [string]$Expected) {
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $Expected) {
        throw "VaKoLink Transport 1.0.4 SHA-256 mismatch for $(Split-Path -Leaf $Path)."
    }
}

Assert-Sha256 (Join-Path $package 'VaKoLink-Transport.exe') 'C0A39D9113335E6BDB73D080FFE3D02CBF6F6F479E45DD419AF3DA5928D2D513'
Assert-Sha256 $sourceArchive '7FBED2991215893E3D766DE523E92DB84ABE269ABCF45907F0949D51322A13CF'
Assert-Sha256 $core '7BBEF1DEA9189EE12799AE834EA4B4658355DA25C47A21AD8804904C0CCD9410'
Expand-Archive -LiteralPath $sourceArchive -DestinationPath $staged

# Keep the standalone application's data and listener selection out of the client.
$plan = Join-Path $staged 'src/VakoLink.AntiDpi.Windows/ProxyTunPlan.cs'
$text = [IO.File]::ReadAllText($plan)
$originalRoot = 'public static string Root => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VakoLink", "AionTransportProxy");'
$clientRoot = 'public static string Root => AppContext.GetData("VaKoLink.Client.TransportData") as string ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VakoLink", "AionTransportProxy");'
if (!$text.Contains($originalRoot)) { throw 'Unexpected Transport data-root declaration.' }
[IO.File]::WriteAllText($plan, $text.Replace($originalRoot, $clientRoot))

# The integrated probe runs inside v2rayN.exe, which also matches the process loop guard.
# Give only UDP on the authenticated diagnostic inbound precedence over that guard.
$text = [IO.File]::ReadAllText($plan)
$probeRule = 'rules.Insert(1, new JsonObject { ["inbound"] = new JsonArray("discord-check"), ["network"] = "udp", ["action"] = "route", ["outbound"] = "discord-media" });'
if (!$text.Contains($probeRule)) { throw 'Unexpected Transport Discord UDP probe rule.' }
[IO.File]::WriteAllText($plan, $text.Replace($probeRule, $probeRule.Replace('rules.Insert(1,', 'rules.Insert(0,')))

$runtime = Join-Path $staged 'src/VakoLink.AionTransport.Proxy/UserTransportRuntime.cs'
$text = [IO.File]::ReadAllText($runtime)
$type = 'public sealed class LocalTransportPlatform : IUserTransportPlatform'
$discovery = 'await LocalProxy.DiscoverAsync(_discovery)'
if (!$text.Contains($type) -or [regex]::Matches($text, [regex]::Escape($discovery)).Count -ne 2) {
    throw 'Unexpected Transport listener-discovery contract.'
}
$text = $text.Replace($type, 'public sealed class LocalTransportPlatform(int guiPid, int socksPort) : IUserTransportPlatform')
$text = $text.Replace($discovery, 'await DiscoverClientAsync()')
$method = @'
    private async Task<IReadOnlyList<LocalProxyEndpoint>> DiscoverClientAsync() =>
        (await LocalProxy.DiscoverAsync(_discovery))
            .Where(endpoint => endpoint.GuiPid == guiPid && endpoint.Port == socksPort).ToArray();

'@
$text = $text.Replace('    public ProxyProbe? LastProbe { get; private set; }', $method + [Environment]::NewLine + '    public ProxyProbe? LastProbe { get; private set; }')
[IO.File]::WriteAllText($runtime, $text)

$options = @('-c', 'Release', '-r', 'win-x64', '-p:SelfContained=true', '-p:EnableWindowsTargeting=true', '--nologo')
& $Dotnet publish (Join-Path $repo 'v2rayN/v2rayN/v2rayN.csproj') @options "-p:VaKoLinkTransportSourceRoot=$staged" "-p:VaKoLinkTransportCore=$core" -o $output
if ($LASTEXITCODE -ne 0) { throw "VaKoLink publish failed ($LASTEXITCODE)." }
& $Dotnet publish (Join-Path $repo 'v2rayN/AmazTool/AmazTool.csproj') @options '-p:PublishTrimmed=true' -o $output
if ($LASTEXITCODE -ne 0) { throw "AmazTool publish failed ($LASTEXITCODE)." }

$manifest = Get-Content -LiteralPath (Join-Path $package 'SHA256SUMS.json') -Raw | ConvertFrom-Json
$license = 'third-party/sing-box-LICENSE'
$licenseEntry = @($manifest.Files | Where-Object File -CEQ $license)
if ($licenseEntry.Count -ne 1) { throw 'Missing sing-box license in package manifest.' }
Assert-Sha256 (Join-Path $package $license) $licenseEntry[0].SHA256
New-Item -ItemType Directory -Path (Join-Path $output 'third-party') -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $package $license) -Destination (Join-Path $output $license)

Write-Output (Join-Path $output 'v2rayN.exe')
