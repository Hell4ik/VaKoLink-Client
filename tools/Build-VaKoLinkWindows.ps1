param(
    [Parameter(Mandatory)]
    [string] $OutputDirectory
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$root = Split-Path -Parent $PSScriptRoot
$output = [IO.Path]::GetFullPath($OutputDirectory)
$work = Join-Path $output ('work-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null

Push-Location $root
try {
    if ((dotnet --version) -ne '10.0.114') {
        throw 'VaKoLink Windows builds require .NET SDK 10.0.114.'
    }
    $submodule = 'v2rayN/GlobalHotKeys'
    if ((git -C $submodule rev-parse HEAD) -ne (git rev-parse "HEAD:$submodule")) {
        throw 'Initialize the pinned GlobalHotKeys submodule before building.'
    }

    # Reuse the public release's pinned third-party files. Build both VaKoLink executables below.
    $baseName = 'VaKoLink-v1.17-windows-x64'
    $baseZip = Join-Path $work "$baseName.zip"
    $baseSha = '6b026f3a051ab39fda84ccea24446edc39637d1c8d1e238c19a938bc5f05d8bd'
    $baseUrl = "https://github.com/Hell4ik/VaKoLink-Client/releases/download/v1.17/$baseName.zip"
    curl.exe --disable --fail --location --proto '=https' --proto-redir '=https' --silent --show-error `
        --retry 2 --max-time 240 --output $baseZip $baseUrl
    if ((Get-FileHash -LiteralPath $baseZip -Algorithm SHA256).Hash -ne $baseSha) {
        throw 'The dependency archive failed SHA-256 verification.'
    }
    [IO.Compression.ZipFile]::ExtractToDirectory($baseZip, $work)
    $base = Join-Path $work $baseName
    $transportCore = Join-Path $base 'core/sing-box.exe'
    $transportSha = '7BBEF1DEA9189EE12799AE834EA4B4658355DA25C47A21AD8804904C0CCD9410'
    if ((Get-FileHash -LiteralPath $transportCore -Algorithm SHA256).Hash -ne $transportSha) {
        throw 'The Transport core failed SHA-256 verification.'
    }

    $app = Join-Path $work 'app'
    $helper = Join-Path $work 'helper'
    $publishOptions = @(
        '-c', 'Release', '-r', 'win-x64', '--self-contained', 'true',
        '-p:DebugType=None', '-p:DebugSymbols=false', "-p:PathMap=$root=/_/VaKoLink-Client"
    )
    dotnet publish ./v2rayN/v2rayN/v2rayN.csproj @publishOptions -o $app `
        "-p:VaKoLinkTransportSourceRoot=$root/Transport-1.0.4" "-p:VaKoLinkTransportCore=$transportCore"
    dotnet publish ./v2rayN/AmazTool/AmazTool.csproj @publishOptions -o $helper -p:PublishTrimmed=true

    $appVersion = (Get-Item -LiteralPath (Join-Path $app 'VaKoLink.exe')).VersionInfo
    $version = "$($appVersion.FileMajorPart).$($appVersion.FileMinorPart)"
    $name = "VaKoLink-v$version-windows-x64"
    $portable = Join-Path $work "portable/$name"
    New-Item -ItemType Directory -Path $portable | Out-Null
    Get-ChildItem -LiteralPath $app | Copy-Item -Destination $portable -Recurse
    Copy-Item -LiteralPath (Join-Path $helper 'AmazTool.exe') -Destination $portable
    Copy-Item -LiteralPath (Join-Path $root 'LICENSE') -Destination (Join-Path $portable 'LICENSE.txt')
    Copy-Item -LiteralPath (Join-Path $root 'README.md') -Destination $portable
    foreach ($directory in @('bin', 'third-party')) {
        Copy-Item -LiteralPath (Join-Path $base $directory) -Destination $portable -Recurse
    }

    $sources = Join-Path $portable 'sources'
    New-Item -ItemType Directory -Path $sources | Out-Null
    Get-ChildItem -LiteralPath (Join-Path $base 'sources') -Filter '*.zip' |
        Where-Object Name -NotLike 'VaKoLink-Client-*' |
        Copy-Item -Destination $sources

    $snapshot = Join-Path $work 'source'
    $sourceZip = Join-Path $work 'source.zip'
    $submoduleZip = Join-Path $work 'GlobalHotKeys.zip'
    git archive --format=zip "--output=$sourceZip" HEAD
    git -C $submodule archive --format=zip "--prefix=$submodule/" "--output=$submoduleZip" HEAD
    [IO.Compression.ZipFile]::ExtractToDirectory($sourceZip, $snapshot)
    [IO.Compression.ZipFile]::ExtractToDirectory($submoduleZip, $snapshot)
    [IO.Compression.ZipFile]::CreateFromDirectory(
        $snapshot, (Join-Path $sources "VaKoLink-Client-v$version-source.zip"))

    if ((Get-FileHash -LiteralPath (Join-Path $portable 'core/sing-box.exe') -Algorithm SHA256).Hash -ne $transportSha) {
        throw 'The packaged Transport core differs from the verified input.'
    }
    Get-ChildItem -LiteralPath $portable -Recurse -File | Sort-Object FullName | ForEach-Object {
        $path = [IO.Path]::GetRelativePath($portable, $_.FullName).Replace('\', '/')
        $digest = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$digest  $path"
    } | Set-Content -LiteralPath (Join-Path $portable 'SHA256SUMS.txt') -Encoding utf8

    $artifact = Join-Path $output "$name-ci.zip"
    [IO.Compression.ZipFile]::CreateFromDirectory($portable, $artifact, 'Optimal', $true)
    Get-FileHash -LiteralPath $artifact -Algorithm SHA256
} finally {
    Pop-Location
}
