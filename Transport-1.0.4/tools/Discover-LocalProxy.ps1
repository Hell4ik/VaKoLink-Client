param()
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
# Only processes descending from the running v2rayN GUI, never node/outbound credentials.
$all=@(Get-CimInstance Win32_Process)
$session=[Diagnostics.Process]::GetCurrentProcess().SessionId
$guis=@($all|Where-Object{$_.Name -eq 'v2rayN.exe' -and [int]$_.SessionId -eq $session})
$result=@()
foreach($gui in $guis){
 $ids=@([int]$gui.ProcessId)
 for($depth=0;$depth -lt 4;$depth++){$ids=@($ids+@($all|Where-Object{[int]$_.ParentProcessId -in $ids}|ForEach-Object{[int]$_.ProcessId})|Select-Object -Unique)}
 $members=@($all|Where-Object{[int]$_.ProcessId -in $ids -and $_.Name -in @('v2rayN.exe','xray.exe','v2ray.exe','sing-box.exe')})
 $clients=@($members|ForEach-Object{$p=Get-Process -Id $_.ProcessId -ErrorAction Stop
  [ordered]@{Pid=[int]$_.ProcessId;Name=$_.Name;Path=$_.ExecutablePath;BirthUtc=$p.StartTime.ToUniversalTime().ToString('o')}})
 $fingerprints=@()
 foreach($m in $members){
  # Fingerprint the runtime config only; never export JSON, remote addresses, UUIDs or credentials.
  $match=[regex]::Match([string]$m.CommandLine,'(?:-c|-config)\s+(?:"([^"\r\n]+\.json)"|([^\s"]+\.json))')
  if($match.Success -and $gui.ExecutablePath){$file=if($match.Groups[1].Success){$match.Groups[1].Value}else{$match.Groups[2].Value}
   if(-not [IO.Path]::IsPathRooted($file)){$file=Join-Path (Split-Path $gui.ExecutablePath) $file}
   if(Test-Path -LiteralPath $file){$fingerprints+=,[ordered]@{Path=[IO.Path]::GetFullPath($file);Hash=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash}}}
 }
 $tun=$false
 if($gui.ExecutablePath){$settings=Join-Path (Split-Path $gui.ExecutablePath) 'guiConfigs\guiNConfig.json'
  if(Test-Path -LiteralPath $settings){$tun=(Get-Content -LiteralPath $settings -Raw|ConvertFrom-Json).TunModeItem.EnableTun -eq $true}}
 $listeners=@(Get-NetTCPConnection -State Listen|Where-Object{[int]$_.OwningProcess -in $members.ProcessId -and $_.LocalAddress -in @('127.0.0.1','0.0.0.0','::1','::')}|
  Select-Object @{n='Pid';e={[int]$_.OwningProcess}},@{n='Host';e={if($_.LocalAddress -in @('::1','::')){'::1'}else{'127.0.0.1'}}},@{n='Port';e={[int]$_.LocalPort}})
 $result+=,[ordered]@{GuiPid=[int]$gui.ProcessId;TunEnabled=$tun;Members=$clients;Listeners=$listeners;Configurations=$fingerprints}
}
ConvertTo-Json -InputObject @($result) -Depth 8 -Compress
