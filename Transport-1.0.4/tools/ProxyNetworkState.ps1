[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
# Read-only projection. Raw output is consumed privately/DPAPI protected, never published as a safe report.
$adapters=@(Get-NetAdapter -IncludeHidden|Sort-Object InterfaceIndex|Select-Object InterfaceIndex,Name,Status,HardwareInterface,InterfaceDescription)
$routes=@(Get-NetRoute -PolicyStore ActiveStore|Sort-Object InterfaceIndex,AddressFamily,DestinationPrefix,NextHop|Select-Object InterfaceIndex,AddressFamily,DestinationPrefix,NextHop,RouteMetric)
$ips=@(Get-NetIPAddress -PolicyStore ActiveStore|Sort-Object InterfaceIndex,AddressFamily,IPAddress|Select-Object InterfaceIndex,AddressFamily,IPAddress,PrefixLength,PrefixOrigin)
$interfaces=@(Get-NetIPInterface -PolicyStore ActiveStore|Sort-Object InterfaceIndex,AddressFamily|Select-Object InterfaceIndex,AddressFamily,InterfaceMetric,NlMtu,Dhcp,ConnectionState)
$dns=@(Get-DnsClientServerAddress|Sort-Object InterfaceIndex,AddressFamily|Select-Object InterfaceIndex,AddressFamily,ServerAddresses)
$firewall=@(Get-NetFirewallProfile|Sort-Object Name|Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction)
$proxy=Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
$defaults=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore|Sort-Object RouteMetric)
$best=@($defaults|ForEach-Object{$r=$_;$i=$interfaces|Where-Object{$_.InterfaceIndex -eq $r.InterfaceIndex -and [int]$_.AddressFamily -eq 2}|Select-Object -First 1
 [pscustomobject]@{Index=$r.InterfaceIndex;Metric=[int]$r.RouteMetric+[int]$i.InterfaceMetric}}|Sort-Object Metric|Select-Object -First 1)
$physical=$adapters|Where-Object{$_.InterfaceIndex -eq $best[0].Index}|Select-Object -First 1
$loopback=Get-NetIPInterface -AddressFamily IPv4|Where-Object{$_.InterfaceIndex -eq 1}|Select-Object -First 1
[ordered]@{Adapters=$adapters;Routes=$routes;Addresses=$ips;Interfaces=$interfaces;DNS=$dns;Firewall=$firewall
 Proxy=[ordered]@{Enable=$proxy.ProxyEnable;Server=$proxy.ProxyServer;Override=$proxy.ProxyOverride;PAC=$proxy.AutoConfigURL}
 Physical=[ordered]@{Index=$physical.InterfaceIndex;Name=$physical.Name;Hardware=$physical.HardwareInterface}
 LoopbackInterface=$loopback.InterfaceAlias
 SourceRuntimeSHA='NotRead_LocalProxyMode'
 V2rayTunEnabled=$false
}|ConvertTo-Json -Depth 8 -Compress
