# Сборка VaKoLink r12

Исходники клиента основаны на v2rayN 7.25.6, коммит 1883178b5f1e222b6c6db2782e7a3d989b7cc18f.
Каталог Transport-1.0.4 содержит исходники, использованные при интеграции Transport в эту сборку.
Подмодуль GlobalHotKeys вложен из коммита 162d401dfe0140b41d1fa349b9aadb4060e739b1.

Распакуйте этот архив в подпапку sources/client внутри распакованного дистрибутива.
В PowerShell из sources/client выполните следующие команды с .NET SDK 10.0.114.

```powershell
$transport = (Resolve-Path './Transport-1.0.4').Path
$core = (Resolve-Path '../../core/sing-box.exe').Path
dotnet publish ./v2rayN/v2rayN/v2rayN.csproj -c Release -r win-x64 --self-contained true "-p:VaKoLinkTransportSourceRoot=$transport" "-p:VaKoLinkTransportCore=$core" -o ./out
dotnet publish ./v2rayN/AmazTool/AmazTool.csproj -c Release -r win-x64 --self-contained true -p:PublishTrimmed=true -o ./out
Copy-Item ../../bin ./out -Recurse
```


