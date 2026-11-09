# Сборка VaKoLink-Client

VaKoLink v1.16 основан на [v2rayN 7.25.6](https://github.com/2dust/v2rayN/tree/7.25.6), коммит `1883178b5f1e222b6c6db2782e7a3d989b7cc18f`. Лицензия и уведомления об авторах v2rayN сохранены в [LICENSE](LICENSE) и [README.md](README.md).

Для сборки на Windows x64 нужен .NET SDK 10.0.114. В Git-копии сначала инициализируйте подмодуль GlobalHotKeys. В архиве исходников релиза его содержимое уже включено.

```powershell
git submodule update --init -- v2rayN/GlobalHotKeys
```

Для интеграции Transport используйте каталог `Transport-1.0.4` и `core/sing-box.exe` из портативного релиза r15. Контрольная сумма SHA-256 этого ядра — `7BBEF1DEA9189EE12799AE834EA4B4658355DA25C47A21AD8804904C0CCD9410`.

Запустите из корня исходников, подставив путь к распакованному релизу.

```powershell
$release = (Resolve-Path -LiteralPath 'C:\path\to\VaKoLink-r15-windows-x64').Path
$transport = (Resolve-Path -LiteralPath './Transport-1.0.4').Path
$core = Join-Path $release 'core/sing-box.exe'
dotnet publish ./v2rayN/v2rayN/v2rayN.csproj -c Release -r win-x64 --self-contained true "-p:VaKoLinkTransportSourceRoot=$transport" "-p:VaKoLinkTransportCore=$core" -o ./out
dotnet publish ./v2rayN/AmazTool/AmazTool.csproj -c Release -r win-x64 --self-contained true -p:PublishTrimmed=true -o ./out
Copy-Item -LiteralPath (Join-Path $release 'bin') -Destination ./out -Recurse
Copy-Item -LiteralPath ./LICENSE -Destination ./out/LICENSE.txt
```

Результат — `out/VaKoLink.exe` и `out/AmazTool.exe`. Для портативного запуска оставьте рядом каталоги `bin`, `core` и `tools`.

## Пакет обновления приложения

Для версии `1.16` тег релиза — `v1.16`, а имя пакета — `VaKoLink-v1.16-windows-x64-update.zip`. Поместите в корень ZIP файлы из списка `UpdatePackage.Files` в [UpdatePackage.cs](v2rayN/Update/UpdatePackage.cs), сохраняя относительные пути и регистр. Пакет обновляет приложение, его инструменты и Transport. Каталог `bin` обслуживается обновлятором компонентов отдельно.

В том же релизе разместите `vakolink-update.json` с полями `version` и `sha256`. В `version` укажите числовую часть тега, а в `sha256` — SHA-256 ZIP-пакета. Клиент берёт манифест из последнего релиза и запрашивает ZIP по тегу из манифеста. Оба файла должны быть доступны по HTTPS из самого клиента.

Установщик сохраняет заменяемые файлы в `.vakolink-update/<идентификатор>/backup` рядом с приложением. Профили, подписки и настройки остаются в текущем каталоге данных.
