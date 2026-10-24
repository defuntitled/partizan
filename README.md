# partizan

Зашифрованный туннель для TCP и UDP с локальным SOCKS5-прокси. Клиент работает
на Linux и OpenWrt, сервер — на Linux VPS. Основной транспорт — QUIC;
при недоступности UDP клиент автоматически переходит на TCP+TLS.

## Как это работает

```mermaid
flowchart LR
    A[Приложение или podkop] -->|SOCKS5| B[Клиент partizan]
    B -->|QUIC или TCP+TLS| C[Сервер partizan]
    C -->|TCP и UDP| D[Сайт или сервис]
```

Клиент принимает SOCKS5 CONNECT и UDP ASSOCIATE. После TLS-рукопожатия он
аутентифицируется отдельным токеном устройства, затем передаёт соединения
и датаграммы через туннель. Сервер открывает соединения к нужным адресам;
внешний сервис видит IP сервера. На сервере сохраняется хэш токена.

В QUIC потоки TCP передаются отдельными stream, UDP — датаграммами. В режиме
TCP+TLS используется собственный мультиплексор. Клиент восстанавливает сессию
после обрыва и периодически проверяет возможность вернуться с TLS на QUIC.
TLS клиента работает на BoringSSL с профилем Chrome. В режиме `static`
обычные HTTPS/HTTP3-запросы без аутентификации получают страницу маскировки.

## Что нужно для установки

| Компонент | Поддерживаемая система |
| --- | --- |
| Сервер | Linux x86_64, systemd, публичный IP или домен |
| Клиент Linux | Linux x86_64, systemd |
| Клиент OpenWrt | OpenWrt 24.10, ARMv8/AArch64 или x86_64, procd/UCI |

Готовые бинарники статически собраны с musl. Для установщиков нужны root,
Bash и доступ к GitHub по HTTPS. Для сервера откройте входящие **TCP и UDP**
на выбранном порту; по умолчанию используется **443**.

Нужен опубликованный [GitHub Release](https://github.com/defuntitled/partizan/releases).
Если релизов ещё нет, владелец репозитория может собрать и опубликовать первый:
**Actions → Release → Run workflow**, параметр `publish` включён.
Версия берётся из `Cargo.toml`. Подробнее: [сборка релиза](packaging/RELEASE.md).

## Быстрый старт

### 1. Подготовьте сервер и клиент

На Debian/Ubuntu установите инструменты для скачивания:

```sh
sudo apt-get update
sudo apt-get install -y bash curl ca-certificates tar gzip coreutils
```

На OpenWrt выполните от root:

```sh
opkg update
opkg install bash curl ca-bundle jq tar gzip coreutils-sha256sum
```

Установщики предложат установить остальные зависимости через apt-get, dnf
или opkg. На Linux без systemd автоматическая установка не поддерживается.

### 2. Скачайте установщики

Выполните этот блок отдельно на сервере и на клиентском устройстве:

```sh
release_dir=$(mktemp -d)
release_url=https://github.com/defuntitled/partizan/releases/latest/download

curl -fL "$release_url/SHA256SUMS" -o "$release_dir/SHA256SUMS" &&
curl -fL "$release_url/partizan-installers.tar.gz" -o "$release_dir/partizan-installers.tar.gz" &&
(cd "$release_dir" && grep '  partizan-installers.tar.gz$' SHA256SUMS | sha256sum -c -) &&
tar -xzf "$release_dir/partizan-installers.tar.gz" -C "$release_dir"
```

Продолжайте после успешной проверки SHA-256. Распаковывайте архив целиком:
установщикам нужны общая библиотека и шаблоны служб из него.
Запускайте их в интерактивном терминале — ввод нужен мастеру.

### 3. Установите сервер

На VPS:

```sh
sudo bash "$release_dir/partizan-installers/scripts/install-server.sh"
```

Если вы уже работаете от root, запускайте `bash` без `sudo`.
Мастер запросит публичный IP/домен, порт и имя первого клиента. Выберите TLS:

- **Без домена/CA:** мастер создаст постоянный самоподписанный сертификат.
  Клиент проверяет его по SPKI pin из ссылки подключения. Сертификат хранится
  на диске, поэтому pin сохраняется после рестартов и обновлений.
- **С готовым сертификатом CA:** укажите fullchain PEM и приватный ключ без пароля.
  Мастер проверит их и скопирует в `/etc/partizan/tls/`. Выпуск и автоматическое
  продление сертификата настройте отдельно — [подробности](packaging/INSTALL.md#сервер).

Установщик создаст службу `partizan-server`, включит автозапуск и зарегистрирует
первого клиента. Он покажет **URI `partizan://…` и QR-код**. Сохраните URI:
он содержит секретный токен и понадобится на клиенте.

При активном UFW или firewalld мастер предложит открыть порт. Также проверьте
firewall/security group в панели VPS-провайдера.

### 4. Установите клиент

На Linux:

```sh
sudo bash "$release_dir/partizan-installers/scripts/install-client.sh"
```

На OpenWrt, от root:

```sh
bash "$release_dir/partizan-installers/scripts/install-client.sh"
```

Вставьте URI сервера; ввод скрыт. Оставьте SOCKS5 на `127.0.0.1:1080`, если
прокси использует приложение или podkop на том же устройстве. Мастер проверит
подключение, настроит systemd или procd и включит автозапуск.

### 5. Используйте SOCKS5

В приложении укажите SOCKS5-прокси `127.0.0.1:1080`. Проверка через curl:

```sh
curl --proxy socks5h://127.0.0.1:1080 https://example.com
```

`socks5h` передаёт имя назначения через прокси для разрешения на стороне сервера.
Для podkop задайте SOCKS5-выход на адрес клиента partizan. Для доступа с других
устройств LAN укажите в мастере LAN-IP роутера вместо loopback и ограничьте
доступ firewall: SOCKS5 работает без пароля.

## Управление и диагностика

### Сервер

```sh
sudo systemctl status partizan-server
sudo journalctl -u partizan-server -e

sudo partizan-server device list
sudo partizan-server session list
sudo partizan-server device add laptop --host YOUR_PUBLIC_HOST
sudo partizan-server device revoke laptop
sudo partizan-server device rotate home-router --host YOUR_PUBLIC_HOST
```

`add` выдаёт новую ссылку. `revoke` отзывает доступ устройства.
`rotate` меняет токен и завершает старые сессии — замените URI на клиенте.
Эти команды используют `/etc/partizan/server.toml`; для другого файла добавьте
`--config /path/to/server.toml`.

### Клиент Linux

```sh
sudo systemctl status partizan-client
sudo journalctl -u partizan-client -e
sudo partizan status --admin-sock /run/partizan-client/admin.sock
sudo partizan check --uri-file /etc/partizan/client.uri
```

`check` отдельно проверяет QUIC и TCP+TLS. При `transport=auto` для успеха
достаточно доступности одного транспорта.

### Клиент OpenWrt

```sh
/etc/init.d/partizan status
partizan status
logread -e partizan

# При работающей службе URI находится в этом временном файле:
partizan check --uri-file /var/run/partizan.uri
```

Основные файлы:

| Назначение | Путь |
| --- | --- |
| Сервер: настройки | `/etc/partizan/server.toml` |
| Сервер: устройства | `/etc/partizan/devices.toml` |
| Сервер: сертификат и ключ установщика | `/etc/partizan/tls/` |
| Linux-клиент: секретный URI | `/etc/partizan/client.uri` |
| Linux-клиент: адрес SOCKS5 | `/etc/partizan/client.env` |
| OpenWrt-клиент: настройки и URI | `/etc/config/partizan` |

После изменения настроек перезапустите соответствующую службу. Храните URI
в защищённом файле и передавайте его через `--uri-file`, чтобы токен не попадал
в аргументы процесса и историю команд.

Если меняется приватный ключ сертификата сервера, меняется и SPKI pin:
обновите ссылки подключения клиентов. Обычное продление сертификата с тем же
ключом pin не меняет.

## Обновление

Снова скачайте установщики и запустите нужный скрипт. При наличии конфигурации
он предложит обновить бинарник, сохранив настройки, сертификаты, URI и устройства.
При неудачном запуске предыдущий бинарник восстанавливается.

На OpenWrt конфигурация сохраняется при sysupgrade; после обновления прошивки
может потребоваться заново установить бинарник и службу.

## Ограничения текущей реализации

- Клиент предоставляет SOCKS5. Системные маршруты, DNS и правила podkop
  установщик не меняет; приложения нужно направить в прокси отдельно.
- REALITY/C24 отложен. Режим `passthrough` пока только пересылает все TCP/UDP
  соединения на чужой сайт и не принимает VPN-сессии. Для VPN используется `static`.
- Встроенный выпуск ACME-сертификатов не реализован; для сертификата CA нужен
  внешний ACME-клиент и deploy hook.
- TCP+TLS fallback сохраняет работоспособность при блокировке UDP, но потери
  пакетов могут сильнее влиять на задержки звонков и другого UDP-трафика.

## Сборка из исходников

Версия Rust закреплена в `rust-toolchain.toml`. Для BoringSSL нужны CMake,
C/C++-компилятор и libclang.

```sh
cargo build --release -p server
cargo build --profile release-client -p client-openwrt
cargo test --workspace
```

Бинарники: `target/release/partizan-server` и
`target/release-client/partizan`. Команды кросс-сборки, готовые архивы и
проверки описаны в [руководстве по релизам](packaging/RELEASE.md).

## Документация и лицензия

- [Подробная установка и обновление](packaging/INSTALL.md)
- [Ручной деплой сервера и Docker](packaging/server/README.md)
- [Протокол и конфигурация](spec/partizan_spec.md)
- [План реализации](<spec/partizan — decompozition.md>)

Лицензия — [GNU AGPLv3](LICENSE), SPDX: `AGPL-3.0-only`.
