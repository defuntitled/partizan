# Интерактивная установка и обновление

Установщики загружают подходящий бинарник из **последнего опубликованного
GitHub Release** и проверяют его SHA-256. Поддерживаются:

- сервер Linux x86_64 с systemd;
- клиент Linux x86_64 с systemd;
- клиент OpenWrt 24.10 ARMv8/AArch64 или x86_64 с procd/UCI.

Нужны root, Bash, доступ к GitHub по HTTPS и интерактивный терминал.
Не запускайте установщик через `curl | bash`: стандартный ввод нужен мастеру.
Если curl/jq/tar/gzip/sha256sum/OpenSSL отсутствуют, мастер предложит установить
их через apt-get, dnf или opkg. На OpenWrt сначала установите Bash:

```sh
opkg update
opkg install bash curl ca-bundle jq tar gzip coreutils-sha256sum
```

## Скачать установщики

Сначала опубликуйте хотя бы один релиз через workflow **Release** с включённым
параметром `publish`. Артефакты Actions и draft/prerelease не подходят для
`releases/latest`. Для закрытого репозитория анонимная загрузка не поддерживается.

Скачивание и проверка архива (одинаковы для сервера и клиента):

```sh
release_dir=$(mktemp -d)
release_url=https://github.com/defuntitled/partizan/releases/latest/download
curl -fL "$release_url/SHA256SUMS" -o "$release_dir/SHA256SUMS"
curl -fL "$release_url/partizan-installers.tar.gz" -o "$release_dir/partizan-installers.tar.gz"
(cd "$release_dir" && grep '  partizan-installers.tar.gz$' SHA256SUMS | sha256sum -c -)
tar -xzf "$release_dir/partizan-installers.tar.gz" -C "$release_dir"
```

Останавливайтесь при любой ошибке проверки контрольной суммы. Оба entrypoint
используют соседний `install-common.sh` и шаблоны служб, поэтому распаковывайте
весь архив. Из checkout проекта скрипты можно запускать напрямую из `scripts/`.

## Сервер

```sh
sudo bash "$release_dir/partizan-installers/scripts/install-server.sh"
```

Мастер запросит публичный IP/домен, порт TCP/UDP (по умолчанию 443), имя первого
клиента и один из двух вариантов TLS:

1. **Без домена/CA:** создаётся постоянный ECDSA-сертификат. Он хранится на диске;
   сервер работает в `tls.mode = "files"`, поэтому pin сохраняется при рестартах
   и обновлениях. Клиент доверяет pin из выданной ссылки.
2. **Готовый сертификат CA:** укажите fullchain PEM и приватный ключ без пароля.
   Мастер проверит срок действия и соответствие ключа сертификату, затем скопирует
   их в `/etc/partizan/tls/`. Выпуск и автоматическое продление CA-сертификата
   установщик не выполняет. Настройте deploy hook своего ACME-клиента: копировать
   новые файлы с правами `root:partizan 0640` и вызывать
   `systemctl reload partizan-server`.

Будут созданы пользователь `partizan`, конфигурация `/etc/partizan/server.toml`,
реестр устройств и служба `partizan-server`. Используется маскировка `static`;
отложенный REALITY/C24 не включается. Адрес auth генерируется случайно.
После успешного запуска сервер зарегистрирует первого клиента и покажет URI
и QR-код. Сохраните ссылку: повторно исходный токен вывести нельзя.

Мастер предложит открыть выбранный TCP/UDP порт в активном UFW или firewalld.
Правила в панели хостинга/security group или другом firewall настройте отдельно.

```sh
systemctl status partizan-server
journalctl -u partizan-server -e
partizan-server device add another-client --host YOUR_PUBLIC_HOST
partizan-server device rotate home-router --host YOUR_PUBLIC_HOST
```

## Клиент

На Linux:

```sh
sudo bash "$release_dir/partizan-installers/scripts/install-client.sh"
```

На OpenWrt (root):

```sh
bash "$release_dir/partizan-installers/scripts/install-client.sh"
```

Вставьте URI из мастера сервера (ввод скрыт) и выберите адрес SOCKS5. По умолчанию
это `127.0.0.1:1080`. Для podkop на том же роутере этого достаточно; для устройств
LAN укажите LAN-IP роутера и ограничьте доступ firewall: SOCKS5 не имеет собственной
аутентификации. Установщик сначала проверит URI и подключение к серверу, затем
включит автозапуск и проверит состояние соединения.

Linux использует `/etc/partizan/client.uri` (0600), `client.env` и службу
`partizan-client`; OpenWrt — `/etc/config/partizan` (0600), procd-службу и WAN
hotplug для QUIC rebind. Токен передаётся приложению через файл, а не argv.
Системный маршрутизатор, DNS и правила podkop автоматически не перенастраиваются.
Файл UCI сохраняется при sysupgrade; после обновления прошивки бинарник и службу,
установленные без opkg-пакета, может потребоваться установить заново.

```sh
# Linux
systemctl status partizan-client
partizan status --admin-sock /run/partizan-client/admin.sock
# OpenWrt
/etc/init.d/partizan status
partizan status
logread -e partizan
```

## Обновление

Повторите запуск того же установщика. Если конфигурация уже существует, он
предложит обновить бинарник и перезапустить службу, сохранив URI, сертификаты,
ключи, реестр устройств и настройки. При ошибке запуска предыдущий бинарник
восстанавливается; новая конфигурация после неудачной первой установки сохраняется
для диагностики. Отмена до подтверждения не заменяет бинарник.

Для своего форка задайте `PARTIZAN_REPO=owner/repository` в окружении установщика.
Скрытые токены не выводите через `bash -x`.

## Проверки разработки

```sh
for script in scripts/install-{common,server,client}.sh; do bash -n "$script"; done
shellcheck -x scripts/install-{common,server,client}.sh
python3 scripts/test-installers.py
```

Тесты работают с временными каталогами и подменёнными системными командами.
Службы хоста не меняются; для имитации admin socket нужен доступ к Unix-сокетам.
