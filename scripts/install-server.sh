#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=scripts/install-common.sh
source "$SCRIPT_DIR/install-common.sh"

main() {
    local attempt cert_public key_public listen_address
    installer_init "$@"
    [[ $(uname -m) == x86_64 ]] || die 'Серверный релиз поддерживает только Linux x86_64.'
    (( OPENWRT == 0 )) || die 'Сервер устанавливается на Linux с systemd.'
    require_systemd
    ensure_dependencies curl jq tar gzip sha256sum openssl
    PROGRAM=partizan-server
    SERVICE=partizan-server
    DEST="$ROOT/usr/local/bin/$PROGRAM"
    CONFIG="$ROOT/etc/partizan/server.toml"
    fetch_binary server-linux-x86_64

    if [[ -f "$CONFIG" ]]; then
        say 'Найдена существующая конфигурация. Сертификаты и реестр устройств будут сохранены.'
        confirm 'Обновить сервер до последнего релиза и перезапустить службу?' || return 0
        [[ -f "$ROOT/etc/systemd/system/partizan-server.service" ]] || die 'Нет установленного systemd unit; сначала завершите настройку службы.'
        install_binary
        start_service
        BINARY_CHANGED=0
        say 'Сервер обновлён. Конфигурация и устройства сохранены.'
        return 0
    fi

    ask SERVER_HOST 'Публичный IP-адрес или домен сервера'
    host_valid "$SERVER_HOST" || die 'Некорректный IP-адрес или домен (IPv6 вводится без скобок).'
    ask SERVER_PORT 'TCP/UDP порт' 443
    port_valid "$SERVER_PORT" || die 'Порт должен быть от 1 до 65535.'
    ask TLS_CHOICE 'TLS: 1 — постоянный самоподписанный сертификат + pin; 2 — готовый сертификат CA' 1
    case "$TLS_CHOICE" in
        1) ;;
        2)
            ask CERT_SOURCE 'Путь к fullchain.pem'
            ask KEY_SOURCE 'Путь к приватному ключу PEM'
            [[ -r "$CERT_SOURCE" && -r "$KEY_SOURCE" ]] || die 'Сертификат или ключ недоступен для чтения.'
            openssl x509 -in "$CERT_SOURCE" -noout >/dev/null
            openssl x509 -in "$CERT_SOURCE" -checkend 0 -noout >/dev/null || die 'Сертификат уже истёк.'
            openssl pkey -in "$KEY_SOURCE" -passin pass: -noout >/dev/null || die 'Нужен приватный ключ без пароля.'
            cert_public=$(openssl x509 -in "$CERT_SOURCE" -pubkey -noout | sha256sum)
            key_public=$(openssl pkey -in "$KEY_SOURCE" -passin pass: -pubout | sha256sum)
            [[ "$cert_public" == "$key_public" ]] || die 'Сертификат и приватный ключ не соответствуют друг другу.'
            ;;
        *) die 'Выберите 1 или 2.' ;;
    esac
    ask DEVICE_NAME 'Имя первого клиента' home-router
    [[ "$DEVICE_NAME" =~ ^[a-zA-Z0-9._-]{1,64}$ ]] || die 'Имя клиента: 1–64 символа, буквы, цифры, точка, дефис, подчёркивание.'
    confirm "Установить сервер на $SERVER_HOST:$SERVER_PORT с автозапуском?" || return 0

    ensure_user
    mkdir -p "$ROOT/etc/partizan/tls" "$ROOT/etc/systemd/system"
    chmod 750 "$ROOT/etc/partizan" "$ROOT/etc/partizan/tls"
    chown root:partizan "$ROOT/etc/partizan" "$ROOT/etc/partizan/tls"
    if [[ "$TLS_CHOICE" == 1 ]]; then
        # Files mode keeps the certificate/pin stable across restarts and upgrades.
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
            -subj "/CN=$SERVER_HOST" -keyout "$WORK/key.pem" -out "$WORK/fullchain.pem" >/dev/null 2>&1
        CERT_SOURCE="$WORK/fullchain.pem"
        KEY_SOURCE="$WORK/key.pem"
    fi
    cp "$CERT_SOURCE" "$ROOT/etc/partizan/tls/fullchain.pem"
    cp "$KEY_SOURCE" "$ROOT/etc/partizan/tls/key.pem"
    chmod 640 "$ROOT/etc/partizan/tls/"*.pem
    chown root:partizan "$ROOT/etc/partizan/tls/"*.pem
    AUTH_PATH="/$(openssl rand -hex 16)"
    listen_address=0.0.0.0
    [[ "$SERVER_HOST" != *:* ]] || listen_address='[::]'
    {
        printf '[server]\ndomain = '; toml_string "$SERVER_HOST"
        printf '\nlisten = "%s:%s"\nauth_path = "%s"\n' "$listen_address" "$SERVER_PORT" "$AUTH_PATH"
        printf 'devices = '; toml_string "$ROOT/etc/partizan/devices.toml"
        printf '\nadmin_sock = '; toml_string "$ROOT/run/partizan/admin.sock"
        printf '\n\n[tls]\nmode = "files"\ncert = '; toml_string "$ROOT/etc/partizan/tls/fullchain.pem"
        printf '\nkey = '; toml_string "$ROOT/etc/partizan/tls/key.pem"
        printf '\n\n[masquerade]\nmode = "static"\n\n[egress]\ndeny_private = true\nallow = []\n'
    } | save_file "$CONFIG" 640
    chown root:partizan "$CONFIG"
    if [[ ! -e "$ROOT/etc/partizan/devices.toml" ]]; then
        printf '' | save_file "$ROOT/etc/partizan/devices.toml" 600
        chown partizan:partizan "$ROOT/etc/partizan/devices.toml"
    fi
    cp "$SCRIPT_DIR/../packaging/server/partizan-server.service" "$ROOT/etc/systemd/system/partizan-server.service"
    chmod 644 "$ROOT/etc/systemd/system/partizan-server.service"
    install_binary
    start_service
    # Admin socket appears after systemd considers the process active.
    for ((attempt = 0; attempt < 20; attempt++)); do
        [[ ! -S "$ROOT/run/partizan/admin.sock" ]] || break
        sleep 1
    done
    [[ -S "$ROOT/run/partizan/admin.sock" ]] || die 'Не появился admin socket сервера.'
    "$DEST" device add "$DEVICE_NAME" --host "$SERVER_HOST" --config "$CONFIG"
    BINARY_CHANGED=0
    say 'Сервер установлен. Сохраните показанную ссылку: её нужно вставить в установщик клиента.'
    if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
        if confirm "Разрешить входящие TCP/UDP $SERVER_PORT в UFW?"; then
            ufw allow "$SERVER_PORT/tcp"
            ufw allow "$SERVER_PORT/udp"
        fi
    elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
        if confirm "Разрешить входящие TCP/UDP $SERVER_PORT в firewalld?"; then
            firewall-cmd --permanent --add-port="$SERVER_PORT/tcp" --add-port="$SERVER_PORT/udp"
            firewall-cmd --reload
        fi
    fi
    say "Разрешите входящие TCP и UDP $SERVER_PORT в firewall сервера и панели хостинга."
    if [[ "$TLS_CHOICE" == 2 ]]; then
        say "При продлении CA-сертификата обновляйте файлы в /etc/partizan/tls и выполняйте systemctl reload partizan-server."
    fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
