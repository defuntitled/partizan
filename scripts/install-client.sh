#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=scripts/install-common.sh
source "$SCRIPT_DIR/install-common.sh"

main() {
    local archive uri socks_host socks_port attempt octet
    local -a octets
    installer_init "$@"
    case "$(uname -m):$OPENWRT" in
        x86_64:*) archive=client-linux-x86_64 ;;
        aarch64:1|arm64:1) archive=client-openwrt-armv8 ;;
        *) die 'Доступны Linux x86_64 и OpenWrt ARMv8/AArch64 (также OpenWrt x86_64).' ;;
    esac
    if (( OPENWRT )); then
        command -v uci >/dev/null || die 'Не найдена UCI.'
        CONFIG="$ROOT/etc/config/partizan"
        DEST="$ROOT/usr/bin/partizan"
        SERVICE=partizan
        ADMIN_SOCKET="$ROOT/var/run/partizan.sock"
    else
        require_systemd
        CONFIG="$ROOT/etc/partizan/client.uri"
        DEST="$ROOT/usr/local/bin/partizan"
        SERVICE=partizan-client
        ADMIN_SOCKET="$ROOT/run/partizan-client/admin.sock"
    fi
    ensure_dependencies curl jq tar gzip sha256sum
    PROGRAM=partizan
    fetch_binary "$archive"

    if [[ -f "$CONFIG" ]]; then
        say 'Найдена конфигурация клиента. URI и настройки SOCKS будут сохранены.'
        confirm 'Обновить клиент до последнего релиза и перезапустить службу?' || return 0
    else
        printf 'Ссылка partizan:// из установщика сервера (ввод скрыт): ' >&2
        IFS= read -rs uri || die 'Ввод прерван.'
        printf '\n' >&2
        [[ "$uri" == partizan://* && "$uri" != *$'\r'* && "$uri" != *$'\n'* ]] || die 'Некорректная ссылка.'
        printf '%s\n' "$uri" > "$WORK/client.uri"
        unset uri
        ask SOCKS_LISTEN 'Адрес SOCKS5 (для доступа с LAN укажите LAN-IP роутера)' 127.0.0.1:1080
        socks_port=${SOCKS_LISTEN##*:}
        socks_host=${SOCKS_LISTEN%:*}
        [[ "$socks_host" =~ ^[0-9.]+$ || "$socks_host" =~ ^\[[a-fA-F0-9:]+\]$ ]] || die 'Нужен числовой адрес IPv4:порт или [IPv6]:порт.'
        if [[ "$socks_host" != \[* ]]; then
            IFS=. read -ra octets <<< "$socks_host"
            [[ ${#octets[@]} == 4 && "$socks_host" != *. ]] || die 'Некорректный IPv4-адрес SOCKS.'
            for octet in "${octets[@]}"; do
                [[ "$octet" =~ ^[0-9]{1,3}$ ]] || die 'Некорректный IPv4-адрес SOCKS.'
                (( 10#$octet <= 255 )) || die 'Некорректный IPv4-адрес SOCKS.'
            done
        else
            [[ "$socks_host" == *:* ]] || die 'Некорректный IPv6-адрес SOCKS.'
        fi
        port_valid "$socks_port" || die 'Некорректный SOCKS-порт.'
        say 'Проверяю подключение к серверу…'
        "$WORK/payload/partizan" check --uri-file "$WORK/client.uri" || die 'Не удалось подключиться. Проверьте URI и доступность TCP/UDP порта сервера.'
        confirm "Установить клиент, SOCKS5 $SOCKS_LISTEN, с автозапуском?" || return 0

        if (( OPENWRT )); then
            mkdir -p "$ROOT/etc/config"
            : > "$CONFIG"
            chmod 600 "$CONFIG"
            # Batch input keeps the device token out of process arguments and UCI history.
            uri=$(cat "$WORK/client.uri")
            [[ "$uri" != *"'"* ]] || die 'Апостроф в URI должен быть percent-encoded.'
            {
                printf "set partizan.main=client\nset partizan.main.enabled='1'\n"
                printf "set partizan.main.uri='%s'\n" "$uri"
                printf "set partizan.main.socks_listen='%s'\n" "$SOCKS_LISTEN"
                printf "set partizan.main.log_level='info'\nset partizan.main.honest_connect='0'\ncommit partizan\n"
            } | uci -q batch
            unset uri
            chmod 600 "$CONFIG"
        else
            ensure_user
            mkdir -p "$ROOT/etc/partizan"
            chmod 750 "$ROOT/etc/partizan"
            chown root:partizan "$ROOT/etc/partizan"
            save_file "$CONFIG" 600 < "$WORK/client.uri"
            chown partizan:partizan "$CONFIG"
            printf 'SOCKS_LISTEN=%s\n' "$SOCKS_LISTEN" | save_file "$ROOT/etc/partizan/client.env" 640
            chown root:partizan "$ROOT/etc/partizan/client.env"
        fi
    fi

    if (( OPENWRT )); then
        mkdir -p "$ROOT/etc/init.d" "$ROOT/etc/hotplug.d/iface" "$ROOT/lib/upgrade/keep.d"
        if [[ ! -f "$ROOT/etc/init.d/partizan" ]]; then
            cp "$SCRIPT_DIR/../packaging/openwrt/partizan/files/partizan.init" "$ROOT/etc/init.d/partizan"
            chmod 755 "$ROOT/etc/init.d/partizan"
        fi
        if [[ ! -f "$ROOT/etc/hotplug.d/iface/90-partizan" ]]; then
            cp "$SCRIPT_DIR/../packaging/openwrt/partizan/files/partizan.hotplug" "$ROOT/etc/hotplug.d/iface/90-partizan"
            chmod 644 "$ROOT/etc/hotplug.d/iface/90-partizan"
        fi
        # Binary install has no opkg conffiles manifest, so explicitly preserve its config.
        printf '/etc/config/partizan\n' | save_file "$ROOT/lib/upgrade/keep.d/partizan" 644
    else
        mkdir -p "$ROOT/etc/systemd/system"
        if [[ ! -f "$ROOT/etc/systemd/system/partizan-client.service" ]]; then
            cp "$SCRIPT_DIR/../packaging/linux/partizan-client.service" "$ROOT/etc/systemd/system/partizan-client.service"
            chmod 644 "$ROOT/etc/systemd/system/partizan-client.service"
        fi
    fi
    install_binary
    start_service
    for ((attempt = 0; attempt < 20; attempt++)); do
        if "$DEST" status --admin-sock "$ADMIN_SOCKET" 2>/dev/null | jq -e '.connected == true' >/dev/null; then
            BINARY_CHANGED=0
            say "Клиент установлен и подключён. Конфигурация: $CONFIG"
            return 0
        fi
        sleep 1
    done
    die 'Клиент запущен, но соединение не установилось. Проверьте журнал службы и URI.'
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
