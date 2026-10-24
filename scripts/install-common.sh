#!/usr/bin/env bash
# Shared by the interactive installers; shipped in partizan-installers.tar.gz.

say() { printf '%s\n' "$*" >&2; }
die() { say "Ошибка: $*"; exit 1; }

ask() {
    local response
    printf '%s%s: ' "$2" "${3:+ [$3]}" >&2
    IFS= read -r response || die 'Ввод прерван.'
    printf -v "$1" '%s' "${response:-${3-}}"
}

confirm() {
    local answer
    ask answer "$1 (y/n)" "${2:-y}"
    [[ "$answer" == y || "$answer" == Y || "$answer" == yes || "$answer" == да ]]
}

installer_init() {
    [[ $# == 0 ]] || die 'Параметров нет: запустите скрипт без аргументов в терминале.'
    [[ -t 0 ]] || die 'Нужен интерактивный терминал. Скачайте архив и запустите скрипт через bash.'
    [[ $(id -u) == 0 ]] || die 'Запустите установщик от root (sudo bash ...).'
    [[ $(uname -s) == Linux ]] || die 'Поддерживается только Linux.'
    # Staging root for the integration tests; empty on a real installation.
    ROOT=${PARTIZAN_INSTALL_ROOT:-}
    [[ -z "$ROOT" || "$ROOT" =~ ^/[a-zA-Z0-9_./-]+$ ]] || die 'Некорректный PARTIZAN_INSTALL_ROOT.'
    REPOSITORY=${PARTIZAN_REPO:-defuntitled/partizan}
    [[ "$REPOSITORY" =~ ^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$ ]] || die 'Некорректный PARTIZAN_REPO.'
    OPENWRT=0
    [[ ! -f "$ROOT/etc/openwrt_release" ]] || OPENWRT=1
    umask 077
    WORK=$(mktemp -d)
    BINARY_CHANGED=0
    WAS_ACTIVE=0
    trap 'installer_cleanup "$?"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
}

installer_cleanup() {
    local status=$1
    if (( status != 0 && BINARY_CHANGED )); then
        say 'Установка не завершена; откатываю бинарник.'
        if [[ -f "$WORK/previous" ]]; then
            cp -p "$WORK/previous" "$DEST.rollback" && mv -f "$DEST.rollback" "$DEST"
            if (( WAS_ACTIVE )); then service_action restart || true; else service_action stop || true; fi
        else
            service_action stop || true
            service_action disable || true
            rm -f "$DEST"
        fi
        say 'Конфигурация сохранена для диагностики и повторного запуска.'
    fi
    rm -rf "$WORK"
    return "$status"
}

ensure_dependencies() {
    local command missing=0
    for command in "$@"; do command -v "$command" >/dev/null || missing=1; done
    (( missing )) || return 0
    confirm 'Установить необходимые curl, jq, tar, gzip, SHA-256 и OpenSSL?' || die 'Не установлены зависимости.'
    if command -v opkg >/dev/null; then
        opkg update
        opkg install curl ca-bundle jq tar gzip coreutils-sha256sum openssl-util
    elif command -v apt-get >/dev/null; then
        apt-get update
        apt-get install -y curl ca-certificates jq tar gzip coreutils openssl
    elif command -v dnf >/dev/null; then
        dnf install -y curl ca-certificates jq tar gzip coreutils openssl
    else
        die 'Установите зависимости вручную и повторите запуск.'
    fi
    for command in "$@"; do command -v "$command" >/dev/null || die "Не найдена команда $command."; done
}

download() {
    [[ "$1" == https://* ]] || die 'Ссылка загрузки должна использовать HTTPS.'
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 15 --max-time 300 --retry 3 --output "$2" "$1"
}

fetch_binary() {
    local suffix=$1 name url checksum_url expected actual stem
    say "Получаю последний опубликованный релиз $REPOSITORY…"
    download "https://api.github.com/repos/$REPOSITORY/releases/latest" "$WORK/release.json" ||
        die 'Релиз недоступен. Нужен публичный опубликованный GitHub Release с архивами и SHA256SUMS.'
    name=$(jq -er --arg suffix "-$suffix.tar.gz" \
        '[.assets[] | select(.name | endswith($suffix))] | if length == 1 then .[0].name else error("archive missing or ambiguous") end' "$WORK/release.json") || die 'Нет подходящего архива в релизе.'
    [[ "$name" =~ ^partizan-[a-zA-Z0-9.+_-]+\.tar\.gz$ ]] || die 'Небезопасное имя архива.'
    url=$(jq -er --arg name "$name" '.assets[] | select(.name == $name) | .browser_download_url' "$WORK/release.json")
    checksum_url=$(jq -er '[.assets[] | select(.name == "SHA256SUMS")] | if length == 1 then .[0].browser_download_url else error("SHA256SUMS missing") end' "$WORK/release.json") || die 'В релизе нет SHA256SUMS.'
    download "$checksum_url" "$WORK/SHA256SUMS"
    download "$url" "$WORK/$name"
    expected=$(awk -v name="$name" '$2 == name { print $1 }' "$WORK/SHA256SUMS")
    [[ "$expected" =~ ^[a-fA-F0-9]{64}$ ]] || die 'Для архива нет единственной корректной контрольной суммы.'
    actual=$(sha256sum "$WORK/$name"); actual=${actual%% *}
    [[ "${expected,,}" == "$actual" ]] || die 'Не совпала SHA-256; установка остановлена.'
    stem=${name%.tar.gz}
    mkdir -p "$WORK/payload"
    # Extract only named files to stdout: archive paths and symlinks cannot write elsewhere.
    tar -xOzf "$WORK/$name" "$stem/$PROGRAM" > "$WORK/payload/$PROGRAM"
    tar -xOzf "$WORK/$name" "$stem/LICENSE" > "$WORK/payload/LICENSE"
    tar -xOzf "$WORK/$name" "$stem/BUILD-INFO" > "$WORK/payload/BUILD-INFO"
    chmod 700 "$WORK/payload/$PROGRAM"
    "$WORK/payload/$PROGRAM" version
    say 'Архив загружен; SHA-256 проверена.'
}

require_systemd() {
    command -v systemctl >/dev/null || die 'Для этой установки нужен systemd.'
    [[ -d "$ROOT/run/systemd/system" ]] || die 'systemd не запущен.'
}

ensure_user() {
    if ! getent group partizan >/dev/null; then
        command -v groupadd >/dev/null || die 'Не найдена groupadd (пакет passwd/shadow-utils).'
        groupadd --system partizan
    fi
    if ! id partizan >/dev/null 2>&1; then
        command -v useradd >/dev/null || die 'Не найдена useradd (пакет passwd/shadow-utils).'
        useradd --system --gid partizan --no-create-home --shell /usr/sbin/nologin partizan
    fi
}

service_action() {
    if (( OPENWRT )); then "$ROOT/etc/init.d/partizan" "$1";
    else systemctl "$1" "$SERVICE"; fi
}

service_active() {
    if (( OPENWRT )); then "$ROOT/etc/init.d/partizan" running >/dev/null 2>&1;
    else systemctl is-active --quiet "$SERVICE"; fi
}

install_binary() {
    local share="$ROOT/usr/share/licenses/$PROGRAM"
    mkdir -p "$(dirname "$DEST")" "$share"
    chmod 755 "$ROOT/usr/share/licenses" "$share"
    if [[ -f "$DEST" ]]; then cp -p "$DEST" "$WORK/previous"; fi
    service_active && WAS_ACTIVE=1
    cp "$WORK/payload/$PROGRAM" "$DEST.new"
    chmod 755 "$DEST.new"
    mv -f "$DEST.new" "$DEST"
    BINARY_CHANGED=1
    cp "$WORK/payload/LICENSE" "$share/LICENSE"
    cp "$WORK/payload/BUILD-INFO" "$share/BUILD-INFO"
    chmod 644 "$share/LICENSE" "$share/BUILD-INFO"
}

start_service() {
    local attempt
    if (( OPENWRT )); then service_action enable; else systemctl daemon-reload; systemctl enable "$SERVICE"; fi
    service_action restart
    for ((attempt = 0; attempt < 20; attempt++)); do
        if service_active; then return 0; fi
        sleep 1
    done
    die "Служба $SERVICE не запустилась. Проверьте journalctl -u $SERVICE или logread."
}

port_valid() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
host_valid() { [[ "$1" =~ ^[a-zA-Z0-9:][a-zA-Z0-9.:-]*$ && ${#1} -le 253 ]]; }
toml_string() { local value=${1//\\/\\\\}; value=${value//\"/\\\"}; printf '"%s"' "$value"; }

save_file() {
    # stdin -> atomic file; protect secrets even if the destination already exists.
    local path=$1 mode=$2
    mkdir -p "$(dirname "$path")"
    cat > "$path.new"
    chmod "$mode" "$path.new"
    mv -f "$path.new" "$path"
}
