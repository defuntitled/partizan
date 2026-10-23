# Deploying partizan-server

Static binary, systemd or Docker. Commands assume a Debian-like VPS.

## Binary

```sh
cargo zigbuild --release -p server --target x86_64-unknown-linux-musl
install -m 755 target/x86_64-unknown-linux-musl/release/partizan-server /usr/local/bin/
```

## Certificate

With a domain: `certbot certonly --standalone -d cdn.example.com` (port 80 free), and a deploy
hook that copies the live certificate and key to `/etc/partizan/tls/` owned by `partizan`. With
`tls.mode = "files"` the server rereads them on SIGHUP and hourly, so renewals need no restart.
Without a public certificate use `mode = "self-signed"`; clients then rely on the pin in their
link.

## systemd

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin partizan
install -d -m 750 -o partizan -g partizan /etc/partizan /etc/partizan/tls
install -m 640 -o root -g partizan packaging/server/server.toml /etc/partizan/server.toml
install -m 600 -o partizan -g partizan /dev/null /etc/partizan/devices.toml
install -m 644 packaging/server/99-partizan.conf /etc/sysctl.d/ && sysctl --system
install -m 644 packaging/server/partizan-server.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now partizan-server
```

## Docker

```sh
docker build -f packaging/server/Dockerfile -t partizan-server .
docker compose -f packaging/server/docker-compose.yml up -d
```

Apply the sysctl settings on the host.

## Devices

```sh
partizan-server device add home-router --config /etc/partizan/server.toml
partizan-server device list
partizan-server session list
partizan-server device revoke home-router
```

`device add` prints the connection link once (and a QR code); put it into
`/etc/config/partizan` on the router. The CLI keeps `devices.toml` owned by its current owner.
