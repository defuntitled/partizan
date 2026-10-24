# Static musl binary in an empty image. Build the binary first:
#   cargo zigbuild --release -p server --target x86_64-unknown-linux-musl
#   docker build -f packaging/server/Dockerfile -t partizan-server .
FROM scratch
COPY LICENSE /LICENSE
COPY target/x86_64-unknown-linux-musl/release/partizan-server /partizan-server
STOPSIGNAL SIGTERM
ENTRYPOINT ["/partizan-server", "run", "--config", "/etc/partizan/server.toml"]
