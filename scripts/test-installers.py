#!/usr/bin/env python3
"""Offline installer integration tests: real prompts/archives, fake OS and GitHub."""

import hashlib
import io
import json
import os
from pathlib import Path
import pty
import select
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest


REPO = Path(__file__).resolve().parent.parent
TOKEN = "installer-test-token"
URI = f"partizan://id:{TOKEN}@example.org?path=/auth"
MOCK = r'''#!/usr/bin/env python3
import json, os, pathlib, shutil, socket, sys
root = pathlib.Path(os.environ['PARTIZAN_INSTALL_ROOT'])
fixture = pathlib.Path(os.environ['INSTALLER_FIXTURE'])
name, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
with (fixture / 'commands').open('a') as log:
    log.write(json.dumps([name] + args) + '\n')
if name == 'id':
    print('0' if args == ['-u'] else 'partizan')
elif name == 'uname':
    print(os.environ.get('INSTALLER_ARCH', 'x86_64') if args == ['-m'] else 'Linux')
elif name in ('chown', 'useradd', 'groupadd', 'sleep'):
    pass
elif name == 'getent':
    print('partizan:x:1000:')
elif name == 'curl':
    destination = pathlib.Path(args[args.index('--output') + 1])
    url = args[-1]
    source = fixture / ('release.json' if url.endswith('/releases/latest') else url.rsplit('/', 1)[-1])
    if not source.exists(): sys.exit(22)
    shutil.copyfile(source, destination)
elif name == 'cp':
    subprocess = __import__('subprocess')
    subprocess.run(['/bin/cp'] + args, check=True)
    if args[-1].endswith('/etc/init.d/partizan'):
        # Execute a fake procd rather than the host's /etc/rc.common.
        shutil.copyfile(args[-1], fixture / 'installed-procd-template')
        shutil.copyfile(fixture / 'mock', args[-1])
elif name == 'uci':
    lines = sys.stdin.read().splitlines()
    config = root / 'etc/config/partizan'
    config.write_text('\n'.join(lines))
elif name == 'systemctl' or '/etc/init.d/' in sys.argv[0]:
    action = args[0] if args else ''
    if action in ('is-active', 'running'):
        sys.exit(0 if (fixture / 'active').exists() else 1)
    if action == 'stop': (fixture / 'active').unlink(missing_ok=True)
    if action == 'restart':
        binaries = list(root.glob('usr/**/partizan*'))
        old = any(p.is_file() and p.read_bytes() == b'old-binary' for p in binaries)
        if os.environ.get('INSTALLER_FAIL_START') == '1' and not old: sys.exit(1)
        (fixture / 'active').touch()
        sock_path = root / 'run/partizan/admin.sock'
        sock_path.parent.mkdir(parents=True, exist_ok=True)
        sock_path.unlink(missing_ok=True)
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(sock_path))
        sock.close()
elif name in ('partizan', 'partizan-server'):
    if args[0] == 'version': print('partizan 0.1.0 (protocol v1)')
    elif args[0] == 'check': sys.exit(1 if os.environ.get('INSTALLER_FAIL_CHECK') == '1' else 0)
    elif args[0] == 'status': print(json.dumps({'connected': True}))
    elif args[:2] == ['device', 'add']: print('partizan://generated-test-client')
else:
    raise SystemExit('unexpected command: ' + name)
'''


class Installers(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="partizan-installer-", dir="/tmp")
        self.fixture = Path(self.temp.name)
        self.root = self.fixture / "root"
        (self.root / "run/systemd/system").mkdir(parents=True)
        self.mock = self.fixture / "mock"
        self.mock.write_text(MOCK)
        self.mock.chmod(0o755)
        mock_bin = self.fixture / "mock-bin"
        mock_bin.mkdir()
        for name in ("curl", "id", "uname", "chown", "useradd", "groupadd", "getent", "systemctl", "sleep", "uci", "cp"):
            (mock_bin / name).symlink_to(self.mock)
        self.env = dict(os.environ, PATH=f"{mock_bin}:{os.environ['PATH']}",
                        PARTIZAN_INSTALL_ROOT=str(self.root), INSTALLER_FIXTURE=str(self.fixture))
        assets = []
        sums = []
        for suffix, binary in (("server-linux-x86_64", "partizan-server"),
                               ("client-linux-x86_64", "partizan"),
                               ("client-openwrt-armv8", "partizan")):
            name = f"partizan-0.1.0-{suffix}.tar.gz"
            with tarfile.open(self.fixture / name, "w:gz") as tar:
                for entry, data in ((binary, MOCK.encode()), ("LICENSE", b"AGPLv3"),
                                    ("BUILD-INFO", b"version=0.1.0\n")):
                    info = tarfile.TarInfo(f"{name[:-7]}/{entry}")
                    info.size = len(data)
                    info.mode = 0o755 if entry == binary else 0o644
                    tar.addfile(info, io.BytesIO(data))
                traversal = tarfile.TarInfo("../../must-not-be-created")
                traversal.size = 1
                tar.addfile(traversal, io.BytesIO(b"x"))
            sums.append(f"{hashlib.sha256((self.fixture / name).read_bytes()).hexdigest()}  {name}\n")
            assets.append({"name": name, "browser_download_url": f"https://example.invalid/{name}"})
        (self.fixture / "SHA256SUMS").write_text("".join(sums))
        assets.append({"name": "SHA256SUMS", "browser_download_url": "https://example.invalid/SHA256SUMS"})
        (self.fixture / "release.json").write_text(json.dumps({"tag_name": "v0.1.0", "assets": assets}))

    def tearDown(self):
        self.temp.cleanup()

    def run_installer(self, role, responses=(), success=True):
        master, slave = pty.openpty()
        proc = subprocess.Popen(["bash", str(REPO / f"scripts/install-{role}.sh")],
                                stdin=slave, stdout=slave, stderr=slave, env=self.env)
        os.close(slave)
        output = b""
        response_index = 0
        deadline = time.monotonic() + 30
        try:
            while time.monotonic() < deadline:
                readable, _, _ = select.select([master], [], [], 0.1)
                if readable:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    output += chunk
                if response_index < len(responses):
                    needle, answer = responses[response_index]
                    if needle.encode() in output:
                        time.sleep(0.02)
                        os.write(master, (answer + "\n").encode())
                        response_index += 1
                if proc.poll() is not None:
                    break
            else:
                proc.kill()
                self.fail("installer timeout: " + output.decode(errors="replace"))
            proc.wait(timeout=5)
        finally:
            os.close(master)
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        text = output.decode(errors="replace")
        if success:
            self.assertEqual(proc.returncode, 0, text)
            self.assertEqual(response_index, len(responses), text)
        else:
            self.assertNotEqual(proc.returncode, 0, text)
        commands = (self.fixture / "commands").read_text()
        self.assertNotIn(TOKEN, commands, "device token leaked into process arguments")
        return text

    def client_responses(self):
        return [("Ссылка partizan://", URI), ("Адрес SOCKS5", ""), ("Установить клиент", "y")]

    def test_linux_client_initial_install_and_secret_permissions(self):
        self.run_installer("client", self.client_responses())
        uri = self.root / "etc/partizan/client.uri"
        self.assertEqual(uri.read_text().strip(), URI)
        self.assertEqual(uri.stat().st_mode & 0o777, 0o600)
        self.assertTrue((self.root / "etc/systemd/system/partizan-client.service").exists())
        self.assertFalse((self.fixture.parent / "must-not-be-created").exists())

    def test_openwrt_armv8_install(self):
        (self.root / "etc").mkdir(exist_ok=True)
        (self.root / "etc/openwrt_release").touch()
        self.env["INSTALLER_ARCH"] = "aarch64"
        self.run_installer("client", self.client_responses())
        config = self.root / "etc/config/partizan"
        self.assertIn(URI, config.read_text())
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        self.assertTrue((self.root / "etc/hotplug.d/iface/90-partizan").exists())
        self.assertIn("USE_PROCD=1", (self.fixture / "installed-procd-template").read_text())

    def test_checksum_mismatch_does_not_install(self):
        (self.fixture / "SHA256SUMS").write_text("0" * 64 + "  partizan-0.1.0-client-linux-x86_64.tar.gz\n")
        self.run_installer("client", success=False)
        self.assertFalse((self.root / "usr/local/bin/partizan").exists())
        self.assertFalse((self.root / "etc/partizan/client.uri").exists())

    def test_missing_release_asset_does_not_install(self):
        (self.fixture / "release.json").write_text('{"assets": []}')
        self.run_installer("client", success=False)
        self.assertFalse((self.root / "usr/local/bin/partizan").exists())

    def test_failed_connection_does_not_write_config(self):
        self.env["INSTALLER_FAIL_CHECK"] = "1"
        self.run_installer("client", [("Ссылка partizan://", URI), ("Адрес SOCKS5", "")], success=False)
        self.assertFalse((self.root / "etc/partizan/client.uri").exists())

    def existing_server(self):
        for directory in ("etc/partizan", "etc/systemd/system", "usr/local/bin"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        config = self.root / "etc/partizan/server.toml"
        config.write_text("existing server config\n")
        (self.root / "etc/partizan/devices.toml").write_text("existing registry\n")
        (self.root / "etc/systemd/system/partizan-server.service").write_text("existing unit\n")
        binary = self.root / "usr/local/bin/partizan-server"
        binary.write_text("old-binary")
        binary.chmod(0o755)
        (self.fixture / "active").touch()
        return binary

    def test_server_upgrade_preserves_config_and_registry(self):
        binary = self.existing_server()
        self.run_installer("server", [("Обновить сервер", "y")])
        self.assertIn("partizan", binary.read_text())
        self.assertEqual((self.root / "etc/partizan/server.toml").read_text(), "existing server config\n")
        self.assertEqual((self.root / "etc/partizan/devices.toml").read_text(), "existing registry\n")

    def test_failed_upgrade_restores_old_binary(self):
        binary = self.existing_server()
        self.env["INSTALLER_FAIL_START"] = "1"
        self.run_installer("server", [("Обновить сервер", "y")], success=False)
        self.assertEqual(binary.read_text(), "old-binary")
        self.assertTrue((self.fixture / "active").exists())

    def test_cancel_upgrade_leaves_old_binary(self):
        binary = self.existing_server()
        self.run_installer("server", [("Обновить сервер", "n")])
        self.assertEqual(binary.read_text(), "old-binary")

    def test_server_initial_install_uses_persistent_certificate(self):
        responses = [("Публичный IP-адрес", "example.org"), ("TCP/UDP порт", "443"),
                     ("TLS: 1", "1"), ("Имя первого клиента", ""), ("Установить сервер", "y")]
        self.run_installer("server", responses)
        config = (self.root / "etc/partizan/server.toml").read_text()
        self.assertIn('mode = "files"', config)
        cert = self.root / "etc/partizan/tls/fullchain.pem"
        previous = cert.read_bytes()
        self.run_installer("server", [("Обновить сервер", "y")])
        self.assertEqual(cert.read_bytes(), previous)
        self.assertEqual((self.root / "etc/partizan/tls/key.pem").stat().st_mode & 0o777, 0o640)

    def test_server_accepts_existing_certificate_and_key(self):
        cert, key = self.fixture / "provided.pem", self.fixture / "provided-key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                        "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj",
                        "/CN=example.org", "-out", str(cert), "-keyout", str(key)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        responses = [("Публичный IP-адрес", "example.org"), ("TCP/UDP порт", "443"),
                     ("TLS: 1", "2"), ("Путь к fullchain.pem", str(cert)),
                     ("Путь к приватному ключу", str(key)), ("Имя первого клиента", ""),
                     ("Установить сервер", "y")]
        self.run_installer("server", responses)
        self.assertEqual((self.root / "etc/partizan/tls/fullchain.pem").read_bytes(), cert.read_bytes())
        self.assertEqual((self.root / "etc/partizan/tls/key.pem").read_bytes(), key.read_bytes())

    def test_client_upgrade_preserves_uri(self):
        self.run_installer("client", self.client_responses())
        uri = self.root / "etc/partizan/client.uri"
        previous = uri.read_bytes()
        self.run_installer("client", [("Обновить клиент", "y")])
        self.assertEqual(uri.read_bytes(), previous)

    def test_unsupported_server_architecture_is_rejected(self):
        self.env["INSTALLER_ARCH"] = "aarch64"
        self.run_installer("server", success=False)
        self.assertNotIn('"curl"', (self.fixture / "commands").read_text())


if __name__ == "__main__":
    unittest.main(verbosity=2)
