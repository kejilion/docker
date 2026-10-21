"""Check PHP 7.4's official backport and FPM recovery in isolated containers."""

from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time


BACKPORT_REF = "712e60f9edfd03f0960fc4fc3c2c375f42b90aa2"


def docker(*args, check=True):
    return subprocess.run(
        ["docker", *args], check=check, capture_output=True, text=True, timeout=60
    )


def record(kind, content=b""):
    return struct.pack("!BBHHBB", 1, kind, 1, len(content), 0, 0) + content


def length(value):
    return bytes([value]) if value < 128 else struct.pack("!I", value | 0x80000000)


def request(port, script, allow_disconnect=False):
    params = {
        "SCRIPT_FILENAME": f"/checks/{script}", "REQUEST_METHOD": "GET",
        "REQUEST_URI": f"/{script}", "QUERY_STRING": "", "CONTENT_LENGTH": "0",
        "SERVER_PROTOCOL": "HTTP/1.1", "GATEWAY_INTERFACE": "CGI/1.1",
        "SERVER_NAME": "localhost", "SERVER_PORT": "80", "REMOTE_ADDR": "127.0.0.1",
    }
    encoded = b""
    for key, value in params.items():
        key, value = key.encode(), value.encode()
        encoded += length(len(key)) + length(len(value)) + key + value
    payload = record(1, struct.pack("!HB5x", 1, 0)) + record(4, encoded) + record(4) + record(5)
    output = b""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
        connection.sendall(payload)

        def receive(size):
            data = b""
            while len(data) < size:
                part = connection.recv(size - len(data))
                if not part:
                    raise EOFError("FPM closed the connection")
                data += part
            return data

        try:
            while True:
                _, kind, _, size, padding, _ = struct.unpack("!BBHHBB", receive(8))
                body = receive(size)
                if padding:
                    receive(padding)
                if kind == 6:
                    output += body
                elif kind == 3:
                    return output
        except (OSError, EOFError):
            if allow_disconnect:
                return output
            raise


def ready(port):
    for _ in range(60):
        try:
            output = request(port, "ready.php")
            if b"READY:7.4.33" in output:
                return
        except (OSError, EOFError):
            pass
        time.sleep(0.5)
    raise RuntimeError("FPM did not become ready or recover")


def verify(image):
    print(docker("run", "--rm", "--entrypoint", "php", image, "-v").stdout)
    code = """
        if (PHP_VERSION_ID !== 70433 || ini_get('max_multipart_body_parts') === false
            || getenv('PHP_SECURITY_BACKPORT') !== '%s') {
            throw new RuntimeException('Official PHP 7.4 backport is missing');
        }
        foreach (['bcmath', 'exif', 'gd', 'imagick', 'intl', 'mysqli', 'pdo_mysql',
                  'redis', 'soap', 'zip', 'SourceGuardian', 'Zend OPcache'] as $extension) {
            if (!extension_loaded($extension)) {
                throw new RuntimeException('Missing extension: ' . $extension);
            }
        }
        echo 'Backport and required extensions verified';
    """ % BACKPORT_REF
    print(docker("run", "--rm", "--entrypoint", "php", image, "-r", code).stdout)
    print(docker("run", "--rm", "--entrypoint", "php-fpm", image, "-t").stderr)
    print(docker("run", "--rm", "--entrypoint", "composer", image, "--version").stdout)
    oom_code = (
        "register_shutdown_function(function () { echo 'UNSAFE_SHUTDOWN_RAN'; });"
        "str_repeat('x', 32 * 1024 * 1024); echo 'OOM_NOT_TRIGGERED';"
    )
    oom = docker(
        "run", "--rm", "--memory=128m", "--entrypoint", "php", image,
        "-d", "memory_limit=8M", "-r", oom_code, check=False,
    )
    if (oom.returncode != 1 or "Allowed memory size" not in oom.stderr
            or "UNSAFE_SHUTDOWN_RAN" in oom.stdout or "OOM_NOT_TRIGGERED" in oom.stdout):
        raise RuntimeError(f"Unexpected OOM shutdown behavior: {oom}")
    print("Patched CLI OOM path exits directly without running shutdown callbacks")

    container = f"php74-security-check-{time.time_ns()}"
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        root.chmod(0o755)
        (root / "ready.php").write_text("<?php echo 'READY:' . PHP_VERSION;")
        (root / "oom.php").write_text("<?php ini_set('memory_limit', '8M');" + oom_code)
        for file in root.iterdir():
            file.chmod(0o644)
        try:
            docker("run", "-d", "--name", container, "--memory=256m",
                   "-p", "127.0.0.1::9000", "-v", f"{root}:/checks:ro", image)
            port = int(docker("port", container, "9000/tcp").stdout.strip().rsplit(":", 1)[1])
            ready(port)
            output = request(port, "oom.php", allow_disconnect=True)
            if b"UNSAFE_SHUTDOWN_RAN" in output or b"OOM_NOT_TRIGGERED" in output:
                raise RuntimeError(f"Unexpected FPM OOM response: {output!r}")
            ready(port)
            print("FPM handles normal requests and recovers after a worker OOM")
        except Exception:
            logs = docker("logs", container, check=False)
            print(logs.stdout + logs.stderr, file=sys.stderr)
            raise
        finally:
            docker("rm", "-f", container, check=False)


if __name__ == "__main__":
    verify(sys.argv[1])
