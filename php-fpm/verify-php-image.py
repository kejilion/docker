"""Check patched PHP images and bounded session/multipart OOM recovery."""

import argparse
import json
from pathlib import Path
import re
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


def request(port, script, body=b"", allow_disconnect=False):
    params = {
        "SCRIPT_FILENAME": f"/checks/{script}", "REQUEST_METHOD": "POST" if body else "GET",
        "REQUEST_URI": f"/{script}", "QUERY_STRING": "", "CONTENT_LENGTH": str(len(body)),
        "SERVER_PROTOCOL": "HTTP/1.1", "GATEWAY_INTERFACE": "CGI/1.1",
        "SERVER_NAME": "localhost", "SERVER_PORT": "80", "REMOTE_ADDR": "127.0.0.1",
    }
    if body:
        params["CONTENT_TYPE"] = "multipart/form-data; boundary=php-security-check"
        params["HTTP_COOKIE"] = "PHPSESSID=0123456789abcdef0123456789abcdef"
    encoded = b""
    for key, value in params.items():
        key, value = key.encode(), value.encode()
        encoded += length(len(key)) + length(len(value)) + key + value
    payload = record(1, struct.pack("!HB5x", 1, 0)) + record(4, encoded) + record(4)
    output = b""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
        def receive(size):
            data = b""
            while len(data) < size:
                part = connection.recv(size - len(data))
                if not part:
                    raise EOFError("FPM closed the connection")
                data += part
            return data

        try:
            connection.sendall(payload)
            for offset in range(0, len(body), 65535):
                connection.sendall(record(5, body[offset:offset + 65535]))
            connection.sendall(record(5))
            while True:
                _, kind, _, size, padding, _ = struct.unpack("!BBHHBB", receive(8))
                body = receive(size)
                if padding:
                    receive(padding)
                if kind in (6, 7):
                    output += body
                elif kind == 3:
                    return output
        except (OSError, EOFError):
            if allow_disconnect:
                return output
            raise


def ready(port, version):
    last = b""
    for _ in range(60):
        try:
            output = request(port, "ready.php")
            last = output[-2048:]
            if f"READY:{version}".encode() in output:
                return
        except (OSError, EOFError) as error:
            last = str(error).encode()
        time.sleep(0.5)
    raise RuntimeError(f"FPM did not become ready or recover: {last!r}")


def multipart(value):
    # Ordinary upload-progress/file fields followed by a bounded POST field.
    return (
        b'--php-security-check\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\ncheck\r\n'
        b'--php-security-check\r\nContent-Disposition: form-data; name="file"; filename="check.txt"\r\n'
        b'Content-Type: text/plain\r\n\r\nx\r\n'
        b'--php-security-check\r\nContent-Disposition: form-data; name="field"\r\n\r\n'
        + value + b'\r\n--php-security-check--\r\n'
    )


def verify(image, profile):
    print(docker("run", "--rm", "--entrypoint", "php", image, "-v").stdout)
    code = """
        if (PHP_VERSION_ID === 70433 && %s) {
            if (ini_get('max_multipart_body_parts') === false
                || getenv('PHP_SECURITY_BACKPORT') !== '%s') {
                throw new RuntimeException('Official PHP 7.4 backport is missing');
            }
        } elseif (PHP_MAJOR_VERSION !== 8 || PHP_MINOR_VERSION !== 5 || PHP_VERSION_ID < 80512) {
            throw new RuntimeException('Patched PHP 8.5 or the official 7.4 backport is required');
        }
        foreach (%s as $extension) {
            if (!extension_loaded($extension)) {
                throw new RuntimeException('Missing extension: ' . $extension);
            }
        }
        if (!function_exists('opcache_get_status')) {
            throw new RuntimeException('OPcache is missing');
        }
        echo PHP_VERSION;
    """ % (
        "true" if profile == "full" else "false", BACKPORT_REF,
        json.dumps(['bcmath', 'exif', 'gd', 'intl', 'mysqli', 'pdo_mysql', 'redis', 'soap', 'zip']
                   + (['imagick', 'SourceGuardian'] if profile == "full" else [])),
    )
    version = docker("run", "--rm", "--entrypoint", "php", image, "-r", code).stdout.strip()
    print(f"Patched PHP {version} and required extensions verified")
    print(docker("run", "--rm", "--entrypoint", "php-fpm", image, "-t").stderr)
    if profile == "full":
        print(docker("run", "--rm", "--entrypoint", "composer", image, "--version").stdout)
    oom_code = (
        "register_shutdown_function(function () { echo 'UNSAFE_SHUTDOWN_RAN'; });"
        "str_repeat('x', 32 * 1024 * 1024); echo 'OOM_NOT_TRIGGERED';"
    )
    if version == "7.4.33":
        oom = docker(
            "run", "--rm", "--memory=128m", "--entrypoint", "php", image,
            "-d", "memory_limit=8M", "-r", oom_code, check=False,
        )
        if (oom.returncode != 1 or "Allowed memory size" not in oom.stderr
                or "UNSAFE_SHUTDOWN_RAN" in oom.stdout or "OOM_NOT_TRIGGERED" in oom.stdout):
            raise RuntimeError(f"Unexpected OOM shutdown behavior: {oom}")
        print("Patched CLI OOM path exits directly without running shutdown callbacks")

    container = f"php-security-check-{time.time_ns()}"
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        root.chmod(0o755)
        (root / "ready.php").write_text("<?php echo 'READY:' . PHP_VERSION;")
        (root / "oom.php").write_text("<?php ini_set('memory_limit', '8M');" + oom_code)
        # Test-only settings deliberately enable the session parsing entry point.
        (root / "pool.conf").write_text(
            "[www]\nlisten=0.0.0.0:9000\npm=static\npm.max_children=1\n"
            "php_admin_value[memory_limit]=16M\n"
            "php_admin_value[post_max_size]=32M\n"
            "php_admin_value[upload_max_filesize]=1M\n"
            "php_admin_flag[session.upload_progress.enabled]=on\n"
            "php_admin_flag[session.use_strict_mode]=off\n"
            "php_admin_value[session.save_path]=/tmp\n"
            "php_admin_flag[display_errors]=on\n"
            "php_admin_flag[log_errors]=on\n"
            "php_admin_value[error_log]=/proc/self/fd/2\n"
        )
        for file in root.iterdir():
            file.chmod(0o644)
        try:
            docker("run", "-d", "--name", container, "--memory=256m", "--cpus=1", "--pids-limit=64",
                   "-p", "127.0.0.1::9000", "-v", f"{root}:/checks:ro",
                   "-v", f"{root / 'pool.conf'}:/usr/local/etc/php-fpm.d/zz-security-check.conf:ro", image)
            port = int(docker("port", container, "9000/tcp").stdout.strip().rsplit(":", 1)[1])
            ready(port, version)
            expected = f"READY:{version}".encode()
            if expected not in request(port, "ready.php", multipart(b"normal")):
                raise RuntimeError("Normal multipart upload failed")
            output = request(port, "ready.php", multipart(b"x" * (24 * 1024 * 1024)), allow_disconnect=True)
            if expected in output:
                raise RuntimeError("Multipart OOM was not triggered before script execution")
            ready(port, version)
            if expected not in request(port, "ready.php", multipart(b"after-oom")):
                raise RuntimeError("Multipart/session parsing did not recover after OOM")
            if version == "7.4.33":
                output = request(port, "oom.php", allow_disconnect=True)
                if b"UNSAFE_SHUTDOWN_RAN" in output or b"OOM_NOT_TRIGGERED" in output:
                    raise RuntimeError(f"Unexpected FPM OOM response: {output!r}")
                ready(port, version)
            logs = docker("logs", container)
            combined = logs.stdout + logs.stderr
            if "Allowed memory size" not in combined:
                raise RuntimeError("No PHP memory-limit failure was observed")
            if re.search(r"exited on signal (?:6|11)\b|SIGSEGV|SIGABRT", combined):
                raise RuntimeError("FPM worker crashed during the bounded multipart check")
            print("Session multipart OOM confirmed before script execution; GET and multipart requests recover")
        except Exception:
            logs = docker("logs", container, check=False)
            print(logs.stdout + logs.stderr, file=sys.stderr)
            raise
        finally:
            docker("rm", "-f", container, check=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("--profile", choices=("full", "php85"), default="full")
    args = parser.parse_args()
    verify(args.image, args.profile)
