"""Prepare patched PHP source with a pinned Docker Official Image recipe.

This is the emergency path while Docker Hub is still building its release tags.
The upstream recipe verifies both the release SHA-256 and its GPG signature.
"""

import argparse
from pathlib import Path
import re
import time
from urllib.request import urlopen


UPSTREAM_REF = "e3eaff845f7a9f7259c31da54dce0320b47a3bbd"
PHP_VERSION = "8.5.12"
PHP_SHA256 = "08bc2eba2a588654ade1357174aa646b761556c862dda0678345ee29ed481209"
UPSTREAM_URL = (
    f"https://raw.githubusercontent.com/docker-library/php/{UPSTREAM_REF}"
    "/8.5/alpine3.23/fpm"
)
HELPERS = (
    "docker-php-source",
    "docker-php-entrypoint",
    "docker-php-ext-configure",
    "docker-php-ext-enable",
    "docker-php-ext-install",
)


def fetch(name):
    for attempt in range(3):
        try:
            with urlopen(f"{UPSTREAM_URL}/{name}", timeout=30) as response:
                return response.read().decode("utf-8")
        except OSError:
            if attempt == 2:
                raise
            time.sleep(2)


def prepare(destination):
    upstream = fetch("Dockerfile")
    if not re.search(rf"^ENV PHP_VERSION {re.escape(PHP_VERSION)}$", upstream, re.M):
        raise ValueError("Unexpected PHP release in upstream recipe")
    if f'ENV PHP_SHA256="{PHP_SHA256}"' not in upstream:
        raise ValueError("Unexpected PHP release checksum in upstream recipe")
    if "gpg --batch --verify php.tar.xz.asc php.tar.xz" not in upstream:
        raise ValueError("The upstream recipe must verify the release signature")
    upstream, count = re.subn(
        r"^FROM alpine:3\.23$", "FROM alpine:3.23 AS patched-php", upstream, flags=re.M
    )
    if count != 1:
        raise ValueError("Unexpected upstream base image")

    custom = Path(__file__).with_name("Dockerfile").read_text(encoding="utf-8")
    custom, count = re.subn(
        r"^FROM php:8\.5-fpm-alpine3\.23$", "FROM patched-php", custom, flags=re.M
    )
    if count != 1:
        raise ValueError("Unexpected project base image")

    helpers = {name: fetch(name) for name in HELPERS}
    destination.mkdir(parents=True, exist_ok=False)
    for name, content in helpers.items():
        helper = destination / name
        helper.write_text(content, encoding="utf-8", newline="\n")
        helper.chmod(0o755)
    (destination / "Dockerfile").write_text(
        upstream + "\n\n" + custom, encoding="utf-8", newline="\n"
    )
    print(f"Prepared PHP {PHP_VERSION} from docker-library/php@{UPSTREAM_REF}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    prepare(parser.parse_args().destination)
