"""Prepare PHP 7.4.33 with PHP's minimal CVE-2026-109618/109619 backport.

Keep the compatible legacy build recipe, verify the signed release and the
official patch, and also repack patched source for subsequent extension builds.
This does not restore upstream support for PHP 7.4 or its legacy Alpine base.
"""

import argparse
import hashlib
from pathlib import Path
import re
import time
from urllib.request import urlopen


RECIPE_REF = "b9f17156020c3aef71df681b27684533529347a7"
BACKPORT_REF = "712e60f9edfd03f0960fc4fc3c2c375f42b90aa2"
PATCH_SHA256 = "5fe57ca6ee96d59b36c6e0ca842843c50884f177bef1e85234cf669b577f5e48"
SOURCE_SHA256 = "924846abf93bc613815c55dd3f5809377813ac62a9ec4eb3778675b82a27b927"
RECIPE_URL = (
    f"https://raw.githubusercontent.com/docker-library/php/{RECIPE_REF}"
    "/7.4/alpine3.16/fpm"
)
HELPERS = (
    "docker-php-source", "docker-php-entrypoint", "docker-php-ext-configure",
    "docker-php-ext-enable", "docker-php-ext-install",
)


def fetch(url):
    for attempt in range(3):
        try:
            with urlopen(url, timeout=60) as response:
                return response.read()
        except OSError:
            if attempt == 2:
                raise
            time.sleep(2)


def prepare(destination):
    upstream = fetch(f"{RECIPE_URL}/Dockerfile").decode("utf-8")
    if ("ENV PHP_VERSION 7.4.33\n" not in upstream
            or f'ENV PHP_SHA256="{SOURCE_SHA256}"' not in upstream
            or "gpg --batch --verify php.tar.xz.asc php.tar.xz" not in upstream):
        raise ValueError("Unexpected legacy release recipe or missing signature check")
    upstream, count = re.subn(
        r"^FROM alpine:3\.16$", "FROM alpine:3.16 AS patched-php74", upstream, flags=re.M
    )
    if count != 1:
        raise ValueError("Unexpected legacy Alpine base")
    patch = fetch(f"https://github.com/php/php-src/commit/{BACKPORT_REF}.patch")
    if hashlib.sha256(patch).hexdigest() != PATCH_SHA256:
        raise ValueError("Official PHP backport checksum mismatch")

    upstream = upstream.replace(
        "COPY docker-php-source /usr/local/bin/",
        "COPY docker-php-source /usr/local/bin/\n"
        "COPY security.patch /usr/src/php74-security.patch\n"
        f"ENV PHP_SECURITY_BACKPORT={BACKPORT_REF}",
        1,
    )
    # Patch before compilation and preserve patched headers/source for PECL.
    anchor = "\tcd /usr/src/php; \\\n"
    if upstream.count(anchor) != 1:
        raise ValueError("Unexpected upstream compilation step")
    apply_patch = (
        anchor
        + "\tapk add --no-cache --virtual .security-patch-deps patch; \\\n"
        + f"\techo '{PATCH_SHA256}  /usr/src/php74-security.patch' | sha256sum -c -; \\\n"
        + "\tpatch --batch --fuzz=0 -p1 < /usr/src/php74-security.patch; \\\n"
        + "\tpatch --batch --fuzz=0 --dry-run -R -p1 < /usr/src/php74-security.patch; \\\n"
        + "\ttar -cJf /usr/src/php.tar.xz --exclude='.docker-extracted' -C /usr/src php; \\\n"
        + "\tapk del --no-network .security-patch-deps; \\\n"
    )
    upstream = upstream.replace(anchor, apply_patch, 1)
    custom = Path(__file__).with_name("Dockerfile-PHP74").read_text(encoding="utf-8")
    custom, count = re.subn(
        r"^FROM php:7\.4-fpm-alpine$", "FROM patched-php74", custom, flags=re.M
    )
    if count != 1:
        raise ValueError("Unexpected project PHP 7.4 base")
    helpers = {name: fetch(f"{RECIPE_URL}/{name}") for name in HELPERS}
    destination.mkdir(parents=True, exist_ok=False)
    for name, content in helpers.items():
        helper = destination / name
        helper.write_bytes(content)
        helper.chmod(0o755)
    (destination / "security.patch").write_bytes(patch)
    (destination / "Dockerfile").write_text(
        upstream + "\n\n" + custom, encoding="utf-8", newline="\n"
    )
    print(f"Prepared PHP 7.4.33 with official backport {BACKPORT_REF}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    prepare(parser.parse_args().destination)
