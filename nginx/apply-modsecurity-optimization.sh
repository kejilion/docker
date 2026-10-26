#!/bin/sh
# An optional optimization must never pin or block an upstream engine upgrade.
set -eu
version=$1
patch=$2
record=$3
source=$(git rev-parse HEAD)
case "$version" in ''|*[!0-9.]*) echo 'Invalid engine version' >&2; exit 1;; esac
case "$source" in ''|*[!0-9a-f]*) echo 'Invalid source identity' >&2; exit 1;; esac
[ "${#source}" -eq 40 ] || { echo 'Invalid source identity length' >&2; exit 1; }
state=upstream
reason=source-not-admitted
if [ "$version" = 3.0.17 ] && [ "$source" = 1925753989ccce977cdaae417b55c9726c7cf02c ]; then
    if git apply --check "$patch"; then
        git apply "$patch"
        state=optimized
        reason=verified-source
    else
        reason=patch-not-applicable
    fi
fi
printf '{"schemaVersion":1,"engineVersion":"%s","sourceCommit":"%s","state":"%s","reason":"%s"}\n' \
    "$version" "$source" "$state" "$reason" > "$record"
echo "ModSecurity target matching: $state ($reason); upstream upgrades remain available."
