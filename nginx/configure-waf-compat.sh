#!/bin/sh
# Build-time image defaults only: never edits mounted Nginx/CF/host configuration.
set -eu

config=/etc/nginx/modsec/modsecurity.conf
set_directive() {
    awk -v key="$1" -v value="$2" '
        $1 == key { if (!seen++) print key " " value; next }
        { print }
        END { if (!seen) print key " " value }
    ' "$config" > "$config.compat-tmp"
    mv "$config.compat-tmp" "$config"
}

set_directive SecRequestBodyLimit 1073741824
set_directive SecRequestBodyNoFilesLimit 8388608
set_directive SecRequestBodyJsonDepthLimit 64
set_directive SecArgumentsLimit 2048
set_directive SecXmlExternalEntity Off
# Keep the recommended argument-budget rejection aligned with its parser limit.
sed -i '/^SecRule &ARGS[[:space:]]/s/@ge [0-9][0-9]*/@ge 2048/' "$config"

# The shared policy has its own site-scoped controls. This compatible image
# default permits standard REST methods and leaves every CRS attack rule active.
# Early blocking retains the installed score thresholds. DetectionOnly still
# inspects subsequent phases; blocked traffic records fewer matching body rules.
cat > /etc/nginx/modsec/plugins/ldnmp-compat-config.conf <<'EOF'
SecAction "id:100001110,phase:1,pass,nolog,t:none,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE',setvar:tx.early_blocking=1"
EOF
