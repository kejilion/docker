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
SecRule &TX:allowed_methods "@eq 0" \
    "id:100001110,phase:1,pass,nolog,t:none,setvar:'tx.allowed_methods=|GET| |HEAD| |POST| |OPTIONS| |PUT| |PATCH| |DELETE|'"
SecRule &TX:early_blocking "@eq 0" \
    "id:100001115,phase:1,pass,nolog,t:none,setvar:tx.early_blocking=1"
EOF

# Older policies set space-separated lists before CRS. Preserve each configured token.
cat > /etc/nginx/modsec/normalize-request-allowlists.lua <<'EOF'
function main()
    for _, setting in ipairs({"allowed_methods", "allowed_http_versions"}) do
        local name = "tx." .. setting
        local value = m.getvar(name)
        if value then
            local normalized = value:gsub("%S+", function(token)
                if token:find("|", 1, true) then return token end
                return "|" .. token .. "|"
            end)
            if normalized ~= value then
                m.setvar("tx.kejilion_original_" .. setting, value)
                m.setvar(name, normalized)
            end
        end
    end
    return nil
end
EOF

# Run after CRS collects plugin values. Requests with native lists skip Lua.
cat > /etc/nginx/modsec/rules/REQUEST-910-KEJILION-COMPAT.conf <<'EOF'
SecRule TX:allowed_methods "!@rx (?:^|[[:space:]])[^|[:space:]]+(?:[[:space:]]|$)" \
    "id:100001111,phase:1,pass,nolog,t:none,skipAfter:KEJILION-ALLOWLISTS-NORMALIZED,chain"
    SecRule TX:allowed_http_versions "!@rx (?:^|[[:space:]])[^|[:space:]]+(?:[[:space:]]|$)" "t:none"
SecRuleScript /etc/nginx/modsec/normalize-request-allowlists.lua "id:100001112,phase:1,pass,nolog"
SecMarker KEJILION-ALLOWLISTS-NORMALIZED
EOF

# Keep the original representation for host rules that inspect the lists in phase 2.
cat > /etc/nginx/modsec/rules/REQUEST-920-Z-KEJILION-ALLOWLIST-COMPAT.conf <<'EOF'
SecRule TX:kejilion_original_allowed_methods "@rx \S" \
    "id:100001113,phase:1,pass,nolog,t:none,setvar:'tx.allowed_methods=%{MATCHED_VAR}'"
SecRule TX:kejilion_original_allowed_http_versions "@rx \S" \
    "id:100001114,phase:1,pass,nolog,t:none,setvar:'tx.allowed_http_versions=%{MATCHED_VAR}'"
EOF

# Keep managed path coverage and existing target exclusions on the same rule ID.
rce_rules=/etc/nginx/modsec/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf
if [ -f "$rce_rules" ] && awk '
    $1 == "SecRule" { targets = $2 }
    /^[[:space:]]*"id:932260,/ && targets !~ /(^|\|)REQUEST_FILENAME(\||$)/ { missing = 1 }
    END { exit !missing }
' "$rce_rules"; then
    printf '%s\n' 'SecRuleUpdateTargetById 932260 "REQUEST_FILENAME"' \
        > /etc/nginx/modsec/rules/REQUEST-932-Z-KEJILION-PATH-COMPAT.conf
fi
