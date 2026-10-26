#!/bin/sh
# Test optional admission/fallback without cloning or compiling an engine.
set -eu
script=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/apply-modsecurity-optimization.sh
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/bin"
cat > "$work/bin/git" <<'EOF'
#!/bin/sh
case "$1" in
 rev-parse) printf '%s\n' "$WAF_TEST_SOURCE";;
 apply)
  if [ "${2:-}" = --check ]; then exit "$WAF_TEST_CHECK"; fi
  printf 'applied\n' >> "$WAF_TEST_MARKER";;
 *) exit 9;;
esac
EOF
chmod +x "$work/bin/git"
export PATH="$work/bin:$PATH"
export WAF_TEST_SOURCE=1925753989ccce977cdaae417b55c9726c7cf02c
export WAF_TEST_CHECK=0 WAF_TEST_MARKER="$work/applied"
check() {
 sh "$script" "$1" "$work/patch" "$work/$2.json"
 python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["state"]==sys.argv[2] and d["reason"]==sys.argv[3]' "$work/$2.json" "$3" "$4"
}
check 3.0.17 known optimized verified-source
[ "$(wc -l < "$work/applied")" -eq 1 ]
check 3.0.18 next upstream source-not-admitted
check 4.0.0 major upstream source-not-admitted
WAF_TEST_SOURCE=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
check 3.0.17 changed-source upstream source-not-admitted
WAF_TEST_SOURCE=1925753989ccce977cdaae417b55c9726c7cf02c
WAF_TEST_CHECK=1
check 3.0.17 inapplicable upstream patch-not-applicable
[ "$(wc -l < "$work/applied")" -eq 1 ]
if sh "$script" '3.0.17"bad' "$work/patch" "$work/invalid.json"; then exit 1; fi
[ ! -e "$work/invalid.json" ]
echo 'Optional optimization: six admission/fallback checks passed'
