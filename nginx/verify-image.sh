#!/usr/bin/env bash
set -euo pipefail

image="$1"
expected_version="$2"
container="nginx-image-check-$$"
test_dir="$(mktemp -d)"
cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$test_dir"
}
trap cleanup EXIT

docker run --rm --entrypoint nginx "$image" -V
version="$(docker run --rm --entrypoint nginx "$image" -v 2>&1)"
test "$version" = "nginx version: nginx/$expected_version"

# Load the custom modules; the base image also ships debug variants of its own.
docker run --rm --entrypoint sh "$image" -ec \
  'for module in ngx_http_brotli_filter_module ngx_http_brotli_static_module ngx_http_modsecurity_module ngx_http_zstd_filter_module ngx_http_zstd_static_module; do printf "load_module /etc/nginx/modules/%s.so;\n" "$module"; done' \
  > "$test_dir/nginx.conf"
cat >> "$test_dir/nginx.conf" <<'EOF'
events {}
http {
    access_log /dev/stdout;
    error_log /dev/stderr;
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/modsecurity.conf;
    modsecurity_rules 'SecRule ARGS:waf_smoke "@streq blocked" "id:100000001,phase:1,deny,status:403"';
    server {
        listen 80;
        root /usr/share/nginx/html;
        location / { try_files $uri $uri/ =404; }
    }
}
EOF

docker run --rm --entrypoint nginx \
  -v "$test_dir/nginx.conf:/etc/nginx/nginx.conf:ro" "$image" -t
docker run --detach --name "$container" -p 127.0.0.1::80 \
  -v "$test_dir/nginx.conf:/etc/nginx/nginx.conf:ro" "$image"
address="http://$(docker port "$container" 80/tcp)"
if ! curl --retry 10 --retry-all-errors --retry-delay 1 -fsS "$address/" -o /dev/null; then
  docker logs "$container"
  exit 1
fi
status="$(curl -sS -o /dev/null -w '%{http_code}' "$address/?waf_smoke=blocked")"
if [[ "$status" != 403 ]]; then
  docker logs "$container"
  echo "WAF smoke test expected HTTP 403, got $status" >&2
  exit 1
fi
echo "NGINX $expected_version: all modules, configuration, HTTP and WAF checks passed"
python3 "$(dirname "$0")/verify-waf-compat.py" --image "$image"
python3 "$(dirname "$0")/verify-target-exclusions.py" --image "$image"
