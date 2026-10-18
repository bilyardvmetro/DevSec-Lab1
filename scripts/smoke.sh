#!/usr/bin/env bash
# Isolated curl integration run; credentials and database are temporary.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
pid=''
cleanup() { if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi; rm -rf "$work"; }
trap cleanup EXIT
mkdir -p "$root/bin"
go build -o "$root/bin/api" "$root/cmd/api"
go build -o "$root/bin/hash" "$root/cmd/hash"
export ADMIN_USERNAME=student
password=$(openssl rand -hex 18)
export ADMIN_PASSWORD_HASH=$(printf '%s\n' "$password" | "$root/bin/hash")
export JWT_SECRET=$(openssl rand -base64 32)
export LISTEN_ADDR=127.0.0.1:18080
(cd "$work" && exec "$root/bin/api") > "$work/server.log" 2>&1 &
pid=$!
base=http://127.0.0.1:18080
for _ in $(seq 1 50); do if curl -s "$base/api/data" > /dev/null; then break; fi; sleep 0.2; done
expect() {
  label=$1; expected=$2; shift 2
  status=$(curl -sS -o "$work/body.json" -w '%{http_code}' "$@")
  printf '%s: HTTP %s\n' "$label" "$status"
  if [ "$status" != "$expected" ]; then cat "$work/body.json"; exit 1; fi
}
expect 'Anonymous GET /api/data' 401 "$base/api/data"
expect 'Anonymous POST /api/data' 401 -X POST "$base/api/data"
expect 'Wrong password' 401 -H 'Content-Type: application/json' -d '{"username":"student","password":"wrong"}' "$base/auth/login"
expect 'SQLi login' 401 -H 'Content-Type: application/json' -d "{\"username\":\"' OR 1=1 --\",\"password\":\"wrong\"}" "$base/auth/login"
expect 'Login' 200 -H 'Content-Type: application/json' -d "{\"username\":\"student\",\"password\":\"$password\"}" "$base/auth/login"
token=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])' < "$work/body.json")
expect 'Create note with XSS payload' 201 -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d '{"title":"Security","content":"<script>alert(1)</script>"}' "$base/api/data"
python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["content"] == "&lt;script&gt;alert(1)&lt;/script&gt;"; print("XSS escaped:", d["content"])' < "$work/body.json"
expect 'Authorized GET /api/data' 200 -H "Authorization: Bearer $token" "$base/api/data"
cat "$work/body.json"
expect 'Malformed JWT' 401 -H 'Authorization: Bearer invalid' "$base/api/data"
expect 'Unknown JSON field' 400 -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d '{"title":"x","admin":true}' "$base/api/data"
expect 'Wrong media type' 415 -H 'Content-Type: text/plain' -d '{}' "$base/auth/login"
printf 'All curl integration checks passed.\n'
