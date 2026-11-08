#!/usr/bin/env bash
# Demonstrates the API with curl. Start the server first: python run.py
# Usage: bash scripts/demo.sh [base_url]
BASE="${1:-http://127.0.0.1:5000}"
JSON="Content-Type: application/json"

step() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$1"; }

if ! curl -sS -m 5 -o /dev/null "$BASE/health"; then
  echo "Server is not reachable at $BASE. Start it with: python run.py" >&2
  echo "On Windows use Git Bash: WSL bash cannot reach the Windows localhost." >&2
  exit 1
fi

step "1. GET /api/data without token (expect 401)"
curl -sS -i "$BASE/api/data"

step "2. POST /auth/login with wrong password (expect 401)"
curl -sS -i -X POST "$BASE/auth/login" -H "$JSON" -d '{"username":"alice","password":"wrong"}'

step "3. POST /auth/login with SQL injection payload (expect 401)"
curl -sS -i -X POST "$BASE/auth/login" -H "$JSON" -d "{\"username\":\"' OR '1'='1' --\",\"password\":\"x\"}"

step "4. POST /auth/login with valid credentials (expect 200 + JWT)"
RESP=$(curl -sS -X POST "$BASE/auth/login" -H "$JSON" -d '{"username":"alice","password":"Alice_Passw0rd!"}')
echo "$RESP"
TOKEN=$(echo "$RESP" | sed -E 's/.*"access_token":"([^"]+)".*/\1/')

step "5. GET /api/data with token (expect 200)"
curl -sS -i "$BASE/api/data" -H "Authorization: Bearer $TOKEN"

step "6. GET /api/data with forged token (expect 401)"
curl -sS -i "$BASE/api/data" -H "Authorization: Bearer ${TOKEN}tampered"

step "7. POST /api/posts with XSS payload (expect 201, HTML escaped)"
curl -sS -i -X POST "$BASE/api/posts" -H "$JSON" -H "Authorization: Bearer $TOKEN" \
  -d '{"title":"<script>alert(1)</script>","content":"<img src=x onerror=alert(1)>"}'

step "8. GET /api/data?search= with SQL injection payload (expect 200, count 0)"
curl -sS -G "$BASE/api/data" --data-urlencode "search=' OR '1'='1" -H "Authorization: Bearer $TOKEN"
echo
