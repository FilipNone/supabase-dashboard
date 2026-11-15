#!/bin/sh
# Makes a throwaway certificate authority and a certificate for localhost,
# writes the fixture-only SMTP login, and starts the mail fixture. Safe to
# run again: existing files are kept.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
certs="$here/certs"
mkdir -p "$certs"

if [ ! -f "$certs/ca.crt" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
        -subj "/CN=supabase-dashboard mail fixture CA" \
        -keyout "$certs/ca.key" -out "$certs/ca.crt" 2>/dev/null
    openssl req -newkey rsa:2048 -nodes \
        -subj "/CN=localhost" \
        -keyout "$certs/server.key" -out "$certs/server.csr" 2>/dev/null
    printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > "$certs/san.ext"
    openssl x509 -req -days 30 -in "$certs/server.csr" \
        -CA "$certs/ca.crt" -CAkey "$certs/ca.key" -CAcreateserial \
        -extfile "$certs/san.ext" -out "$certs/server.crt" 2>/dev/null
    # Mailpit runs as a non-root user and must read the key.
    chmod 644 "$certs/server.key"
fi
[ -f "$certs/smtp-auth" ] || printf 'dashboard:fixture-only-password\n' > "$certs/smtp-auth"

docker compose -f "$here/docker-compose.yml" up -d --wait --wait-timeout 60
