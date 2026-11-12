#!/bin/sh
# Self-signed certificate for the demo (fake, for sniff-lab only).
set -e
cd "$(dirname "$0")"
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout server.key -out server.crt \
  -subj "/CN=server" \
  -addext "subjectAltName=DNS:server,DNS:localhost"
chmod 644 server.key server.crt
echo "ok: certs/server.crt, certs/server.key"
