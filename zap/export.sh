#!/bin/sh
# Usage: sh zap/export.sh
set -eu
umask 077
directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
private="${EXPORT_PRIVATE_DIR:-$directory/private}"
temporary=$(mktemp "$private/.event.XXXXXX")
trap 'rm -f "$temporary" "$temporary.final"' EXIT HUP INT TERM
# Remove old output so failed filtering cannot leave a stale publishable event.
rm -f "$private/event.json"
jq -aceS --arg captured_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --slurpfile tls "$( [ -f "$private/tls.json" ] && echo "$private/tls.json" || echo /dev/null )" \
  --slurpfile har "$( [ -f "$private/traffic.har" ] && echo "$private/traffic.har" || echo /dev/null )" \
  --slurpfile tls_scan "$( [ -f "$private/sslyze.json" ] && echo "$private/sslyze.json" || echo /dev/null )" \
  -f "$directory/findings.jq" "$private/report.json" > "$temporary"
event_id=$(sha256sum "$temporary" | cut -d ' ' -f 1)
jq -ce --arg event_id "$event_id" '. + {event_id: $event_id}' \
  "$temporary" > "$temporary.final"
test "$(wc -c < "$temporary.final")" -le 16384
mv "$temporary.final" "$private/event.json"
printf '%s\n' 'Sanitized event.json ready; publish with AWS CLI.'