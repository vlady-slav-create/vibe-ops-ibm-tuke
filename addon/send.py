"""mitmproxy addon: turns what the proxy sees into signal events and sends them to an endpoint
where a diagnostic agent reads them. Events are RAW with respect to traffic: there are no
conclusions such as "this is a leak", the agent draws those. SECRETS, however, are masked here,
at the edge, before sending (see below).

Common event envelope (the same could be used for VPS logs):
  source       where the signal comes from ("network-capture")
  event        event type
  captured_at  time (UTC)
  ...          fields specific to the event

Events:
  http_exchange        a request + response went through (HTTP, or HTTPS decrypted by the proxy);
                       tls_terminated_by_proxy=true if the client accepted the proxy certificate
  tls_client_rejected  the client aborted the TLS handshake (for example, it did not trust the certificate)

Secret masking (REDACT_SECRETS, on by default):
  Nothing that is not needed for diagnosis should go to the cloud. So the values of the fields
  password / token / secret / api_key (in JSON, at any depth) and of the headers
  Authorization / Cookie / Set-Cookie / X-Api-Key are replaced with "[REDACTED]".
  A body that is not JSON is not sent at all (only its size is kept).
  The fact that a password was present is NOT lost: the names of the hidden fields are listed in
  redacted_fields (for example "request.body.password"), and the transport is visible in scheme.
  The agent draws the conclusion "a password went over http" itself. The values are visible only
  on the attacker screen (mitmweb).

Environment variables:
  ENDPOINT_URL     where to send (default: the local collector stub)
  ENDPOINT_TOKEN   if set, sent in the header Authorization: Bearer <token>
  REDACT_SECRETS   0 = send without masking (only to show "how not to do it" in a demo)
"""
import json
import os
import threading
import urllib.request
from datetime import datetime, timezone

from mitmproxy import ctx

ENDPOINT_URL = os.environ.get("ENDPOINT_URL", "http://collector:9000/ingest")
ENDPOINT_TOKEN = os.environ.get("ENDPOINT_TOKEN")
REDACT = os.environ.get("REDACT_SECRETS", "1") != "0"
SOURCE = "network-capture"

MASK = "[REDACTED]"
SECRET_KEYS = {
    "password", "passwd", "pwd", "secret", "token", "access_token", "refresh_token",
    "id_token", "api_key", "apikey",
}
SECRET_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key"}


def envelope(event, **fields):
    return {
        "source": SOURCE,
        "event": event,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        **fields,
    }


def _walk(value, path, found):
    """Recursively masks the values of secret keys in JSON; paths of hidden fields go into found."""
    if isinstance(value, dict):
        out = {}
        for key, val in value.items():
            here = f"{path}.{key}" if path else key
            if key.lower() in SECRET_KEYS:
                out[key] = MASK
                found.append(here)
            else:
                out[key] = _walk(val, here, found)
        return out
    if isinstance(value, list):
        return [_walk(v, path, found) for v in value]
    return value


def redact_body(text, prefix, found):
    """Returns the body to send. prefix is "request" or "response" (used in redacted_fields)."""
    if not REDACT or not text:
        return text
    try:
        data = json.loads(text)
    except ValueError:
        # Unknown format: do not risk it, do not send the content.
        return f"[omitted: not JSON, {len(text)} chars]"
    inner = []
    cleaned = _walk(data, "", inner)
    found.extend(f"{prefix}.body.{p}" for p in inner)
    return json.dumps(cleaned, ensure_ascii=False)


def redact_headers(headers, prefix, found):
    out = {}
    for name, value in headers.items():
        if REDACT and name.lower() in SECRET_HEADERS:
            out[name] = MASK
            found.append(f"{prefix}.headers.{name}")
        else:
            out[name] = value
    return out


def http_exchange(flow):
    req, resp = flow.request, flow.response
    found = []
    request = {
        "method": req.method,
        "host": req.pretty_host,
        "path": req.path,
        "headers": redact_headers(req.headers, "request", found),
        "body": redact_body(req.get_text(strict=False), "request", found),
    }
    response = {
        "status_code": resp.status_code,
        "headers": redact_headers(resp.headers, "response", found),
        "body": redact_body(resp.get_text(strict=False), "response", found),
    }
    return envelope(
        "http_exchange",
        scheme=req.scheme,  # http or https
        # A raw fact, not a conclusion: whether the client's TLS connection ended at the proxy
        # (rather than at the real server). For HTTPS this means the client accepted the proxy certificate.
        tls_terminated_by_proxy=bool(flow.client_conn.tls_established),
        client_ip=flow.client_conn.peername[0],
        redacted_fields=found,  # which fields were hidden (names, not values)
        request=request,
        response=response,
    )


def tls_client_rejected(conn):
    return envelope(
        "tls_client_rejected",
        client_ip=conn.peername[0] if conn.peername else None,
        sni=conn.sni,
        error=str(conn.error),
    )


def send(payload):
    headers = {"Content-Type": "application/json"}
    if ENDPOINT_TOKEN:
        headers["Authorization"] = f"Bearer {ENDPOINT_TOKEN}"
    try:
        req = urllib.request.Request(
            ENDPOINT_URL, data=json.dumps(payload).encode(), headers=headers, method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            ctx.log.info(f"sent {payload['event']} -> {r.status}")
    except Exception as exc:
        ctx.log.warn(f"send failed: {exc}")


def send_async(payload):
    # In a separate thread, so a slow endpoint does not slow down the browser.
    threading.Thread(target=send, args=(payload,), daemon=True).start()


def running():
    ctx.log.info(f"redaction: {'ON' if REDACT else 'OFF (secrets are sent in clear text!)'}")


def response(flow):
    # Do not send HTML pages (noise). Send API requests, including normal GETs: without "normal"
    # traffic the agent has nothing to compare the problematic traffic against.
    if "text/html" in flow.response.headers.get("content-type", ""):
        return
    send_async(http_exchange(flow))


def tls_failed_client(data):
    # The client refused to trust the proxy certificate: in a browser this is "your connection is not private".
    send_async(tls_client_rejected(data.conn))
