# sniff-lab

A local signal source for a diagnostic agent. It intercepts traffic between a client and a demo portal, turns it into JSON events and sends them to an endpoint where an agent looks for problems. All data is fake: the portal accepts any non-empty username and password (for example `student` / `demo-password`).

HTTP and HTTPS here are **test data**, not the topic itself: traffic in which the agent has to notice that something is wrong. The same approach would work for VPS logs (use-case 1), just with a different `source`.

## Overview

```
browser / tools/traffic.py ──► mitmproxy ──► server (Campus Demo portal)
                                   │
                                   ├─ attacker screen (mitmweb :8081): sees everything, including the password
                                   │
                                   └─ addon/send.py ──► collector (stub)  ──►  AWS endpoint
                                      masks secrets     JSON events             diagnostic agent
```

Two levels of visibility, which is a useful point for the talk:

| Who | What they see |
|-----|---------------|
| Attacker (mitmweb) | Everything as is, password in clear text |
| Agent in the cloud | Events without secret values: `"password": "[REDACTED]"` plus `redacted_fields: ["request.body.password"]` |

## Containers

| Container | Role |
|-----------|------|
| `server` | Campus Demo portal and a small API: HTTP :8080 and HTTPS :8443. Not exposed to the host |
| `mitmproxy` | Sits in front of the server, shows traffic (mitmweb) and sends events through the addon |
| `collector` | Stub for the real endpoint: prints received events to its log |

## Run

```bash
docker-compose up -d
docker-compose logs -f collector     # the events the agent would receive
```

Stop: `docker-compose down`. If you have `docker compose` (with a space), you can drop the hyphen.

## Addresses

| Address | Role |
|---------|------|
| http://localhost:8082 | Portal over HTTP |
| https://localhost:8083 | Portal over HTTPS (proxy certificate, the browser will warn) |
| http://localhost:8081/?token=demo | mitmweb: what the attacker sees |

## Server API

| Request | Response |
|---------|----------|
| `GET /` | Portal page |
| `GET /api/health` | 200 |
| `GET /api/schedule` | 200, schedule |
| `GET /api/courses` | 200, courses |
| `POST /login` with any non-empty username and password | 200 with a token |
| `POST /login` with an empty field | 401 |
| `GET /api/grades` with `Authorization: Bearer demo-token-123` | 200 |
| `GET /api/grades` without a token | 401 |
| anything else | 404 |

## Traffic generator

```bash
python3 tools/traffic.py -n 5     # 5 rounds
```

Run it from the Mac, nothing to install. One round is 10 requests, mixing normal and problematic traffic. The agent gets them without labels and has to tell them apart.

| Kind | Requests | Event in the collector |
|------|----------|------------------------|
| Normal | `GET /api/health`, `/api/schedule`, `/api/courses`, login, `GET /api/grades` with a token (all 200) | `http_exchange`, `scheme: http` |
| Noise | login with an empty password (401), `GET /api/grades` without a token (401), `GET /nope` (404) | `http_exchange`, `scheme: http` |
| Transport | HTTPS with the certificate ignored | `http_exchange`, `scheme: https`, `tls_terminated_by_proxy: true` |
| Transport | HTTPS with the certificate verified | `tls_client_rejected` |

By hand: open the portal in a browser. On :8083 the browser warns about the certificate. "Continue" is the ignored-certificate case, refusing is the verified case.

## Secret masking

Earlier, the password and token went to the cloud in clear text. Now the addon masks them **at the edge**, before sending. The cloud should not receive anything it does not need for diagnosis.

- In JSON (at any depth) the values of the keys `password`, `passwd`, `pwd`, `secret`, `token`, `access_token`, `refresh_token`, `id_token`, `api_key`, `apikey` become `[REDACTED]`.
- So do the headers `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`.
- A body that is not JSON is not sent at all (you get `[omitted: not JSON, N chars]`). This is the safe default.
- The fact that a password was there is not lost: the names of the hidden fields are in `redacted_fields`, and the transport is visible in `scheme`. The agent draws the conclusion "a password went over HTTP" itself.

To turn masking off (only to show how not to do it in a demo): `REDACT_SECRETS=0 docker-compose up -d`. The mitmproxy log prints `redaction: ON` or `OFF` at startup.

Verified by a run: with masking on, the values `demo-password` and `demo-token-123` do not appear in the collector log; with masking off they do.

## Event format

A common envelope for any source:

| Field | Meaning |
|-------|---------|
| `source` | Where the signal comes from (here `network-capture`) |
| `event` | Event type |
| `captured_at` | Time, UTC |

Events are raw with respect to traffic: the conclusion ("this is a leak") is drawn by the agent, not the addon.

**`http_exchange`**: a request and response went through. Fields: `scheme`, `tls_terminated_by_proxy` (the client accepted the proxy certificate), `client_ip`, `redacted_fields`, `request` (method, host, path, headers, body), `response` (status_code, headers, body).

**`tls_client_rejected`**: the client aborted the TLS handshake. Fields: `client_ip`, `sni`, `error`.

Example `http_exchange` (shortened):

```json
{
  "source": "network-capture",
  "event": "http_exchange",
  "scheme": "http",
  "tls_terminated_by_proxy": false,
  "redacted_fields": ["request.body.password", "response.body.token"],
  "request":  {"method": "POST", "path": "/login", "body": "{\"username\": \"student\", \"password\": \"[REDACTED]\"}"},
  "response": {"status_code": 200, "body": "{\"status\": \"ok\", \"token\": \"[REDACTED]\"}"}
}
```

This is a **draft**, not yet agreed with the endpoint owner. It is built in `addon/send.py`.

## Connecting the real endpoint

```bash
ENDPOINT_URL=https://... ENDPOINT_TOKEN=... docker-compose up -d
```

Without these variables, events go to the `collector`. Authorization is currently a Bearer token only.

## Notes

- `client_ip` in the events is the Docker gateway (`172.20.0.1`), not the Mac.
- Reverse mode rewrites the address: the client goes to `localhost:8082`, while the event's `host` is `server`.
- After a rejected TLS handshake, the `server` log may show a `BrokenPipeError`. It is harmless (the proxy manages to open a connection to the server and then closes it), but do not show that log in a recording.

## Portal

`server/index.html` has a deliberately fictional name (Campus Demo) and its own look. It is not a copy of any real system. Do not turn it back into something that resembles a real university portal, and do not host it publicly. The interface is in English; it is easy to change in the file itself.

## Certificate

`certs/make-certs.sh` creates a self-signed server certificate (`certs/server.crt`, `certs/server.key`). Demo only; they are not committed, so run the script after cloning. A certificate created on 2026-11-10 is valid for one year. The browser in the demo is not shown this one but the mitmproxy certificate: this one is only for the proxy-to-server connection.

## Open items

- Agree the endpoint contract: URL and method, authorization (Bearer, API key or IAM), the JSON fields the agent needs, one event per request or a batch.
