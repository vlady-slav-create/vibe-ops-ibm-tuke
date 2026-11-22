# Build new objects; never copy scanner text, URLs, or matched evidence.
# Input: ZAP's traditional JSON report. Output: one content-free scan event.
# export.sh supplies $captured_at (export time).
# jq notation: `|` passes a value onward; `.` means current value;
# `[...[] | ...]` transforms array items; `{...}` constructs a new object.

# Accept ZAP numbers or digit-only numeric strings, then enforce integer bounds.
# Reject booleans, free text, fractions, negatives and values above $max.
def integer($max):
  if type == "string" and test("^[0-9]{1,8}$") then tonumber
  elif type == "number" then .
  else error("invalid numeric field") end
  | if floor == . and . >= 0 and . <= $max then .
    else error("numeric field out of range") end;

# ZAP's built-in rule title (fixed per rule, not per request). Kept only if it
# matches a strict allowlist (same pattern as schemas.json ruleName).
def name_re: "^[A-Za-z0-9 ._:/()'\"-]{1,100}$";

# Endpoint allowlist (keep in sync with schemas.json evidencePath). Anything else,
# and every query string/fragment, collapses to "[other]" or is dropped.
def uri_path:
  sub("^[a-zA-Z]+://[^/?#]+"; "") | split("?")[0] | split("#")[0]
  | if . == "" then "/" else . end
  | if IN("/", "/login", "/api/health", "/api/schedule", "/api/courses", "/api/grades") then . else "[other]" end;
def uri_scheme: if startswith("https://") then "https" else "http" end;
def uris: [(.instances // [])[].uri | select(type == "string")];
# Parameter/header/cookie NAMES only (never values or evidence); strict identifier shape.
def param_re: "^[A-Za-z][A-Za-z0-9_.-]{0,31}$";
# Names only. Drop anything value-like: equal to matched evidence, used as a value
# in the instance URI ("=name"), or token-shaped (4+ digit run, 12+ hex chars).
def params: [(.instances // [])[] | select(.param != .evidence)
             | (.uri // "" | tostring) as $uri | .param | select(type == "string" and test(param_re))
             | . as $p | select($uri | contains("=" + $p) | not)
             | select(test("[0-9]{4,}|^[A-Fa-f0-9]{12,}$") | not)] | unique | .[:10];

# Validate the restricted snapshot schema.
# `keys` is sorted by jq, so exact comparisons also reject unexpected fields.
# Rule IDs stay digit-only strings; risk is 0..3, confidence 0..4 (0 means
# scanner-classified false positive), and instance counts are bounded.
def snapshot:
  if type != "object" or keys != ["findings"] or (.findings | type) != "array"
  then error("invalid snapshot") else . end
  | {findings: [.findings[] |
      if (keys - ["name", "paths", "schemes", "params"]) != ["confidence", "instances", "risk", "rule_id"]
      then error("invalid finding fields") else . end
      | {rule_id: (.rule_id | tostring | if test("^[0-9]{1,8}$") then . else error("invalid rule ID") end),
         risk: (.risk | integer(3)), confidence: (.confidence | integer(4)),
         instances: (.instances | integer(1000000))}
        + (if has("name") then {name: (.name | if type == "string" and test(name_re) then . else error("invalid rule name") end)} else {} end)
        + (if has("paths") then {paths: (.paths | if type == "array" and all(.[]; IN("/", "/login", "/api/health", "/api/schedule", "/api/courses", "/api/grades", "[other]")) then unique else error("invalid paths") end)} else {} end)
        + (if has("params") then {params: (.params | if type == "array" and length <= 10 and all(.[]; type == "string" and test(param_re)) then unique else error("invalid params") end)} else {} end)
        + (if has("schemes") then {schemes: (.schemes | if type == "array" and all(.[]; IN("http", "https")) then unique else error("invalid schemes") end)} else {} end)]}
  # Keep evidence small and ensure each rule appears only once per snapshot.
  | if (.findings | length) > 50 or
       ([.findings[].rule_id] | length) != ([.findings[].rule_id] | unique | length)
    then error("too many or duplicate rules") else . end;

# Content-free transport counts from the local HAR (URLs/bodies never exported).
# No severity-raising heuristics here: agents judge impact from ZAP findings.
def exposure:
  [$har[0].log.entries[] | .request] as $r
  | {http_requests: [$r[] | select(.url | startswith("http://"))] | length,
     https_requests: [$r[] | select(.url | startswith("https://"))] | length,
     tls_client_rejected: (($tls[0].tls_client_rejected // 0) | integer(1000000))};

# Allowlisted TLS facts from sslyze JSON (run in compose against the HTTPS portal). Only booleans,
# protocol names and cipher-suite names leave; certificate names, serials and keys never do.
# The model rates severity; no hints here. Absent or incomplete scans emit nothing (unknown).
def tls_config:
  ($tls_scan[0].server_scan_results[0]) as $s
  | ($s.scan_result) as $r
  | ($r.certificate_info.result.certificate_deployments[0]) as $d
  | ($d.received_certificate_chain[0]) as $leaf
  | if $s.connectivity_status != "COMPLETED" or $r == null or $d == null or $leaf == null
       or ($d.path_validation_results // [] | length) == 0 then empty
    else
      {proto: {ssl_2_0_cipher_suites: "SSL 2.0", ssl_3_0_cipher_suites: "SSL 3.0", tls_1_0_cipher_suites: "TLS 1.0",
               tls_1_1_cipher_suites: "TLS 1.1", tls_1_2_cipher_suites: "TLS 1.2", tls_1_3_cipher_suites: "TLS 1.3"}} as $p
      | {scanned: true,
         self_signed: ($leaf.subject.rfc4514_string == $leaf.issuer.rfc4514_string),
         expired: (($leaf.not_valid_after | fromdateiso8601) < ($captured_at | fromdateiso8601)),
         chain_trusted_all_stores: ([$d.path_validation_results[].was_validation_successful] | all),
         protocols_accepted: [$p.proto | to_entries[] | select($r[.key].result.is_tls_version_supported == true) | .value],
         accepted_ciphers: ([$p.proto | to_entries[] | ($r[.key].result.accepted_cipher_suites // [])[] | .cipher_suite.name] | unique | .[:40])}
    end;

# 1. Check report structure and accept only this demo's configured origins.
# Origin is checked locally, never included in exported event. This prevents
# labeling unrelated reports as demo-portal; it does not verify HAR freshness.
if (.site | type) != "array" then error("expected ZAP JSON report") else . end
| [.site[] |
    if (.["@name"] as $origin |
        ["http://server:8080", "https://server:8443", "http://localhost:8082", "https://localhost:8083"] | index($origin)
       ) then . else error("non-demo report origin") end
    # 2. Flatten each site's alerts and select only approved numeric facts.
    # `count` is ZAP's reported instance count, not users or leaked secrets.
    # Descriptions, instance URLs, evidence and other report fields are dropped
    # by constructing a new object, not by trying to redact known secrets.
    | .alerts[] |
    {rule_id: (.pluginid | tostring | if test("^[0-9]{1,8}$") then . else error("invalid rule ID") end),
     risk: (.riskcode | integer(3)), confidence: (.confidence | integer(4)),
     instances: (.count | integer(1000000)),
     paths: ([uris[] | uri_path] | unique), schemes: ([uris[] | uri_scheme] | unique), params: params}
    + ((.name // .alert) | if type == "string" and test(name_re) then {name: .} else {} end)]
# 3. Merge repeated rule IDs across sites: highest risk, lowest confidence,
# summed instance counts. Lowest confidence avoids overstating merged evidence.
# group_by also sorts groups by rule ID for stable output.
| group_by(.rule_id)
| {findings: map({rule_id: .[0].rule_id, risk: (map(.risk) | max),
                  confidence: (map(.confidence) | min), instances: (map(.instances) | add),
                  paths: (map(.paths) | add | unique), schemes: (map(.schemes) | add | unique),
                  params: (map(.params) | add | unique | .[:10])}
                 + (map(.name // empty)[0] | if . == null then {} else {name: .} end))}
# 4. Validate merged counts/schema against limits before building the event.
| snapshot
# 5. Attach fixed asset identity and export timestamp. Paths are allowlisted,
# schemes are http/https, params are names only. export.sh adds hash ID.
| {source: "zap-passive", event: "zap_scan", asset_id: "demo-portal",
   captured_at: $captured_at, current: .}
  + (if ($har | length) == 1 then {exposure: exposure} else {} end)
  + ([tls_config] | if length == 1 then {tls_config: .[0]} else {} end)