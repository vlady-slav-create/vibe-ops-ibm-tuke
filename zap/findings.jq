# Build new objects; never copy scanner text, URLs, or matched evidence.
# Input: ZAP's traditional JSON report. Output: one content-free scan event.
# export.sh supplies $captured_at (export time) and $baseline (array from
# --slurpfile: [] without a baseline, [previous_event] with one).
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

# Validate the restricted snapshot schema, used for both current and baseline.
# `keys` is sorted by jq, so exact comparisons also reject unexpected fields.
# Rule IDs stay digit-only strings; risk is 0..3, confidence 0..4 (0 means
# scanner-classified false positive), and instance counts are bounded.
def snapshot:
  if type != "object" or keys != ["findings"] or (.findings | type) != "array"
  then error("invalid snapshot") else . end
  | {findings: [.findings[] |
      if keys != ["confidence", "instances", "risk", "rule_id"]
      then error("invalid finding fields") else . end
      | {rule_id: (.rule_id | tostring | if test("^[0-9]{1,8}$") then . else error("invalid rule ID") end),
         risk: (.risk | integer(3)), confidence: (.confidence | integer(4)),
         instances: (.instances | integer(1000000))}]}
  # Keep evidence small and ensure each rule appears only once per snapshot.
  | if (.findings | length) > 50 or
       ([.findings[].rule_id] | length) != ([.findings[].rule_id] | unique | length)
    then error("too many or duplicate rules") else . end;

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
     instances: (.count | integer(1000000))}]
# 3. Merge repeated rule IDs across sites: highest risk, lowest confidence,
# summed instance counts. Lowest confidence avoids overstating merged evidence.
# group_by also sorts groups by rule ID for stable output.
| group_by(.rule_id)
| {findings: map({rule_id: .[0].rule_id, risk: (map(.risk) | max),
                  confidence: (map(.confidence) | min), instances: (map(.instances) | add)})}
# 4. Validate merged counts/schema against limits before building the event.
| snapshot
# 5. Attach fixed asset identity and export timestamp; never infer transport,
# affected paths or request coverage from alert counts. export.sh adds hash ID.
| {source: "zap-passive", event: "zap_scan", asset_id: "demo-portal",
   captured_at: $captured_at, current: .,
   # No baseline: null. Otherwise require exactly one matching event and reuse
   # only its validated current snapshot, not its metadata or nested baseline.
   # Agent compares snapshots later; this filter does not claim fixes/regressions.
   baseline: (if ($baseline | length) == 0 then null
              elif ($baseline | length) == 1 and $baseline[0].source == "zap-passive"
                   and $baseline[0].asset_id == "demo-portal"
              then $baseline[0].current | snapshot
              else error("invalid baseline") end)}