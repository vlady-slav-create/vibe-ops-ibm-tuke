# Construct allowlisted objects; never copy bodies, headers or query values.
if .source == "zap-passive" then
  {source, event, asset_id, captured_at, current, baseline: (.baseline // null)}
else
  {source, event, captured_at} +
  (if .event == "http_exchange" then
     {scheme, tls_terminated_by_proxy,
      request: {method: .request.method,
                path: (.request.path | split("?")[0] |
                       if . as $path | $paths | index($path) then . else "[other]" end)},
      response: {status_code: .response.status_code},
      redacted_fields: [(.redacted_fields // [])[] | ascii_downcase | split(".") |
                        (.[0:2] + [.[-1]] | join(".")) |
                        select(test($redacted_field) and (test("\\s") | not))] | unique}
   else {} end)
end