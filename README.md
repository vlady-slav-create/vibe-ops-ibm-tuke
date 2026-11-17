# sniff-lab

Local demo traffic, offline ZAP scanning, and agent-led security triage on AWS.
Only sanitized findings leave the host; raw captures stay local.

## Architecture

![Architecture overview](docs/architecture.svg)

| Architecture | Diagram | Editable |
| --- | --- | --- |
| Overview | [SVG](docs/architecture.svg) | [Draw.io](docs/architecture.drawio) |
| Single agent (`single`) | [SVG](docs/architecture-alternative-1.svg) | [Draw.io](docs/architecture-alternative-1.drawio) |
| Model-directed orchestrator (`orchestrator`) | [SVG](docs/architecture-alternative-2.svg) | [Draw.io](docs/architecture-alternative-2.drawio) |
| Parallel reviews (`graph`) | [SVG](docs/architecture-alternative-3.svg) | [Draw.io](docs/architecture-alternative-3.drawio) |

### Single agent (`single`)

![Single-agent architecture](docs/architecture-alternative-1.svg)

### Model-directed orchestrator (`orchestrator`)

![Model-directed orchestrator architecture](docs/architecture-alternative-2.svg)

### Parallel reviews (`graph`)

![Parallel-review graph architecture](docs/architecture-alternative-3.svg)

## Agent robustness and cost controls

`single` remains the default. All report-producing agents use Strands structured
output backed by the existing JSON Schema; evidence citation checks still run
after generation. Invalid, truncated, or budget-exhausted reports are not published.
Single requests allow two turns and one failed structured-output attempt;
orchestrator requests share an eight-turn budget with nested agents. Token limits
are checked between calls, not hard billing caps. Per-response output stays capped
at 6,000 tokens. Graph nodes and specialists retain hard call caps (two each).

Terraform `prompt_cache_enabled` defaults to `true`. Strands automatic model
detection caches only static system prefixes with a five-minute TTL, not evidence
messages. Disable for unsupported models. Model-specific minimum token thresholds
still apply; small prompts may produce no cache hits. Caching is not scan memory.

Runtime emits allowlisted JSON metrics: latency, token/cache usage when provided,
tool-failure counts, completion/budget outcome, context schema version and baseline
availability. SDK log propagation and OpenTelemetry export are disabled in the
runtime to avoid exporting evidence, reports or tool payloads. No new AWS telemetry
permissions or tracing backend required. Do not enable Bedrock invocation-body
logging for this demo.

AgentCore Memory remains intentionally unused: there is no authenticated
human-decision ingestion path. Add it when approved triage decisions need semantic
retrieval; namespace by tenant/asset, retain provenance and expiry, and never use
model-extracted memories as authoritative scan baselines or action permissions.

## Local demo

Docker Compose and Python 3 required. Commands assume clone at
`/workspaces/project/vibe-ops-ibm-tuke`.

```bash
cd /workspaces/project/vibe-ops-ibm-tuke
sh /workspaces/project/vibe-ops-ibm-tuke/certs/make-certs.sh
docker compose up -d server mitmproxy
python3 /workspaces/project/vibe-ops-ibm-tuke/tools/traffic.py -n 5
```

| Address | Role |
| --- | --- |
| http://localhost:8082 | Demo portal over HTTP |
| https://localhost:8083 | Demo portal over HTTPS; proxy certificate warning expected |
| http://localhost:8081/?token=demo | mitmweb traffic inspection |

Use synthetic credentials only, e.g. `student` / `demo-password`. The portal
accepts any non-empty credentials. Do not expose this intentionally insecure demo
publicly. Raw HAR contains credentials; never upload it or raw ZAP reports.

Keep `EXPORT_EVENTS=0` (default); legacy per-exchange export is not needed.
Stop with `docker compose down`.

### Capture and offline ZAP scan

Run on a Docker-capable host; Dev Container has no Docker socket. Local conversion
also requires jq 1.6+ and `sha256sum` (GNU coreutils). After generating traffic above:

```bash
cd /workspaces/project/vibe-ops-ibm-tuke
umask 077
mkdir -p /workspaces/project/vibe-ops-ibm-tuke/zap/private
chmod 700 /workspaces/project/vibe-ops-ibm-tuke/zap/private
export ZAP_UID=$(id -u) ZAP_GID=$(id -g)
# Native HAR export writes on graceful exit; do not use docker kill.
docker compose stop -t 30 mitmproxy
docker compose cp mitmproxy:/home/mitmproxy/traffic.har /workspaces/project/vibe-ops-ibm-tuke/zap/private/traffic.har
chmod 600 /workspaces/project/vibe-ops-ibm-tuke/zap/private/traffic.har
# Prevent stale report reuse if this scan fails.
rm -f /workspaces/project/vibe-ops-ibm-tuke/zap/private/report.json
docker compose --profile zap run --rm zap
# Run only after ZAP exits successfully.
sh /workspaces/project/vibe-ops-ibm-tuke/zap/export.sh
```

ZAP 2.17.0 imports HAR without replay, crawling or active scanning. Its container
has no network or AWS credentials; local scan/conversion makes no cloud/model calls.
Raw HAR and ZAP reports contain secrets: never upload them to an LLM, cloud storage,
issue tracker or Git. Keep captures short (HAR accumulates in memory until exit),
delete raw files after review, and restart mitmproxy before capturing again.

Only sanitized `zap/private/event.json` may be published. It contains numeric rule
IDs, risk/confidence/counts, asset ID, timestamp, SHA-256 event ID and optional
baseline, not URLs, headers, bodies or matched evidence. Agents cannot infer affected
endpoints, HTTP/HTTPS exposure or comparable coverage from it. Empty findings do not
prove safety; require successful ZAP exit and local review. ZAP detects weaknesses,
not arbitrary secret leaks or malicious MITM attribution.

## AWS deployment

### Prerequisites

- Terraform >= 1.5, Python 3.12, AWS CLI, Docker with ARM64 buildx support.
- AWS deployment credentials with service-creation, IAM role-passing, and `bedrock:GetInferenceProfile` permissions.
- AgentCore Runtime and Bedrock model access in selected region; default `eu-central-1` with Claude Sonnet 4 EU inference profile.
- Existing IAM user/role for publishing, allowed to assume stack's publisher role.

Use a dedicated demo account. Terraform owns regional Security Hub CSPM enrollment;
destroying this stack disables it, including imported enrollment. AWS charges apply.

### Deploy with Terraform

1. Create `/workspaces/project/vibe-ops-ibm-tuke/aws/terraform/demo.tfvars` (ignored by Git). Replace publisher ARN:

   ```hcl
   region                  = "eu-central-1"
   publisher_principal_arn = "arn:aws:iam::123456789012:role/YourExistingLabRole"
   analysis_mode           = "single" # single, orchestrator, graph
   ```

2. Package Lambda and initialize Terraform:

   ```bash
   sh /workspaces/project/vibe-ops-ibm-tuke/aws/scripts/package.sh
   terraform -chdir=/workspaces/project/vibe-ops-ibm-tuke/aws/terraform init
   terraform -chdir=/workspaces/project/vibe-ops-ibm-tuke/aws/terraform validate
   ```

   If Security Hub is already enabled, import it before applying:

   ```bash
   terraform -chdir=/workspaces/project/vibe-ops-ibm-tuke/aws/terraform import \
     -var-file=demo.tfvars aws_securityhub_account.demo \
     "$(aws sts get-caller-identity --query Account --output text)"
   ```

3. Bootstrap resources, including ECR. Review Terraform's plan before confirming:

   ```bash
   terraform -chdir=/workspaces/project/vibe-ops-ibm-tuke/aws/terraform apply -var-file=demo.tfvars
   ```

4. Build and push runtime image using deployment credentials. Match region to `demo.tfvars`; use a new tag for each build:

   ```bash
   export AWS_REGION=eu-central-1
   REPO=$(terraform -chdir=/workspaces/project/vibe-ops-ibm-tuke/aws/terraform output -raw ecr_repository_url)
   REGISTRY=${REPO%%/*}
   TAG=demo-v1
   aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$REGISTRY"
   docker buildx build --platform linux/arm64 --provenance=false \
     -f /workspaces/project/vibe-ops-ibm-tuke/aws/agentcore_runtime/Dockerfile \
     -t "$REPO:$TAG" --push /workspaces/project/vibe-ops-ibm-tuke/aws
   DIGEST=$(aws ecr describe-images --region "$AWS_REGION" \
     --repository-name "${REPO#*/}" --image-ids "imageTag=$TAG" \
     --query 'imageDetails[0].imageDigest' --output text)
   printf 'image_uri = "%s@%s"\n' "$REPO" "$DIGEST"
   ```

5. Add printed `image_uri` line to `demo.tfvars`, then deploy runtime and pipeline:

   ```bash
   terraform -chdir=/workspaces/project/vibe-ops-ibm-tuke/aws/terraform apply -var-file=demo.tfvars
   terraform -chdir=/workspaces/project/vibe-ops-ibm-tuke/aws/terraform output
   ```

   Keep `image_uri` in `demo.tfvars`; removing it destroys runtime and stream consumer.
   For updates, repackage Lambda, push a new image tag, and replace saved digest before applying.

### Use

After [capture and conversion](#capture-and-offline-zap-scan) succeeds, configure
host AWS CLI profile `sniff-publisher` to assume Terraform's `publisher_role_arn`.
Set `KINESIS_STREAM_NAME` to output `stream_name` and `AWS_REGION` to deployment region:

```bash
aws kinesis put-record \
  --stream-name "${KINESIS_STREAM_NAME:?set KINESIS_STREAM_NAME}" \
  --partition-key demo-portal \
  --data fileb:///workspaces/project/vibe-ops-ibm-tuke/zap/private/event.json \
  --region "${AWS_REGION:?set AWS_REGION}" \
  --profile sniff-publisher --no-cli-pager
```

Publish sanitized events only; never HAR or raw ZAP reports. Success returns shard/
sequence IDs, not completed analysis. On failure, retry the same saved event to retain
its ID for deduplication. Review recommendations in **Security Hub CSPM → Findings**
using output `security_hub_console_url`; full reports stay in `results_bucket` S3 bucket.
Security reviews recommendations; engineers apply fixes and recapture. Missing alerts
do not auto-close findings, and agents do not perform autonomous remediation.

### Baselines

Scan analysis shares seven-day S3 context across executions. Without an embedded
baseline, each scan pins the latest accepted earlier scan for its demo asset.
Retries retain pinned context; only validated, saved analyses advance latest context.
All agents receive one precomputed comparison; absent alerts never prove resolution.
Saved results retain original evidence, pinned context and deterministic deltas.
Automatic baselines assume one demo scan scope per asset, not verified comparability.

For an explicit baseline, save sanitized `event.json` before the next capture:

```bash
cp /workspaces/project/vibe-ops-ibm-tuke/zap/private/event.json /workspaces/project/vibe-ops-ibm-tuke/zap/private/baseline.json
```

After a fresh capture and successful ZAP run, convert with the saved baseline, then
publish the new `event.json` using the command above. Explicit baselines take precedence:

```bash
sh /workspaces/project/vibe-ops-ibm-tuke/zap/export.sh \
  /workspaces/project/vibe-ops-ibm-tuke/zap/private/baseline.json
```

### Cleanup

Export any needed results, then explicitly empty the results bucket and ECR repository.
The stack refuses to delete them while nonempty. Keep Terraform state until cleanup succeeds.

```bash
terraform -chdir=/workspaces/project/vibe-ops-ibm-tuke/aws/terraform destroy -var-file=demo.tfvars
```
