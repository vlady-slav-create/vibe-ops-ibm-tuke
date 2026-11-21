data "aws_bedrock_inference_profile" "analysis" {
  inference_profile_id = var.model_id
}

# Marketplace subscription for the model, done by the applying identity (needs
# aws-marketplace:ViewSubscriptions/Subscribe), not the runtime role.
# ponytail: first model of the profile; all models in a profile share one provider offer.
locals {
  foundation_model_id = element(split("/", data.aws_bedrock_inference_profile.analysis.models[0].model_arn), 1)
}

data "aws_bedrock_foundation_model_agreement_offers" "analysis" {
  model_id   = local.foundation_model_id
  offer_type = "PUBLIC"
}

resource "aws_bedrock_foundation_model_agreement" "analysis" {
  model_id    = local.foundation_model_id
  offer_token = data.aws_bedrock_foundation_model_agreement_offers.analysis.offers[0].offer_token
  lifecycle {
    ignore_changes = [offer_token]
  }
}

resource "aws_ecr_repository" "agent" {
  name                 = "${var.name}-agent"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
}

locals {
  runtime_sources = concat(
    ["requirements.txt", ".dockerignore", "scripts/build_image.py"],
    [for file in fileset("${path.module}/../agentcore_runtime", "**") : "agentcore_runtime/${file}" if !strcontains(file, "__pycache__/") && !endswith(file, ".pyc")],
    [for file in fileset("${path.module}/../contracts", "**") : "contracts/${file}" if !strcontains(file, "__pycache__/") && !endswith(file, ".pyc")]
  )
  runtime_tag = sha256(jsonencode({ for file in local.runtime_sources : file => filesha256("${path.module}/../${file}") }))
}

resource "terraform_data" "runtime_image" {
  count            = var.image_uri == "" ? 1 : 0
  triggers_replace = [local.runtime_tag, aws_ecr_repository.agent.repository_url]
  provisioner "local-exec" {
    command = "python3 \"${abspath(path.module)}/../scripts/build_image.py\""
    environment = {
      ECR_REPOSITORY_URL = aws_ecr_repository.agent.repository_url
      IMAGE_TAG          = local.runtime_tag
      AWS_REGION         = var.region
    }
  }
}

data "aws_ecr_image" "runtime" {
  count           = var.image_uri == "" ? 1 : 0
  repository_name = aws_ecr_repository.agent.name
  image_tag       = local.runtime_tag
  depends_on      = [terraform_data.runtime_image]
}

resource "aws_bedrock_guardrail" "analysis" {
  count                     = local.enabled ? 1 : 0
  name                      = "${var.name}-analysis"
  blocked_input_messaging   = "Input blocked by guardrail."
  blocked_outputs_messaging = "Output blocked by guardrail."
  content_policy_config {
    filters_config {
      input_strength  = "HIGH"
      output_strength = "NONE"
      type            = "PROMPT_ATTACK"
    }
  }
}

resource "aws_bedrockagentcore_agent_runtime" "analysis" {
  count              = local.enabled ? 1 : 0
  agent_runtime_name = replace("${var.name}_analysis", "-", "_")
  role_arn           = aws_iam_role.agent.arn
  agent_runtime_artifact {
    container_configuration {
      container_uri = var.image_uri != "" ? var.image_uri : "${aws_ecr_repository.agent.repository_url}@${data.aws_ecr_image.runtime[0].image_digest}"
    }
  }
  network_configuration {
    network_mode = "PUBLIC"
  }
  protocol_configuration {
    server_protocol = "HTTP"
  }
  environment_variables = {
    MODEL_ID             = data.aws_bedrock_inference_profile.analysis.inference_profile_id
    GUARDRAIL_ID         = aws_bedrock_guardrail.analysis[0].guardrail_id
    GUARDRAIL_VERSION    = aws_bedrock_guardrail.analysis[0].version
    PROMPT_CACHE_ENABLED = tostring(var.prompt_cache_enabled)
  }
  lifecycle_configuration {
    idle_runtime_session_timeout = 60
    max_lifetime                 = 600
  }
  depends_on = [aws_iam_role_policy.agent, aws_bedrock_foundation_model_agreement.analysis]
}
