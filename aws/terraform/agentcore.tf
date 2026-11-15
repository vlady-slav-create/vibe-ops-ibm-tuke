data "aws_bedrock_inference_profile" "analysis" {
  inference_profile_id = var.model_id
}

resource "aws_ecr_repository" "agent" {
  name                 = "${var.name}-agent"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_bedrock_guardrail" "analysis" {
  count                     = local.enabled ? 1 : 0
  name                      = "${var.name}-analysis"
  blocked_input_messaging   = "Input blocked by guardrail."
  blocked_outputs_messaging = "Output blocked by guardrail."
  content_policy_config {
    filters_config {
      input_strength  = "HIGH"
      output_strength = "HIGH"
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
      container_uri = var.image_uri
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
  depends_on = [aws_iam_role_policy.agent]
}
