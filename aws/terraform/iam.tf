resource "aws_iam_role" "publisher" {
  name = "${var.name}-publisher"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Action = "sts:AssumeRole", Principal = { AWS = var.publisher_principal_arn }
  }] })
}

resource "aws_iam_role_policy" "publisher" {
  role = aws_iam_role.publisher.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Action = ["kinesis:PutRecord"], Resource = aws_kinesis_stream.events.arn
  }] })
}

resource "aws_iam_role" "agent" {
  name = "${var.name}-agent"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect    = "Allow", Action = "sts:AssumeRole",
    Principal = { Service = "bedrock-agentcore.amazonaws.com" },
    Condition = {
      StringEquals = { "aws:SourceAccount" = local.account },
      ArnLike      = { "aws:SourceArn" = "${local.prefix}:bedrock-agentcore:${var.region}:${local.account}:*" }
    }
  }] })
}

resource "aws_iam_role_policy" "agent" {
  role = aws_iam_role.agent.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = "*" },
    { Effect = "Allow", Action = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"], Resource = aws_ecr_repository.agent.arn },
    { Effect = "Allow", Action = ["bedrock:InvokeModel"], Resource = concat(
      [data.aws_bedrock_inference_profile.analysis.inference_profile_arn],
      [for model in data.aws_bedrock_inference_profile.analysis.models : model.model_arn]
    ) },
    { Effect = "Allow", Action = ["bedrock:ApplyGuardrail"], Resource = try([aws_bedrock_guardrail.analysis[0].guardrail_arn], []) },
    { Effect = "Allow", Action = ["logs:CreateLogGroup", "logs:DescribeLogStreams", "logs:CreateLogStream", "logs:PutLogEvents"],
    Resource = "${local.prefix}:logs:${var.region}:${local.account}:log-group:/aws/bedrock-agentcore/runtimes/*" },
    { Effect = "Allow", Action = ["logs:DescribeLogGroups"], Resource = "${local.prefix}:logs:${var.region}:${local.account}:log-group:*" }
  ] })
}

resource "aws_iam_role" "pipeline" {
  for_each = local.pipeline_tasks
  name     = "${var.name}-${each.key}"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "lambda.amazonaws.com" }
  }] })
}

locals {
  pipeline_permissions = {
    start-analysis = [
      { Effect = "Allow", Action = ["kinesis:DescribeStream", "kinesis:DescribeStreamSummary", "kinesis:GetRecords", "kinesis:GetShardIterator", "kinesis:ListShards"], Resource = aws_kinesis_stream.events.arn },
      { Effect = "Allow", Action = ["states:StartExecution"], Resource = "${local.prefix}:states:${var.region}:${local.account}:stateMachine:${var.name}-security-analysis" },
      { Effect = "Allow", Action = ["s3:PutObject"], Resource = "${aws_s3_bucket.results.arn}/aws/lambda/*" },
      { Effect = "Allow", Action = ["s3:ListBucket", "s3:GetBucketLocation"], Resource = aws_s3_bucket.results.arn }
    ]
    analyze-and-store = [
      { Effect = "Allow", Action = ["bedrock-agentcore:InvokeAgentRuntime"], Resource = try([aws_bedrockagentcore_agent_runtime.analysis[0].agent_runtime_arn, "${aws_bedrockagentcore_agent_runtime.analysis[0].agent_runtime_arn}/runtime-endpoint/*"], []) },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = ["${aws_s3_bucket.results.arn}/results/*", "${aws_s3_bucket.results.arn}/context/v1/*"] },
      # GetObject needs ListBucket to distinguish missing objects (404) from denied reads (403).
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = aws_s3_bucket.results.arn }
    ]
    publish-findings = [
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.results.arn}/results/*" }
    ]
  }
}

resource "aws_iam_role_policy" "pipeline" {
  for_each = local.pipeline_tasks
  role     = aws_iam_role.pipeline[each.key].id
  policy = jsonencode({ Version = "2012-10-17", Statement = concat(local.pipeline_permissions[each.key], [
    { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.pipeline[each.key].arn}:*" }
  ]) })
}

resource "aws_iam_role" "workflow" {
  count = local.enabled ? 1 : 0
  name  = "${var.name}-security-analysis"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "states.amazonaws.com" },
    Condition = {
      StringEquals = { "aws:SourceAccount" = local.account },
      ArnEquals    = { "aws:SourceArn" = "${local.prefix}:states:${var.region}:${local.account}:stateMachine:${var.name}-security-analysis" }
    }
  }] })
}

resource "aws_iam_role_policy" "workflow" {
  count = local.enabled ? 1 : 0
  role  = aws_iam_role.workflow[0].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect   = "Allow", Action = ["lambda:InvokeFunction"],
    Resource = [aws_lambda_function.pipeline["analyze-and-store"].arn, aws_lambda_function.pipeline["publish-findings"].arn]
    }, {
    Effect   = "Allow", Action = ["securityhub:BatchImportFindings"],
    Resource = "${local.prefix}:securityhub:${var.region}:${local.account}:product/${local.account}/default"
  }] })
}
