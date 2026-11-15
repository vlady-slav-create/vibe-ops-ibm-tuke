locals {
  pipeline_tasks = local.enabled ? {
    start-analysis = {
      handler     = "start_analysis", timeout = 30,
      environment = { WORKFLOW_ARN = "${local.prefix}:states:${var.region}:${local.account}:stateMachine:${var.name}-security-analysis", ANALYSIS_MODE = var.analysis_mode }
    }
    analyze-and-store = {
      handler     = "analyze_and_store", timeout = 300,
      environment = { RUNTIME_ARN = aws_bedrockagentcore_agent_runtime.analysis[0].agent_runtime_arn, RESULTS_BUCKET = aws_s3_bucket.results.id }
    }
    publish-findings = {
      handler     = "publish_findings", timeout = 60,
      environment = { RESULTS_BUCKET = aws_s3_bucket.results.id, ACCOUNT_ID = local.account, AWS_PARTITION = data.aws_partition.current.partition }
    }
  } : {}
}

resource "aws_cloudwatch_log_group" "pipeline" {
  for_each          = local.pipeline_tasks
  name              = "/aws/lambda/${var.name}-${each.key}"
  retention_in_days = 7
}

resource "aws_lambda_function" "pipeline" {
  for_each         = local.pipeline_tasks
  function_name    = "${var.name}-${each.key}"
  role             = aws_iam_role.pipeline[each.key].arn
  runtime          = "python3.12"
  handler          = "lambda_functions.${each.value.handler}.handler"
  filename         = "${path.module}/../build/lambda_functions.zip"
  source_code_hash = filebase64sha256("${path.module}/../build/lambda_functions.zip")
  timeout          = each.value.timeout
  memory_size      = 256
  environment {
    variables = each.value.environment
  }
  depends_on = [aws_iam_role_policy.pipeline, aws_securityhub_account.demo, aws_cloudwatch_log_group.pipeline]
}

resource "aws_lambda_event_source_mapping" "events" {
  count                              = local.enabled ? 1 : 0
  event_source_arn                   = aws_kinesis_stream.events.arn
  function_name                      = aws_lambda_function.pipeline["start-analysis"].arn
  starting_position                  = "TRIM_HORIZON"
  batch_size                         = 1 # One complete scan; bounds structured model output for demo.
  maximum_batching_window_in_seconds = 5
  maximum_retry_attempts             = 2
  maximum_record_age_in_seconds      = 3600
  bisect_batch_on_function_error     = true
  destination_config {
    on_failure {
      destination_arn = aws_s3_bucket.results.arn
    }
  }
  depends_on = [aws_iam_role_policy.pipeline, aws_sfn_state_machine.analysis]
}
