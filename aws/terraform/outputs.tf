output "stream_name" {
  value = aws_kinesis_stream.events.name
}

output "security_hub_console_url" {
  value = "https://${var.region}.console.aws.amazon.com/securityhub/home?region=${var.region}#/findings"
}

output "ecr_repository_url" {
  value = aws_ecr_repository.agent.repository_url
}

output "results_bucket" {
  value = aws_s3_bucket.results.id
}

output "publisher_role_arn" {
  value = aws_iam_role.publisher.arn
}

output "runtime_arn" {
  value = try(aws_bedrockagentcore_agent_runtime.analysis[0].agent_runtime_arn, null)
}

output "workflow_arn" {
  value = try(aws_sfn_state_machine.analysis[0].arn, null)
}

output "pipeline_lambda_names" {
  value = { for task, function in aws_lambda_function.pipeline : task => function.function_name }
}
