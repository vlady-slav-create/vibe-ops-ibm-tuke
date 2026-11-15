resource "aws_sfn_state_machine" "analysis" {
  count    = local.enabled ? 1 : 0
  name     = "${var.name}-security-analysis"
  role_arn = aws_iam_role.workflow[0].arn
  type     = "STANDARD"
  definition = templatefile("${path.module}/workflow/analysis.asl.json", {
    analyze_and_store_arn = aws_lambda_function.pipeline["analyze-and-store"].arn
    publish_findings_arn  = aws_lambda_function.pipeline["publish-findings"].arn
    partition             = data.aws_partition.current.partition
  })
  depends_on = [aws_iam_role_policy.workflow]
}
