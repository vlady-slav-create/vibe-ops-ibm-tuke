data "aws_caller_identity" "current" {}

data "aws_iam_session_context" "publisher" {
  count = var.publisher_principal_arn == null ? 1 : 0
  arn   = data.aws_caller_identity.current.arn
}

data "aws_partition" "current" {}

locals {
  enabled                 = true
  prefix                  = "arn:${data.aws_partition.current.partition}"
  account                 = data.aws_caller_identity.current.account_id
  publisher_principal_arn = var.publisher_principal_arn != null ? var.publisher_principal_arn : data.aws_iam_session_context.publisher[0].issuer_arn
}
