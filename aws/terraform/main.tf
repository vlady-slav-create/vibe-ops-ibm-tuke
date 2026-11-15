data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  enabled = var.image_uri != ""
  prefix  = "arn:${data.aws_partition.current.partition}"
  account = data.aws_caller_identity.current.account_id
}
