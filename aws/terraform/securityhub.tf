# Demo stack owns regional Security Hub enrollment; import existing enrollment first.
resource "aws_securityhub_account" "demo" {
  enable_default_standards = false
}