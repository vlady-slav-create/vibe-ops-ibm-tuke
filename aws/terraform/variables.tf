variable "region" {
  type    = string
  default = "eu-central-1"
}

variable "name" {
  type    = string
  default = "sniff-lab"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,24}$", var.name))
    error_message = "Use 3..25 lowercase letters, digits or hyphens, starting with a letter."
  }
}

variable "model_id" {
  type        = string
  default     = "eu.anthropic.claude-sonnet-4-6"
  description = "Bedrock Converse inference profile ID. Demo defaults to Claude Sonnet 4.6 EU; Terraform resolves profile and destination model ARNs for IAM."
  validation {
    condition     = length(trimspace(var.model_id)) > 0 && !strcontains(var.model_id, "*")
    error_message = "Provide a nonempty inference profile ID without wildcards."
  }
}

variable "image_uri" {
  type        = string
  default     = ""
  description = "Optional prebuilt ARM64 image URI. Empty builds and pushes the runtime image automatically during apply."
}

variable "prompt_cache_enabled" {
  type        = bool
  default     = true
  description = "Cache static system prefixes on supported Bedrock models; disable for unsupported models. No evidence/message cache checkpoints."
}

variable "publisher_principal_arn" {
  type        = string
  default     = null
  description = "Optional trusted IAM user/role override. Defaults to the authenticated Terraform user's ARN or underlying IAM role (including SSO)."
  validation {
    condition     = var.publisher_principal_arn == null || can(regex("^arn:[^:]+:iam::[0-9]{12}:(user|role)/.+$", var.publisher_principal_arn))
    error_message = "Use an IAM user or role ARN, not an STS session or account root ARN."
  }
}
