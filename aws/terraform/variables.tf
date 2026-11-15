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
  default     = "eu.anthropic.claude-sonnet-4-20250514-v1:0"
  description = "Bedrock Converse inference profile ID. Demo defaults to Claude Sonnet 4 EU; Terraform resolves profile and destination model ARNs for IAM."
  validation {
    condition     = length(trimspace(var.model_id)) > 0 && !strcontains(var.model_id, "*")
    error_message = "Provide a nonempty inference profile ID without wildcards."
  }
}

variable "image_uri" {
  type        = string
  default     = ""
  description = "ARM64 image in this stack's ECR repository; empty creates bootstrap resources only. Prefer immutable digest."
}

variable "analysis_mode" {
  type        = string
  default     = "single"
  description = "single: direct analysis with bounded structured output; orchestrator: model-selected specialist tools; graph: parallel reviews then summarizer."
  validation {
    condition     = contains(["single", "orchestrator", "graph"], var.analysis_mode)
    error_message = "Use single, orchestrator or graph."
  }
}

variable "prompt_cache_enabled" {
  type        = bool
  default     = true
  description = "Cache static system prefixes on supported Bedrock models; disable for unsupported models. No evidence/message cache checkpoints."
}

variable "publisher_principal_arn" {
  type        = string
  description = "Existing IAM user/role ARN allowed to assume publisher role; not an STS session ARN."
}
