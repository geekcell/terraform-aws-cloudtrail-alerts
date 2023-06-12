# Context
variable "prefix" {
  description = "Prefix that will added to created resources."
  type        = string
}

variable "tags" {
  default     = {}
  description = "Tags to add to the created resources."
  type        = map(any)
}

# SNS
variable "sns_topic_arn" {
  description = "Use an existing SNS topic to send alerts to."
  default     = null
  type        = string
}

variable "sns_kms_master_key_id" {
  description = "The ARN of the KMS key to use to encrypt the SNS topic. Will create a new CMK if not provided."
  default     = null
  type        = string
}

variable "sns_kms_master_key_alias" {
  description = "The alias of the KMS key to use to encrypt the SNS topic if no key is provided."
  default     = "sns/cloudtrail-alerts"
  type        = string
}

# CloudWatch
variable "cloudtrail_log_group_name" {
  description = "The name of the CloudWatch log group to filter for events. Defaults to the AWS Control Tower created Baseline."
  default     = "aws-controltower/CloudTrailLogs"
  type        = string
}

variable "cloudwatch_namespace" {
  description = "The namespace to use for the CloudWatch metric filter."
  default     = "CISBenchmark"
  type        = string
}

# Slack
variable "slack_workspace_id" {
  description = "The ID of the Slack workspace to send alerts to."
  default     = null
  type        = string
}

variable "slack_channel_id" {
  description = "The ID of the Slack channel to send alerts to."
  default     = null
  type        = string
}
