/**
 * # Terraform AWS CloudTrail Alerts Module
 *
 * A module that create CloudWatch metric filters and alarms required for most modern compliance reports. This
 * module includes the necessary metric filters and alarms for the following compliance reports:
 *
 * | Compliance Report | Sections |
 * |---|---|
 * | CIS AWS Foundations Benchmark v1.5.0 | Section 4.1 - 4.15 |
 * | NIST 800-171 v2 | Section 3.12.3 |
 * | ISO/IEC 27001 v2 | Section A.12.4.1 |
 * | PCI DSS v3.2.1 | Section 10.1 |
 * | SOC 2 v2 | Section 5.2 |
 *
 * This module can also create an SNS topic with a Slack channel configuration for AWS Chatbot (must be configured)
 * manually in the AWS Console.
 */
data "aws_caller_identity" "current" {}

data "aws_cloudwatch_log_group" "cloudtrail" {
  name = var.cloudtrail_log_group_name
}

resource "aws_cloudwatch_log_metric_filter" "main" {
  for_each = { for rule in local.alerts : rule.name => rule }

  name           = each.value.name
  pattern        = each.value.pattern
  log_group_name = data.aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "${each.value.name}Count"
    namespace = var.cloudwatch_namespace
    value     = 1
  }
}

resource "aws_cloudwatch_metric_alarm" "main" {
  for_each = { for rule in local.alerts : rule.name => rule }

  alarm_name  = "${each.value.name}Alarm"
  metric_name = "${each.value.name}Count"
  namespace   = var.cloudwatch_namespace

  evaluation_periods  = each.value.evaluation_periods
  threshold           = each.value.threshold
  period              = each.value.period
  comparison_operator = each.value.comparison_operator
  statistic           = each.value.statistic
  alarm_description   = each.value.description

  alarm_actions      = [coalesce(var.sns_topic_arn, aws_sns_topic.main[0].arn)]
  treat_missing_data = "notBreaching"

  tags = var.tags
}

## KMS
resource "aws_kms_key" "main" {
  count = var.sns_kms_master_key_id == null ? 1 : 0

  description             = "KMS key for CloudTrail alerts SNS topic."
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.kms[0].json

  tags = var.tags
}

resource "aws_kms_alias" "main" {
  count = var.sns_kms_master_key_id == null ? 1 : 0

  target_key_id = aws_kms_key.main[0].id
  name          = var.sns_kms_master_key_alias
}

data "aws_iam_policy_document" "kms" {
  count = var.sns_kms_master_key_id == null ? 1 : 0

  statement {
    sid       = "IAMUserAdministration"
    resources = ["*"]
    actions   = ["kms:*"]

    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
      ]
    }
  }

  statement {
    sid       = "CloudwatchUsage"
    resources = ["*"]
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey*"
    ]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
  }
}

## SNS
resource "aws_sns_topic" "main" {
  count = var.sns_topic_arn == null ? 1 : 0

  name              = "${var.prefix}-cloudtrail-alerts"
  kms_master_key_id = coalesce(var.sns_kms_master_key_id, aws_kms_key.main[0].arn)

  tags = var.tags
}

## CHATBOT
resource "awscc_chatbot_slack_channel_configuration" "main" {
  count = var.slack_channel_id != null && var.slack_workspace_id != null ? 1 : 0

  configuration_name = "${var.prefix}-cloudtrail-alerts"

  slack_channel_id   = var.slack_channel_id
  slack_workspace_id = var.slack_workspace_id

  sns_topic_arns = [coalesce(var.sns_topic_arn, aws_sns_topic.main[0].arn)]
  iam_role_arn   = module.chatbot_role[0].arn
}

module "chatbot_role" {
  count = var.slack_channel_id != null && var.slack_workspace_id != null ? 1 : 0

  source = "github.com/geekcell/terraform-aws-iam-role?ref=v1"

  name        = "${var.prefix}-chatbot-cloudtrail-alerts"
  description = "Role for AWS Chatbot to read CloudWatch alerts."
  policy_arns = ["arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"]
  assume_roles = {
    "Service" : {
      identifiers = ["chatbot.amazonaws.com"]
    }
  }

  tags = var.tags
}
