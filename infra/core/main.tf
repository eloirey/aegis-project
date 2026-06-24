###############################################################################
# Aegis Project CORE backbone
#
# The shared, always-on plumbing every scenario depends on:
#   - CloudTrail (the source of truth for detection)
#   - EventBridge (routes events to detection Lambdas)
#   - SNS (the central alert channel)
#   - Log bucket (CloudTrail storage)
#
# SKELETON — implement the TODOs.
###############################################################################

terraform {
  required_version = ">= 1.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "alert_email" {
  description = "Email subscribed to the SNS alert topic"
  type        = string
}

# ---------------------------------------------------------------------------
# SNS alert topic
# ---------------------------------------------------------------------------
resource "aws_sns_topic" "alerts" {
  name = "aegis-project-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
  # After apply, confirm the subscription from your inbox.
}

# ---------------------------------------------------------------------------
# CloudTrail + log bucket
# ---------------------------------------------------------------------------
# TODO: Create an S3 bucket for CloudTrail logs (with Block Public Access ON — this one
#       must be secure!) and an aws_cloudtrail trail that records management events.
#       Enable log file validation. Consider sending events to EventBridge.

# ---------------------------------------------------------------------------
# EventBridge
# ---------------------------------------------------------------------------
# TODO: If you use a custom event bus, declare it here and export its name so scenarios
#       can attach their rules. (Starting on the 'default' bus is fine for v1.)

output "alert_topic_arn" {
  value       = aws_sns_topic.alerts.arn
  description = "SNS topic ARN scenarios publish alerts to"
}
