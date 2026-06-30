terraform {
  required_version = ">= 1.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# IAM is a global service: its CloudTrail management events are delivered to
# EventBridge in us-east-1, not in the lab's eu-west-1 region. The whole
# reactive pipeline for this scenario (rule, detector, findings topic, and the
# remediation that subscribes to it) therefore lives in us-east-1. The core
# multi-region trail is what makes those global events available to capture.
provider "aws" {
  region = var.event_region
}

variable "event_region" {
  description = "Region where global-service (IAM) CloudTrail events are delivered"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix used to name resources"
  type        = string
  default     = "aegis-project"
}

data "aws_caller_identity" "current" {}

# Resolve the compliance mapping at deploy time and inject it as Lambda config, so the
# function enriches findings without parsing YAML at runtime. Note the alerts topic and the
# findings table both live in eu-west-1 even though this stack runs in us-east-1 — the
# notifier and the store reach them cross-region (region taken from config, not the runtime).
locals {
  mapping = yamldecode(file("${path.module}/../mapping.yaml"))
  enrichment = jsonencode({
    severity     = local.mapping.severity
    mitre_attack = local.mapping.mitre_attack
    controls = {
      ens     = [for c in local.mapping.compliance.ens : c.id]
      nis2    = [for c in local.mapping.compliance.nis2 : c.id]
      cis_aws = [for c in local.mapping.compliance.cis_aws : c.id]
    }
  })
  alert_topic_arn    = "arn:aws:sns:eu-west-1:${data.aws_caller_identity.current.account_id}:${var.project_name}-alerts"
  findings_table_arn = "arn:aws:dynamodb:eu-west-1:${data.aws_caller_identity.current.account_id}:table/${var.project_name}-findings"
}

# Package the handler together with the shared engine (notifier + store - no YAML at runtime).
# file() pulls the real engine modules straight from the repo, so nothing is duplicated.
data "archive_file" "detect_zip" {
  type        = "zip"
  output_path = "${path.module}/detect_handler.zip"

  source {
    content  = file("${path.module}/detect_handler.py")
    filename = "detect_handler.py"
  }
  source {
    content  = file("${path.module}/../../../engine/__init__.py")
    filename = "engine/__init__.py"
  }
  source {
    content  = file("${path.module}/../../../engine/notifier/__init__.py")
    filename = "engine/notifier/__init__.py"
  }
  source {
    content  = file("${path.module}/../../../engine/notifier/notify.py")
    filename = "engine/notifier/notify.py"
  }
  source {
    content  = file("${path.module}/../../../engine/store/__init__.py")
    filename = "engine/store/__init__.py"
  }
  source {
    content  = file("${path.module}/../../../engine/store/findings.py")
    filename = "engine/store/findings.py"
  }
}

resource "aws_sns_topic" "findings" {
  name = "${var.project_name}-findings"
}

resource "aws_iam_role" "detect" {
  name = "${var.project_name}-02-detect-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "detect_logs" {
  role       = aws_iam_role.detect.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "detect_publish" {
  name = "${var.project_name}-02-detect-publish"
  role = aws_iam_role.detect.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sns:Publish"
      Resource = [aws_sns_topic.findings.arn, local.alert_topic_arn]
    }]
  })
}

resource "aws_iam_role_policy" "detect_persist" {
  name = "${var.project_name}-02-detect-persist"
  role = aws_iam_role.detect.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "dynamodb:PutItem"
      Resource = local.findings_table_arn
    }]
  })
}

resource "aws_lambda_function" "detect" {
  function_name    = "${var.project_name}-02-detect"
  role             = aws_iam_role.detect.arn
  handler          = "detect_handler.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.detect_zip.output_path
  source_code_hash = data.archive_file.detect_zip.output_base64sha256

  environment {
    variables = {
      FINDINGS_TOPIC_ARN    = aws_sns_topic.findings.arn
      ALERT_TOPIC_ARN       = local.alert_topic_arn
      ENRICHMENT            = local.enrichment
      FINDINGS_TABLE        = "${var.project_name}-findings"
      FINDINGS_TABLE_REGION = "eu-west-1"
    }
  }
}

# AttachUserPolicy/AttachRolePolicy carry a managed policyArn; PutUserPolicy/
# PutRolePolicy carry an inline document. The handler decides which are
# admin-equivalent — the rule just funnels all four event names to it.
resource "aws_cloudwatch_event_rule" "iam_privileged" {
  name = "${var.project_name}-02-iam-privileged"
  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName   = ["AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy"]
    }
  })
}

resource "aws_cloudwatch_event_target" "detect" {
  rule = aws_cloudwatch_event_rule.iam_privileged.name
  arn  = aws_lambda_function.detect.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detect.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_privileged.arn
}