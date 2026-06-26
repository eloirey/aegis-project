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

data "archive_file" "detect_zip" {
  type        = "zip"
  source_file = "${path.module}/detect_handler.py"
  output_path = "${path.module}/detect_handler.zip"
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
      Resource = aws_sns_topic.findings.arn
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
      FINDINGS_TOPIC_ARN = aws_sns_topic.findings.arn
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
