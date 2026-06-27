terraform {
  required_version = ">= 1.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# EC2 is regional: its CloudTrail events land in the lab region, so unlike the IAM
# scenario this whole pipeline stays in eu-west-1.
provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "project_name" {
  type    = string
  default = "aegis-project"
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
  name = "${var.project_name}-03-detect-role"
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
  name = "${var.project_name}-03-detect-publish"
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
  function_name    = "${var.project_name}-03-detect"
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

resource "aws_cloudwatch_event_rule" "exposed_ssh" {
  name = "${var.project_name}-03-exposed-ssh"
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["AuthorizeSecurityGroupIngress"]
    }
  })
}

resource "aws_cloudwatch_event_target" "detect" {
  rule = aws_cloudwatch_event_rule.exposed_ssh.name
  arn  = aws_lambda_function.detect.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detect.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.exposed_ssh.arn
}
