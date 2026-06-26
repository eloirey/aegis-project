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

variable "project_name" {
  type    = string
  default = "aegis-project"
}

# Detection owns the topic; remediation only subscribes to it
data "aws_sns_topic" "findings" {
  name = "${var.project_name}-findings"
}

data "archive_file" "remediate_zip" {
  type        = "zip"
  source_file = "${path.module}/remediate_handler.py"
  output_path = "${path.module}/remediate_handler.zip"
}

resource "aws_iam_role" "remediate" {
  name = "${var.project_name}-01-remediate-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "remediate_logs" {
  role       = aws_iam_role.remediate.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "remediate_s3" {
  name = "${var.project_name}-01-remediate-s3"
  role = aws_iam_role.remediate.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:PutBucketPublicAccessBlock",
        "s3:DeleteBucketPolicy",
      ]
      Resource = "arn:aws:s3:::${var.project_name}-lab-*"
    }]
  })
}

resource "aws_lambda_function" "remediate" {
  function_name    = "${var.project_name}-01-remediate"
  role             = aws_iam_role.remediate.arn
  handler          = "remediate_handler.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.remediate_zip.output_path
  source_code_hash = data.archive_file.remediate_zip.output_base64sha256
}

resource "aws_sns_topic_subscription" "remediate" {
  topic_arn = data.aws_sns_topic.findings.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.remediate.arn
}

resource "aws_lambda_permission" "allow_sns" {
  statement_id  = "AllowSNSInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediate.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = data.aws_sns_topic.findings.arn
}