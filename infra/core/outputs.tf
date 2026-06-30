output "alert_topic_arn" {
  description = "SNS topic ARN scenarios publish alerts to"
  value       = aws_sns_topic.alerts.arn
}

output "trail_logs_bucket" {
  description = "Bucket storing CloudTrail logs"
  value       = aws_s3_bucket.trail_logs.id
}

output "findings_table_name" {
  description = "DynamoDB table tracking the finding lifecycle for the live dashboard"
  value       = aws_dynamodb_table.findings.name
}

output "findings_table_arn" {
  description = "ARN scenario Lambdas grant themselves PutItem/UpdateItem on"
  value       = aws_dynamodb_table.findings.arn
}