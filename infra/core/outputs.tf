output "alert_topic_arn" {
  description = "SNS topic ARN scenarios publish alerts to"
  value       = aws_sns_topic.alerts.arn
}

output "trail_logs_bucket" {
  description = "Bucket storing CloudTrail logs"
  value       = aws_s3_bucket.trail_logs.id
}