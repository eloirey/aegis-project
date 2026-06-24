output "bucket_name" {
  description = "Name of the deliberately public bucket"
  value       = aws_s3_bucket.vulnerable.id
}

output "decoy_object_url" {
  description = "Public URL of the decoy object (used by the attack)"
  value       = "https://${aws_s3_bucket.vulnerable.id}.s3.${var.region}.amazonaws.com/${aws_s3_object.decoy.key}"
}