output "lowpriv_user_name" {
  description = "Name of the escalatable lab identity (target of the attack)"
  value       = aws_iam_user.lowpriv.name
}

output "lowpriv_access_key_id" {
  description = "Access key id the attack script uses to authenticate"
  value       = aws_iam_access_key.lowpriv.id
}

output "lowpriv_secret_access_key" {
  description = "Secret key for the attack. Read with: terraform output -raw lowpriv_secret_access_key"
  value       = aws_iam_access_key.lowpriv.secret
  sensitive   = true
}
