output "security_group_id" {
  description = "Security group the attack opens to the internet"
  value       = aws_security_group.ssh.id
}

output "instance_public_ip" {
  description = "Public IP the attack tests for SSH reachability"
  value       = aws_instance.target.public_ip
}

output "instance_id" {
  description = "EC2 instance id of the lab SSH host"
  value       = aws_instance.target.id
}
