variable "region" {
  description = "AWS region for the lab"
  type        = string
  default     = "eu-west-1"
}

variable "project_name" {
  description = "Prefix used to name resources"
  type        = string
  default     = "aegis-project"
}

# No default: keeps the address out of the public repo and forces it at apply time.
variable "alert_email" {
  description = "Email subscribed to security alerts"
  type        = string
}