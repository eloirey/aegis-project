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