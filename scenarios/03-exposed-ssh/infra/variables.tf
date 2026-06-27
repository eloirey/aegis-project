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

variable "instance_type" {
  description = "Free Tier eligible instance type"
  type        = string
  default     = "t3.micro"
}
