###############################################################################
# Scenario 01 — Vulnerable (public) S3 bucket
#
# ⚠️  This file DELIBERATELY creates an insecure resource for the lab.
#     Deploy ONLY in a dedicated sandbox account. Run `destroy` when done.
#
# This is a SKELETON. The TODOs are where you learn — fill them in yourself.
###############################################################################

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
  description = "AWS region for the lab"
  type        = string
  default     = "eu-west-1" # Ireland — close to Spain, full service coverage
}

variable "bucket_prefix" {
  description = "Prefix for the deliberately-public bucket name"
  type        = string
  default     = "aegis-project-lab-public"
}

# A random suffix keeps the bucket name globally unique.
resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "vulnerable" {
  bucket = "${var.bucket_prefix}-${random_id.suffix.hex}"

  # Tag clearly so you never confuse this with anything real.
  tags = {
    Project   = "aegis-project"
    Scenario  = "01-public-s3-bucket"
    Intent    = "INTENTIONALLY-VULNERABLE"
    ManagedBy = "terraform"
  }
}

# TODO: This is the heart of the misconfiguration. To make the bucket public you will
#       typically need to (a) DISABLE Block Public Access and (b) attach a public ACL or
#       bucket policy. Implement these resources:
#
#   resource "aws_s3_bucket_public_access_block" "vulnerable" {
#     bucket                  = aws_s3_bucket.vulnerable.id
#     block_public_acls       = false
#     block_public_policy     = false
#     ignore_public_acls      = false
#     restrict_public_buckets = false
#   }
#
#   resource "aws_s3_bucket_policy" "public_read" {
#     bucket = aws_s3_bucket.vulnerable.id
#     policy = jsonencode({ ... allow s3:GetObject to Principal "*" ... })
#   }
#
# Note: tfsec/Checkov in CI WILL flag these — that's expected and intentional here.
# Suppress with an inline comment that explains it's a controlled lab resource.

# TODO: Optionally upload a harmless "secret looking" sample object so the attack has
#       something to read (e.g. a fake 'credentials.txt' with obviously fake content).

output "bucket_name" {
  value       = aws_s3_bucket.vulnerable.id
  description = "Name of the deliberately public bucket"
}
