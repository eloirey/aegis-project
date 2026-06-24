resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "vulnerable" {
  bucket = "${var.project_name}-lab-public-${random_id.suffix.hex}"

  tags = {
    Project  = var.project_name
    Scenario = "01-public-s3-bucket"
    Intent   = "intentionally-vulnerable"
  }
}

# Scenario 01 deliberately exposes this bucket. Both the public access block
# and the policy below are insecure ON PURPOSE so the range can detect and
# remediate them. tfsec/Checkov findings here are expected.
resource "aws_s3_bucket_public_access_block" "vulnerable" {
  bucket = aws_s3_bucket.vulnerable.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Grants anonymous read (Principal "*") to every object: the actual data leak.
resource "aws_s3_bucket_policy" "public_read" {
  bucket = aws_s3_bucket.vulnerable.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicRead"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.vulnerable.arn}/*"
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.vulnerable]
}

# Decoy object so the attack has something to exfiltrate. Fake content only.
resource "aws_s3_object" "decoy" {
  bucket  = aws_s3_bucket.vulnerable.id
  key     = "credentials.txt"
  content = "FAKE LAB DATA - not real credentials\nuser=demo\npassword=not-a-real-secret\n"
}