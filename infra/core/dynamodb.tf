resource "aws_dynamodb_table" "findings" {
  name         = "${var.project_name}-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  # Lab rows expire on their own so the table never grows across demo runs.
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}