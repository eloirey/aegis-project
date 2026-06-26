# Scenario 02 deliberately provisions an escalatable IAM identity. The attached
# policy is the vulnerability ON PURPOSE: it grants the privilege-escalation
# primitive the range is built to detect and remediate. tfsec/Checkov findings
# here are expected.
resource "aws_iam_user" "lowpriv" {
  name = "${var.project_name}-lab-developer"

  # The attack and the remediation both mutate this user out-of-band (attaching
  # AdministratorAccess, then a quarantine deny). Those policies never enter
  # Terraform state, so without force_destroy a teardown would fail on the
  # leftover attachments. This keeps `terraform destroy` clean every session.
  force_destroy = true

  tags = {
    Project  = var.project_name
    Scenario = "02-overprivileged-iam"
    Intent   = "intentionally-vulnerable"
  }
}

# The privilege-escalation primitive. On its own this reads like harmless IAM
# self-service, but iam:AttachUserPolicy over the user's own ARN lets the
# identity attach AdministratorAccess to itself: full escalation from a single
# leaked key. Scoped to self so the lab's blast radius is exactly that path and
# nothing else in the account is reachable. Widen Resource to "*" for the
# broader "over-permissioned CI/CD user" flavour.
resource "aws_iam_user_policy" "escalation_primitive" {
  name = "self-iam-management"
  user = aws_iam_user.lowpriv.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SelfIamManagement"
        Effect = "Allow"
        Action = [
          "iam:AttachUserPolicy",
          "iam:PutUserPolicy",
          "iam:ListAttachedUserPolicies",
          "iam:ListUserPolicies",
          "iam:GetUser",
        ]
        Resource = aws_iam_user.lowpriv.arn
      }
    ]
  })
}

# Long-lived key so the attack can authenticate as this identity, exactly as a
# leaked developer credential would. Lab-only: lives in (gitignored) state and
# is destroyed with the scenario each session.
resource "aws_iam_access_key" "lowpriv" {
  user = aws_iam_user.lowpriv.name
}
