###############################################################################
# Scenario 01 — Detection: catch the bucket being made public.
#
# Strategy: CloudTrail records S3 management API calls. An EventBridge rule matches the
# relevant call(s) and invokes the detection Lambda.
#
# SKELETON — fill in the TODOs.
###############################################################################

# TODO: An EventBridge rule whose event_pattern matches the CloudTrail events that signal
#       a bucket being exposed, e.g. eventName in:
#         - PutBucketAcl
#         - PutBucketPolicy
#         - PutPublicAccessBlock
#         - DeletePublicAccessBlock
#
# resource "aws_cloudwatch_event_rule" "s3_public_change" {
#   name           = "aegis-project-01-s3-public-change"
#   event_bus_name = var.event_bus_name   # from infra/core outputs
#   event_pattern  = jsonencode({
#     source        = ["aws.s3"],
#     "detail-type" = ["AWS API Call via CloudTrail"],
#     detail = {
#       eventSource = ["s3.amazonaws.com"],
#       eventName   = ["PutBucketAcl", "PutBucketPolicy", "PutPublicAccessBlock",
#                      "DeletePublicAccessBlock"]
#     }
#   })
# }
#
# TODO: A target wiring the rule to the detection Lambda (aws_cloudwatch_event_target),
#       plus the aws_lambda_permission that lets EventBridge invoke it.
#
# TODO: Package detect_handler.py as the Lambda (aws_lambda_function). For a first version
#       you can zip it inline with the archive_file data source.

variable "event_bus_name" {
  type    = string
  default = "default"
}
