# Module: detection-lambda

Reusable Terraform module to package + deploy a detection/remediation Python Lambda,
wire an EventBridge rule to it, and grant the needed IAM permissions. Build this once
scenario 01 works, then refactor 01 to use it and reuse it for 02/03.
