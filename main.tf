data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_partition" "current" {}
resource "aws_kms_key" "ssmkey" {
  description             = "SSM Key"
  deletion_window_in_days = var.kms_key_deletion_window
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_access.json
  tags                    = var.tags
}

resource "aws_kms_alias" "ssmkey" {
  name_prefix   = "${var.kms_key_alias}-"
  target_key_id = aws_kms_key.ssmkey.key_id
}

resource "aws_cloudwatch_log_group" "session_manager_log_group" {
  name_prefix       = "${var.cloudwatch_log_group_name}-"
  retention_in_days = var.cloudwatch_logs_retention
  kms_key_id        = aws_kms_key.ssmkey.arn

  lifecycle {
    ignore_changes = [
      retention_in_days,
    ]
  }

  tags = var.tags
}

# resource "aws_ssm_document" "session_manager_prefs" {
#   name            = "SSM-SessionManagerRunShell-${var.environment_name}-${var.customer_name}"
#   document_type   = "Session"
#   document_format = "JSON"
#   tags            = var.tags

#   content = jsonencode({
#     schemaVersion = "1.0"
#     description   = "Document to hold regional settings for Session Manager"
#     sessionType   = "Standard_Stream"
#     inputs = {
#       s3BucketName                = var.enable_log_to_s3 ? aws_s3_bucket.session_logs_bucket.id : ""
#       s3KeyPrefix                 = ""
#       s3EncryptionEnabled         = var.enable_log_to_s3 ? true : false
#       cloudWatchLogGroupName      = var.enable_log_to_cloudwatch ? aws_cloudwatch_log_group.session_manager_log_group.name : ""
#       cloudWatchEncryptionEnabled = var.enable_log_to_cloudwatch ? true : false
#       cloudWatchStreamingEnabled  = var.enable_log_to_cloudwatch ? true : false
#       idleSessionTimeout          = "60"
#       maxSessionDuration          = "1000"
#       kmsKeyId                    = aws_kms_key.ssmkey.key_id
#       runAsEnabled                = false
#       runAsDefaultUser            = ""
#       shellProfile = {
#         linux   = var.linux_shell_profile == "" ? var.linux_shell_profile : ""
#         windows = var.windows_shell_profile == "" ? var.windows_shell_profile : ""
#       }
#     }
#   })
# }

resource "null_resource" "update_ssm_document" {
  provisioner "local-exec" {
    command = <<-EOT
      #!/bin/bash
      set -e

      # Auth to current AWS TF provider account
      ROLE_ARN="arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.assume_profile_name}"
      echo $ROLE_ARN
      CREDS=$(aws sts assume-role --role-arn "$ROLE_ARN" --role-session-name tf-session --external-id ${var.external_id})
      echo $CREDS
      export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.Credentials.AccessKeyId')
      export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.Credentials.SecretAccessKey')
      export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r '.Credentials.SessionToken')

      # Find epoch
      export EPOCH=$(date +%s)

      # Run update-document and capture the new DocumentVersion
      DOC_VERSION=$(aws ssm update-document \
        --name "SSM-SessionManagerRunShell" \
        --region "${var.region}" \
        --document-version "\$LATEST" \
        --content "$(cat <<EOF
{
  "description": "Document to hold regional settings for Session Manager $EPOCH",
  "inputs": {
    "cloudWatchEncryptionEnabled": true,
    "cloudWatchLogGroupName": "${aws_cloudwatch_log_group.session_manager_log_group.name}",
    "cloudWatchStreamingEnabled": true,
    "idleSessionTimeout": "60",
    "kmsKeyId": "${aws_kms_key.ssmkey.key_id}",
    "maxSessionDuration": "1000",
    "runAsDefaultUser": "",
    "runAsEnabled": false,
    "s3BucketName": "",
    "s3EncryptionEnabled": false,
    "s3KeyPrefix": "",
    "shellProfile": {
      "linux": "",
      "windows": ""
    }
  },
  "schemaVersion": "1.0",
  "sessionType": "Standard_Stream"
}
EOF
)" | jq -r '.DocumentDescription.DocumentVersion')

      echo "New DocumentVersion is: $DOC_VERSION"

      # Set the default version
      aws ssm update-document-default-version \
        --name "SSM-SessionManagerRunShell" \
        --document-version "$DOC_VERSION" \
        --region "${var.region}"
    EOT
  }
}
