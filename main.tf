data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_partition" "current" {}

# Check if SSM parameters exist in current region using external data source
data "external" "check_ssm_params" {
  count   = var.init_env ? 0 : 1
  program = ["bash", "-c", <<-EOT
    set -e
    # Try to get the SSM parameter, return exists=true/false
    if aws ssm get-parameter --name "_ssm_session_kms_key_id" --region ${data.aws_region.current.id} >/dev/null 2>&1; then
      echo '{"exists":"true"}'
    else
      echo '{"exists":"false"}'
    fi
  EOT
  ]
}

# Determine if we need to initialize in this region
locals {
  ssm_params_missing = var.init_env ? false : try(data.external.check_ssm_params[0].result.exists == "false", true)
  should_init        = var.init_env || local.ssm_params_missing
}

resource "aws_kms_key" "ssmkey" {
  count                   = local.should_init ? 1 : 0
  description             = "SSM Key"
  deletion_window_in_days = var.kms_key_deletion_window
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_access.json
  tags                    = var.tags
}

resource "aws_kms_alias" "ssmkey" {
  count         = local.should_init ? 1 : 0
  name_prefix   = "${var.kms_key_alias}-"
  target_key_id = aws_kms_key.ssmkey[0].key_id
}

resource "aws_ssm_parameter" "ssmkey" {
  count = local.should_init ? 1 : 0
  name  = "_ssm_session_kms_key_id"
  type  = "String"
  value = aws_kms_key.ssmkey[0].key_id
}

data "aws_ssm_parameter" "ssm_session_kms_key_id" {
  count = local.should_init ? 0 : 1
  name  = "_ssm_session_kms_key_id"
}

resource "aws_cloudwatch_log_group" "session_manager_log_group" {
  count             = local.should_init ? 1 : 0
  name_prefix       = "${var.cloudwatch_log_group_name}-${lower(var.customer_name)}-"
  retention_in_days = var.cloudwatch_logs_retention
  kms_key_id        = local.should_init ? aws_kms_key.ssmkey[0].arn : "arn:aws:kms:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:key/${data.aws_ssm_parameter.ssm_session_kms_key_id[0].value}"

  lifecycle {
    ignore_changes = [
      retention_in_days,
    ]
  }

  tags = var.tags
}

resource "aws_ssm_parameter" "ssmlogs" {
  count = local.should_init ? 1 : 0
  name  = "_ssm_session_cw_log_group_name"
  type  = "String"
  value = aws_cloudwatch_log_group.session_manager_log_group[0].name
}

data "aws_ssm_parameter" "ssm_session_cw_log_group_name" {
  count = local.should_init ? 0 : 1
  name  = "_ssm_session_cw_log_group_name"
}

resource "null_resource" "update_ssm_document" {
  count = local.should_init ? 1 : 0
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
    "cloudWatchLogGroupName": "${local.should_init ? aws_cloudwatch_log_group.session_manager_log_group[0].name : data.aws_ssm_parameter.ssm_session_cw_log_group_name[0].value}",
    "cloudWatchStreamingEnabled": true,
    "idleSessionTimeout": "60",
    "kmsKeyId": "${local.should_init ? aws_kms_key.ssmkey[0].arn : "arn:aws:kms:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:key/${data.aws_ssm_parameter.ssm_session_kms_key_id[0].value}"}",
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
)" | jq -r '.DocumentDescription.DocumentVersion // "1"')

      echo "New DocumentVersion is: $DOC_VERSION"

      # Set the default version
      aws ssm update-document-default-version \
        --name "SSM-SessionManagerRunShell" \
        --document-version "$DOC_VERSION" \
        --region "${var.region}"
    EOT
  }
}
