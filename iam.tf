
data "aws_iam_policy_document" "kms_access" {
  # checkov:skip=CKV_AWS_111: todo reduce perms on key
  # checkov:skip=CKV_AWS_109: ADD REASON
  statement {
    sid = "KMS Key Default"
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions = [
      "kms:*",
    ]

    resources = ["*"]

  }

  statement {
    sid = "CloudWatchLogsEncryption"
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]

    resources = ["*"]
  }

}


#"kmsKeyId": "${aws_kms_key.ssmkey.key_id}",
#"kmsKeyId": "${aws_kms_key.ssmkey.arn}",

# Create EC2 Instance Role
resource "aws_iam_role" "ssm_role" {
  name_prefix = "ssm_role-"
  path        = "/"
  tags        = var.tags

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
               "Service": "ec2.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}
EOF
}

data "aws_iam_policy" "AmazonSSMManagedInstanceCore" {
  arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "ssm_s3_cwl_access" {
  # checkov:skip=CKV_AWS_111: ADD REASON
  # A custom policy for S3 bucket access
  # https://docs.aws.amazon.com/en_us/systems-manager/latest/userguide/setup-instance-profile.html#instance-profile-custom-s3-policy
  statement {
    sid = "S3BucketAccessForSessionManager"

    actions = [
      "s3:PutObject",
      "s3:PutObjectAcl",
      "s3:PutObjectVersionAcl",
    ]

    resources = [
      aws_s3_bucket.session_logs_bucket.arn,
      "${aws_s3_bucket.session_logs_bucket.arn}/*",
    ]
  }

  statement {
    sid = "S3EncryptionForSessionManager"

    actions = [
      "s3:GetEncryptionConfiguration",
    ]

    resources = [
      aws_s3_bucket.session_logs_bucket.arn
    ]
  }

  dynamic "statement" {
      for_each = length(var.s3_disk_connector_directories) > 0 ? [1] : []
      content {
      sid = "S3BucketAccessForDiskConnectorBucket"

      actions = [
        "s3:ListBucket",
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ]

      resources = [
        "arn:aws:s3:::${lower("s3-disk-connector-${var.customer_name}-${var.environment_name}")}",
        "arn:aws:s3:::${lower("s3-disk-connector-${var.customer_name}-${var.environment_name}")}/*"
      ]

      condition {
        test     = "Bool"
        variable = "aws:SecureTransport"
        values   = ["true"]
      }
    }
  }

  statement {
    sid = "AllowKMS"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*"
    ]
    resources = "*"
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = ["${data.aws_caller_identity.current.account_id}"]
    }
  }

  # A custom policy for CloudWatch Logs access
  # https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/permissions-reference-cwl.html
  statement {
    sid = "CloudWatchLogsAccessForSessionManager"

    actions = [
      "logs:PutLogEvents",
      "logs:CreateLogStream",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]

    resources = ["*"]
  }

  statement {
    sid = "EC2InstanceMetadataAccess"

    actions = [
      "ec2:Describe*",
    ]

    resources = ["*"]
  }

  statement {
    sid = "CloudWatchWriteAccess"

    actions = [
      "cloudwatch:PutMetricData",
    ]

    resources = ["*"]
  }

  statement {
    sid = "KMSEncryptionForSessionManager"

    actions = [
      "kms:DescribeKey",
      "kms:GenerateDataKey",
      "kms:Decrypt",
      "kms:Encrypt",
    ]

    resources = [aws_kms_key.ssmkey.arn]
  }
}

resource "aws_iam_policy" "ssm_s3_cwl_access" {
  name   = "ssm_s3_cwl_access-${local.region}-${var.environment_name}-${var.customer_name}"
  path   = "/"
  policy = data.aws_iam_policy_document.ssm_s3_cwl_access.json
}

resource "aws_iam_role_policy_attachment" "SSM-role-policy-attach" {
  role       = aws_iam_role.ssm_role.name
  policy_arn = data.aws_iam_policy.AmazonSSMManagedInstanceCore.arn
}

resource "aws_iam_role_policy_attachment" "SSM-s3-cwl-policy-attach" {
  role       = aws_iam_role.ssm_role.name
  policy_arn = aws_iam_policy.ssm_s3_cwl_access.arn
}

resource "aws_iam_instance_profile" "ssm_profile" {
  name_prefix = "ssm_profile-"
  role        = aws_iam_role.ssm_role.name
}
