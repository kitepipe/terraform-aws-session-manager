output "session_logs_bucket_name" {
  value = aws_s3_bucket.session_logs_bucket.id
}

output "access_log_bucket_name" {
  value = aws_s3_bucket.access_log_bucket.id
}

output "cloudwatch_log_group_arn" {
  value = (var.init_env) ? aws_cloudwatch_log_group.session_manager_log_group[0].name : data.aws_ssm_parameter.ssm_session_cw_log_group_name[0].value
}

output "kms_key_arn" {
  value = (var.init_env) ? aws_kms_key.ssmkey[0].arn : "arn:aws:kms:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:key/${data.aws_ssm_parameter.ssm_session_kms_key_id[0].value}"
}

output "iam_role_arn" {
  value = aws_iam_role.ssm_role.arn
}

output "iam_profile_name" {
  value = aws_iam_instance_profile.ssm_profile.name
}

output "ssm_security_group" {
  value = aws_security_group.ssm_sg.*.id
}

output "vpc_endpoint_ssm" {
  value = aws_vpc_endpoint.ssm.*.id
}

output "vpc_endpoint_ec2messages" {
  value = aws_vpc_endpoint.ec2messages.*.id
}

output "vpc_endpoint_ssmmessages" {
  value = aws_vpc_endpoint.ssmmessages.*.id
}

output "vpc_endpoint_s3" {
  value = aws_vpc_endpoint.s3.*.id
}

output "vpc_endpoint_logs" {
  value = aws_vpc_endpoint.logs.*.id
}

output "vpc_endpoint_kms" {
  value = aws_vpc_endpoint.kms.*.id
}
