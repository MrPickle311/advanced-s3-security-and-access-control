resource "aws_cloudtrail" "s3_data_events" {
  name                          = "s3-data-events-trail"
  s3_bucket_name                = aws_s3_bucket.logging_bucket.id
  s3_key_prefix                 = "cloudtrail-logs"
  include_global_service_events = false

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail_logs.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch_role.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = [
        "${aws_s3_bucket.bucket_2.arn}/",
        "${aws_s3_bucket.bucket_3.arn}/"
      ]
    }
  }

  depends_on = [aws_s3_bucket_policy.logging_bucket_policy]
}

# https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html
data "aws_iam_policy_document" "logging_bucket_policy_data" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl",
    ]

    resources = [
      aws_s3_bucket.logging_bucket.arn
    ]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "s3:PutObject",
    ]

    resources = [
      "${aws_s3_bucket.logging_bucket.arn}/*",
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"

      values = [
        "bucket-owner-full-control",
      ]
    }
  }
}

resource "aws_s3_bucket_policy" "logging_bucket_policy" {
  bucket = aws_s3_bucket.logging_bucket.id
  policy = data.aws_iam_policy_document.logging_bucket_policy_data.json
}