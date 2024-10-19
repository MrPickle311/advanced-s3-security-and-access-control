resource "aws_kms_key" "bucket_2_kms_key" {
  description = "KMS key for Bucket 2 encryption"
}

resource "aws_kms_key_policy" "aws_kms_key_policy" {
  key_id = aws_kms_key.bucket_2_kms_key.id
  policy = jsonencode({
    Id = "example"
    Statement = [
      {
        Action = "kms:*"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }

        Resource = "*"
        Sid      = "Enable S3 Permissions"
      },
      {
        Action = "kms:*"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:root"
        }

        Resource = "*"
        Sid      = "Enable IAM User Permissions"
      },
    ]
    Version = "2012-10-17"
  })
}