resource "aws_iam_role" "replication_role" {
  name = "s3-bucket-replication-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "replication_policy" {
  name = "s3-bucket-replication-policy"
  role = aws_iam_role.replication_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket",
          "s3:GetObjectVersionForReplication",
          "s3:GetObject",
          "s3:DeleteObject"
        ]
        Effect = "Allow"
        Resource = [
          aws_s3_bucket.bucket_2.arn,
          aws_s3_bucket.bucket_3.arn
        ]
      },
      {
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging"
        ]
        Effect = "Allow"
        Resource = [
          "${aws_s3_bucket.bucket_2.arn}/*",
          "${aws_s3_bucket.bucket_3.arn}/*"
        ]
      },
      {
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags",
          "s3:PutObject",
          "s3:GetObjectAcl",
          "s3:PutObjectAcl",
          "s3:ObjectOwnerOverrideToBucketOwner"
        ]
        Effect = "Allow"
        Resource = [
          aws_s3_bucket.bucket_2_replica.arn,
          aws_s3_bucket.bucket_3_replica.arn
        ]
      },
      {
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags",
          "s3:PutObject",
          "s3:GetObjectAcl",
          "s3:PutObjectAcl",
          "s3:ObjectOwnerOverrideToBucketOwner"
        ]
        Effect = "Allow"
        Resource = [
          "${aws_s3_bucket.bucket_2_replica.arn}/*",
          "${aws_s3_bucket.bucket_3_replica.arn}/*"
        ]
      },
      {
        "Action" : [
          "kms:Decrypt"
        ],
        "Effect" : "Allow",
        "Condition" : {
          "StringLike" : {
            "kms:ViaService" : "s3.${data.aws_region.current}.amazonaws.com",
            "kms:EncryptionContext:aws:s3:arn" : [
              aws_s3_bucket.bucket_2.arn
            ]
          }
        },
        "Resource" : [
          aws_kms_key.bucket_2_kms_key.arn
        ]
      },
      {
        "Action" : [
          "kms:Encrypt"
        ],
        "Effect" : "Allow",
        "Condition" : {
          "StringLike" : {
            "kms:ViaService" : "s3.${data.aws_region.current}.amazonaws.com",
            "kms:EncryptionContext:aws:s3:arn" : [
              aws_s3_bucket.bucket_2_replica.arn
            ]
          }
        },
        "Resource" : [
          aws_kms_key.bucket_2_kms_key.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role" "data_analytics_role" {
  name = "DataAnalyticsRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "DataAnalyticsRole"
  }
}

resource "aws_iam_policy" "data_analytics_policy" {
  name        = "DataAnalyticsPolicy"
  path        = "/"
  description = "IAM policy for Data Analytics role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.bucket_3.arn,
          "${aws_s3_bucket.bucket_3.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "data_analytics_policy_attachment" {
  role       = aws_iam_role.data_analytics_role.name
  policy_arn = aws_iam_policy.data_analytics_policy.arn
}
