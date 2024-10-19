terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }

  required_version = ">= 1.2.0"
}

provider "aws" {
  alias  = "replica_region"
  region = "eu-central-1"
}

# Create S3 buckets
resource "aws_s3_bucket" "bucket_1" {
  bucket = "s3-trainings-public-website-bucket"
}

resource "aws_s3_bucket" "bucket_2" {
  bucket = "s3-trainings-confidential-documents-bucket"
}

resource "aws_s3_bucket" "bucket_3" {
  bucket = "s3-trainings-data-analytics-bucket"
}

resource "aws_s3_bucket" "logging_bucket" {
  bucket = "s3-trainings-s3-access-logs-bucket"
}

# Bucket 1: Public read access for static website hosting
resource "aws_s3_bucket_website_configuration" "bucket_1_website" {
  bucket = aws_s3_bucket.bucket_1.id

  index_document {
    suffix = "index.html"
  }
}

resource "aws_s3_bucket_public_access_block" "logging_bucket_public_access" {
  bucket = aws_s3_bucket.logging_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logging_bucket_versioning" {
  bucket = aws_s3_bucket.logging_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logging_bucket_encryption" {
  bucket = aws_s3_bucket.logging_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "bucket_1_public_access" {
  bucket = aws_s3_bucket.bucket_1.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "bucket_1_policy" {
  depends_on = [aws_s3_bucket_public_access_block.bucket_1_public_access]
  bucket = aws_s3_bucket.bucket_1.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.bucket_1.arn}/*"
      },
      {
        Sid    = "PublicReadGetObject"
        Effect = "Allow"
        Principal = {
          "AWS" : "arn:aws:iam::${var.account_id}:root"
        }
        Action   = "s3:PutBucketAcl"
        Resource = aws_s3_bucket.bucket_1.arn
      },
    ]
  })
}

# Bucket 2: Private access for confidential company documents
resource "aws_s3_bucket_public_access_block" "bucket_2_public_access" {
  bucket = aws_s3_bucket.bucket_2.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "aws_s3_bucket_policy_data" {
  statement {
    sid    = "AllowSpecificRoles"
    effect = "Allow"
    principals {
      identifiers = [
        aws_iam_role.data_analytics_role.arn
      ]
      type = "AWS"
    }
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket"
    ]
    resources = [
      aws_s3_bucket.bucket_3.arn,
      "${aws_s3_bucket.bucket_3.arn}/*"
    ]
  }

  statement {
    sid    = "DenyDeleteObjects"
    effect = "Deny"
    principals {
      type = "AWS"
      identifiers = ["*"]
    }
    actions = ["s3:DeleteObject"]
    resources = ["${aws_s3_bucket.bucket_3.arn}/*"]
    condition {
      test     = "ForAnyValue:StringNotEquals"
      values = [
        "arn:aws:iam::${var.account_id}:root"
      ]
      variable = "aws:PrincipalArn"
    }
  }
}

# Bucket 3: Limited access for specific IAM roles for data analytics
resource "aws_s3_bucket_policy" "bucket_3_policy" {
  bucket = aws_s3_bucket.bucket_3.id
  policy = data.aws_iam_policy_document.aws_s3_bucket_policy_data.json
}

# ACLs

resource "aws_s3_bucket_ownership_controls" "bucket_1_ownership" {
  depends_on = [
    aws_s3_bucket_versioning.bucket_3_replica_versioning,
    aws_s3_bucket_policy.bucket_1_policy
  ]
  bucket = aws_s3_bucket.bucket_1.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "bucket_1_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.bucket_1_ownership]

  bucket = aws_s3_bucket.bucket_1.id
  acl    = "public-read"
}

resource "aws_s3_bucket_ownership_controls" "bucket_2_ownership" {
  bucket = aws_s3_bucket.bucket_2.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "bucket_2_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.bucket_2_ownership]

  bucket = aws_s3_bucket.bucket_2.id
  access_control_policy {
    grant {
      grantee {
        id   = data.aws_canonical_user_id.current.id
        type = "CanonicalUser"
      }
      permission = "FULL_CONTROL"
    }
    owner {
      id = data.aws_canonical_user_id.current.id
    }
  }
}

data "aws_canonical_user_id" "current" {
}

# Versioning and MFA Delete
resource "aws_s3_bucket_versioning" "bucket_1_versioning" {
  bucket = aws_s3_bucket.bucket_1.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "bucket_2_versioning" {
  bucket = aws_s3_bucket.bucket_2.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "bucket_3_versioning" {
  bucket = aws_s3_bucket.bucket_3.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Object Lock
resource "aws_s3_bucket_object_lock_configuration" "bucket_3_object_lock" {
  depends_on = [aws_s3_bucket_versioning.bucket_3_versioning]
  bucket = aws_s3_bucket.bucket_3.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 365
    }
  }
}

# Server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "bucket_1_encryption" {
  bucket = aws_s3_bucket.bucket_1.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bucket_2_encryption" {
  bucket = aws_s3_bucket.bucket_2.id

  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.bucket_2_kms_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bucket_2_replica_encryption" {
  bucket = aws_s3_bucket.bucket_2_replica.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.bucket_2_kms_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

# Note: SSE-C encryption is configured on the client side, not in bucket configuration

# Logging and CloudTrail
resource "aws_s3_bucket_logging" "bucket_1_logging" {
  bucket = aws_s3_bucket.bucket_1.id

  target_bucket = aws_s3_bucket.logging_bucket.id
  target_prefix = "bucket1-logs/"
}

resource "aws_s3_bucket_logging" "bucket_2_logging" {
  bucket = aws_s3_bucket.bucket_2.id

  target_bucket = aws_s3_bucket.logging_bucket.id
  target_prefix = "bucket2-logs/"
}

resource "aws_s3_bucket_logging" "bucket_3_logging" {
  bucket = aws_s3_bucket.bucket_3.id

  target_bucket = aws_s3_bucket.logging_bucket.id
  target_prefix = "bucket3-logs/"
}

# S3 Replication
resource "aws_s3_bucket" "bucket_2_replica" {
  provider = aws.replica_region
  bucket   = "confidential-documents-replica"
}

resource "aws_s3_bucket_versioning" "bucket_2_replica_versioning" {
  bucket = aws_s3_bucket.bucket_2_replica.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_replication_configuration" "bucket_2_replication" {
  depends_on = [aws_s3_bucket_versioning.bucket_2_versioning]

  role   = aws_iam_role.replication_role.arn
  bucket = aws_s3_bucket.bucket_2.id

  rule {
    id     = "bucket2-replication-rule"
    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.bucket_2_replica.arn
      storage_class = "STANDARD"
      encryption_configuration {
        replica_kms_key_id = aws_kms_key.bucket_2_kms_key.arn
      }
      metrics {
        status = "Enabled"
      }
    }
    filter {
      and {
        tags = {}
      }
    }
    delete_marker_replication {
      status = "Enabled"
    }

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

  }
}

# # Same-region replication for Bucket 3
resource "aws_s3_bucket" "bucket_3_replica" {
  bucket = "data-analytics-replica"
}

resource "aws_s3_bucket_versioning" "bucket_3_replica_versioning" {
  bucket = aws_s3_bucket.bucket_3_replica.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "bucket_3_replica_object_lock" {
  depends_on = [aws_s3_bucket_versioning.bucket_3_replica_versioning]
  bucket = aws_s3_bucket.bucket_3_replica.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 365
    }
  }
}

resource "aws_s3_bucket_replication_configuration" "bucket_3_replication" {
  depends_on = [
    aws_s3_bucket_versioning.bucket_3_versioning,
    aws_s3_bucket_object_lock_configuration.bucket_3_replica_object_lock
  ]

  role   = aws_iam_role.replication_role.arn
  bucket = aws_s3_bucket.bucket_3.id

  rule {
    id     = "bucket3-replication-rule"
    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.bucket_3_replica.arn
      storage_class = "STANDARD"
    }


  }
}
