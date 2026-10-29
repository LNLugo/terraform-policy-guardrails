# Golden path example: a governed data bucket, its access-log bucket,
# and a bastion security group. Passes every policy in /policy, with one
# documented exception (ADR-0002) for the access-log bucket encryption.

locals {
  tags = {
    owner               = "payments-platform"
    cost_center         = "CC1042"
    data_classification = "confidential"
  }
}

resource "aws_kms_key" "data" {
  description         = "CMK for the payments data bucket"
  enable_key_rotation = true
  tags                = local.tags
}

resource "aws_s3_bucket" "data" {
  bucket = "example-payments-data-use1"
  tags   = local.tags
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
  }
}

resource "aws_s3_bucket_logging" "data" {
  bucket        = aws_s3_bucket.data.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "data/"
}

# Access-log destination. Server access logs require SSE-S3 on the target
# bucket, so S3_003 is waived here under ADR-0002 (see data/exceptions.json).
resource "aws_s3_bucket" "access_logs" {
  bucket = "example-payments-access-logs-use1"
  tags   = merge(local.tags, { data_classification = "internal" })
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_security_group" "bastion" {
  name        = "bastion-ssh"
  description = "SSH from the corporate range only"
  tags        = local.tags

  ingress {
    description = "SSH from corporate network"
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = [var.corporate_cidr]
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}
