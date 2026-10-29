# Deliberately broken. The pipeline must REJECT this plan.
# Expected findings: GOV_001, TAG_001, TAG_002, S3_001, S3_002, S3_003, S3_004, NET_001

resource "aws_s3_bucket" "reports" {
  bucket = "example-reports-euw1"
  tags = {
    owner = "analytics"
  }
}

resource "aws_s3_bucket" "exports" {
  bucket = "example-exports-euw1"
  tags = {
    owner               = "analytics"
    cost_center         = "CC2001"
    data_classification = "top-secret"
  }
}

resource "aws_s3_bucket_public_access_block" "exports" {
  bucket                  = aws_s3_bucket.exports.id
  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = false
}

resource "aws_s3_bucket_server_side_encryption_configuration" "exports" {
  bucket = aws_s3_bucket.exports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_security_group" "jump" {
  name        = "jump-host"
  description = "Too open"

  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
