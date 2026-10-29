# S3 guardrails.
# S3_001  public access block must set all four flags to true
# S3_002  every bucket must have a public access block attached
# S3_003  server side encryption must use KMS (aws:kms)
# S3_004  every bucket must have a server side encryption configuration
package main

pab_flags := [
	"block_public_acls",
	"block_public_policy",
	"ignore_public_acls",
	"restrict_public_buckets",
]

finding contains v if {
	some r in resources
	r.type == "aws_s3_bucket_public_access_block"
	some flag in pab_flags
	r.change.after[flag] != true
	v := {
		"rule": "S3_001",
		"resource": r.address,
		"msg": sprintf("%s must be true", [flag]),
	}
}

finding contains v if {
	some r in resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
	some rule in r.change.after.rule
	some d in rule.apply_server_side_encryption_by_default
	d.sse_algorithm != "aws:kms"
	v := {
		"rule": "S3_003",
		"resource": r.address,
		"msg": sprintf("sse_algorithm is '%s'; aws:kms is required", [d.sse_algorithm]),
	}
}

# Cross-resource checks. Bucket ids are unknown at plan time, so the link
# between a bucket and its companion resources is read from the
# configuration block (the references Terraform recorded), not from values.
# Limitation: root module only. See README.
config_resources := object.get(input, ["configuration", "root_module", "resources"], [])

buckets_referenced_by(companion_type) := {ref |
	some c in config_resources
	c.type == companion_type
	some ref in c.expressions.bucket.references
}

bucket_missing_companion(r, companion_type) if {
	r.type == "aws_s3_bucket"
	not r.address in buckets_referenced_by(companion_type)
	not sprintf("%s.id", [r.address]) in buckets_referenced_by(companion_type)
}

finding contains v if {
	some r in resources
	bucket_missing_companion(r, "aws_s3_bucket_public_access_block")
	v := {
		"rule": "S3_002",
		"resource": r.address,
		"msg": "bucket has no aws_s3_bucket_public_access_block",
	}
}

finding contains v if {
	some r in resources
	bucket_missing_companion(r, "aws_s3_bucket_server_side_encryption_configuration")
	v := {
		"rule": "S3_004",
		"resource": r.address,
		"msg": "bucket has no aws_s3_bucket_server_side_encryption_configuration",
	}
}
