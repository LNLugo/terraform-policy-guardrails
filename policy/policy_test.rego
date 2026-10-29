# Unit tests. Run with: opa test policy -v
package main_test

import data.main

# Fixed clock: 2026-11-01T00:00:00Z
fixed_now := time.parse_rfc3339_ns("2026-11-01T00:00:00Z")

good_tags := {"owner": "payments-platform", "cost_center": "CC1042", "data_classification": "confidential"}

change(type, name, after) := {
	"address": sprintf("%s.%s", [type, name]),
	"mode": "managed",
	"type": type,
	"name": name,
	"change": {"actions": ["create"], "after": after},
}

bucket_with_companions := {
	"resource_changes": [
		change("aws_s3_bucket", "data", {"bucket": "x", "tags": good_tags, "tags_all": good_tags}),
		change("aws_s3_bucket_public_access_block", "data", {
			"block_public_acls": true, "block_public_policy": true,
			"ignore_public_acls": true, "restrict_public_buckets": true,
		}),
		change("aws_s3_bucket_server_side_encryption_configuration", "data", {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]}),
	],
	"configuration": {"root_module": {"resources": [
		{"address": "aws_s3_bucket_public_access_block.data", "type": "aws_s3_bucket_public_access_block", "expressions": {"bucket": {"references": ["aws_s3_bucket.data.id", "aws_s3_bucket.data"]}}},
		{"address": "aws_s3_bucket_server_side_encryption_configuration.data", "type": "aws_s3_bucket_server_side_encryption_configuration", "expressions": {"bucket": {"references": ["aws_s3_bucket.data.id", "aws_s3_bucket.data"]}}},
	]}},
}

# ---------- compliant baseline ----------

test_compliant_bucket_passes if {
	count(main.deny) == 0 with input as bucket_with_companions with data.exceptions as []
}

# ---------- tags ----------

test_missing_tags_denied if {
	inp := {"resource_changes": [change("aws_s3_bucket", "b", {"tags": {"owner": "x"}})]}
	some msg in main.deny with input as inp with data.exceptions as []
	contains(msg, "[TAG_001] aws_s3_bucket.b")
}

test_null_tags_denied if {
	inp := {"resource_changes": [change("aws_security_group", "sg", {"tags": null, "ingress": []})]}
	some msg in main.deny with input as inp with data.exceptions as []
	contains(msg, "TAG_001")
}

test_bad_classification_denied if {
	t := object.union(good_tags, {"data_classification": "secret-ish"})
	inp := {"resource_changes": [change("aws_kms_key", "k", {"tags": t})]}
	some msg in main.deny with input as inp with data.exceptions as []
	contains(msg, "TAG_002")
}

# ---------- S3 ----------

test_public_access_flag_false_denied if {
	inp := {"resource_changes": [change("aws_s3_bucket_public_access_block", "p", {
		"block_public_acls": true, "block_public_policy": false,
		"ignore_public_acls": true, "restrict_public_buckets": true,
	})]}
	some msg in main.deny with input as inp with data.exceptions as []
	contains(msg, "[S3_001]")
	contains(msg, "block_public_policy")
}

test_bucket_without_companions_denied if {
	inp := {"resource_changes": [change("aws_s3_bucket", "lonely", {"tags": good_tags})]}
	denies := main.deny with input as inp with data.exceptions as []
	some a in denies
	contains(a, "[S3_002]")
	some b in denies
	contains(b, "[S3_004]")
}

test_sse_s3_denied if {
	inp := {"resource_changes": [change("aws_s3_bucket_server_side_encryption_configuration", "e", {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]})]}
	some msg in main.deny with input as inp with data.exceptions as []
	contains(msg, "[S3_003]")
}

# ---------- network ----------

test_ssh_open_to_internet_denied if {
	inp := {"resource_changes": [change("aws_security_group", "web", {"tags": good_tags, "ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]})]}
	some msg in main.deny with input as inp with data.exceptions as []
	contains(msg, "[NET_001]")
}

test_all_traffic_rule_denied if {
	inp := {"resource_changes": [change("aws_security_group", "web", {"tags": good_tags, "ingress": [{"protocol": "-1", "from_port": 0, "to_port": 0, "ipv6_cidr_blocks": ["::/0"]}]})]}
	some msg in main.deny with input as inp with data.exceptions as []
	contains(msg, "[NET_001]")
}

test_https_open_to_internet_allowed if {
	inp := {"resource_changes": [change("aws_security_group", "web", {"tags": good_tags, "ingress": [{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]}]})]}
	count(main.deny) == 0 with input as inp with data.exceptions as []
}

test_ssh_from_corporate_range_allowed if {
	inp := {"resource_changes": [change("aws_security_group", "bastion", {"tags": good_tags, "ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["10.20.0.0/16"]}]})]}
	count(main.deny) == 0 with input as inp with data.exceptions as []
}

test_standalone_ingress_rule_denied if {
	inp := {"resource_changes": [change("aws_vpc_security_group_ingress_rule", "rdp", {"ip_protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr_ipv4": "0.0.0.0/0"})]}
	some msg in main.deny with input as inp with data.exceptions as []
	contains(msg, "admin port 3389")
}

# ---------- region ----------

test_unapproved_region_literal_denied if {
	inp := {"resource_changes": [], "configuration": {"provider_config": {"aws": {"expressions": {"region": {"constant_value": "eu-west-1"}}}}}}
	some msg in main.deny with input as inp with data.exceptions as []
	contains(msg, "[GOV_001]")
}

test_unapproved_region_via_variable_denied if {
	inp := {
		"resource_changes": [],
		"variables": {"region": {"value": "ap-south-1"}},
		"configuration": {"provider_config": {"aws": {"expressions": {"region": {"references": ["var.region"]}}}}},
	}
	some msg in main.deny with input as inp with data.exceptions as []
	contains(msg, "ap-south-1")
}

test_approved_region_allowed if {
	inp := {"resource_changes": [], "configuration": {"provider_config": {"aws": {"expressions": {"region": {"constant_value": "us-east-1"}}}}}}
	count(main.deny) == 0 with input as inp with data.exceptions as []
}

# ---------- exceptions ----------

sse_s3_input := {"resource_changes": [change("aws_s3_bucket_server_side_encryption_configuration", "logs", {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]})]}

exception(expires) := [{
	"rule": "S3_003",
	"resource": "aws_s3_bucket_server_side_encryption_configuration.logs",
	"adr": "ADR-0002",
	"owner": "platform-storage",
	"expires": expires,
}]

test_active_exception_waives_and_warns if {
	ex := exception("2027-06-30T00:00:00Z")
	count(main.deny) == 0 with input as sse_s3_input with data.exceptions as ex with data.main.now_ns as fixed_now
	some w in main.warn with input as sse_s3_input with data.exceptions as ex with data.main.now_ns as fixed_now
	contains(w, "waived under ADR-0002")
}

test_expired_exception_denies if {
	ex := exception("2026-10-01T00:00:00Z")
	some msg in main.deny with input as sse_s3_input with data.exceptions as ex with data.main.now_ns as fixed_now
	contains(msg, "expired")
	contains(msg, "ADR-0002")
}

test_exception_for_other_resource_does_not_apply if {
	ex := [object.union(exception("2027-06-30T00:00:00Z")[0], {"resource": "aws_s3_bucket_server_side_encryption_configuration.other"})]
	some msg in main.deny with input as sse_s3_input with data.exceptions as ex with data.main.now_ns as fixed_now
	contains(msg, "[S3_003]")
}
