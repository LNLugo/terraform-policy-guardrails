# TAG_001 and TAG_002: every taggable resource carries ownership,
# cost and data classification tags, and the classification is a known value.
package main

required_tags := {"owner", "cost_center", "data_classification"}

allowed_classifications := {"public", "internal", "confidential", "restricted"}

taggable_types := {
	"aws_s3_bucket",
	"aws_security_group",
	"aws_kms_key",
	"aws_instance",
	"aws_db_instance",
}

# tags_all includes provider default_tags; fall back to tags; treat null as empty.
tag_map(r) := t if {
	t := r.change.after.tags_all
	is_object(t)
} else := t if {
	t := r.change.after.tags
	is_object(t)
} else := {}

finding contains v if {
	some r in resources
	r.type in taggable_types
	present := {k | some k, _ in tag_map(r)}
	missing := required_tags - present
	count(missing) > 0
	v := {
		"rule": "TAG_001",
		"resource": r.address,
		"msg": sprintf("missing required tags %v", [sort(missing)]),
	}
}

finding contains v if {
	some r in resources
	r.type in taggable_types
	c := tag_map(r).data_classification
	not c in allowed_classifications
	v := {
		"rule": "TAG_002",
		"resource": r.address,
		"msg": sprintf("data_classification '%v' is not one of %v", [c, sort(allowed_classifications)]),
	}
}
