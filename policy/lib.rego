# Shared helpers and the decision rules that Conftest reads (deny / warn).
# Every rule file adds entries to the `finding` set; this file decides
# whether each finding blocks the pipeline, is waived by an approved
# exception, or is blocked because its exception has expired.
package main

# Resources Terraform will create or change. Deletes and no-ops are ignored.
resources contains r if {
	some r in input.resource_changes
	r.mode == "managed"
	some action in r.change.actions
	action in {"create", "update"}
}

# Current time. Kept as a rule so tests can pin it with `with data.main.now_ns as ...`.
now_ns := time.now_ns()

# An exception matches a finding on rule id and resource address.
matching_exceptions(v) := {e |
	some e in data.exceptions
	e.rule == v.rule
	e.resource == v.resource
}

active_exception(v) := e if {
	some e in matching_exceptions(v)
	time.parse_rfc3339_ns(e.expires) > now_ns
}

has_active_exception(v) if active_exception(v)

expired_exception(v) := e if {
	not has_active_exception(v)
	some e in matching_exceptions(v)
	time.parse_rfc3339_ns(e.expires) <= now_ns
}

has_expired_exception(v) if expired_exception(v)

# 1. Plain finding, no exception on file: block.
deny contains msg if {
	some v in finding
	not has_active_exception(v)
	not has_expired_exception(v)
	msg := sprintf("[%s] %s: %s", [v.rule, v.resource, v.msg])
}

# 2. Exception existed but has expired: block, and say which ADR to renew.
deny contains msg if {
	some v in finding
	e := expired_exception(v)
	msg := sprintf("[%s] %s: %s (exception under %s expired %s; renew the ADR or fix the resource)", [v.rule, v.resource, v.msg, e.adr, e.expires])
}

# 3. Approved, unexpired exception: let it through but keep it visible.
warn contains msg if {
	some v in finding
	e := active_exception(v)
	msg := sprintf("[%s] %s: waived under %s (owner %s) until %s", [v.rule, v.resource, e.adr, e.owner, e.expires])
}
