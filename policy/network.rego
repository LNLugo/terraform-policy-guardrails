# NET_001: no administrative port (SSH 22, RDP 3389) open to the internet.
# Covers inline ingress blocks on aws_security_group and the standalone
# aws_vpc_security_group_ingress_rule resource.
package main

admin_ports := {22, 3389}

open_cidrs := {"0.0.0.0/0", "::/0"}

# Admin ports a rule exposes. Protocol "-1" means all traffic, so every port.
exposed_admin_ports(protocol, from, to) := {p |
	some p in admin_ports
	port_in_range(protocol, from, to, p)
}

port_in_range(protocol, _, _, _) if protocol == "-1"

port_in_range(_, from, to, p) if {
	from <= p
	p <= to
}

finding contains v if {
	some r in resources
	r.type == "aws_security_group"
	some rule in r.change.after.ingress
	cidrs := array.concat(object.get(rule, "cidr_blocks", []), object.get(rule, "ipv6_cidr_blocks", []))
	some cidr in cidrs
	cidr in open_cidrs
	some port in exposed_admin_ports(rule.protocol, rule.from_port, rule.to_port)
	v := {
		"rule": "NET_001",
		"resource": r.address,
		"msg": sprintf("ingress from %s exposes admin port %d", [cidr, port]),
	}
}

finding contains v if {
	some r in resources
	r.type == "aws_vpc_security_group_ingress_rule"
	a := r.change.after
	cidr := object.get(a, "cidr_ipv4", object.get(a, "cidr_ipv6", ""))
	cidr in open_cidrs
	some port in exposed_admin_ports(a.ip_protocol, object.get(a, "from_port", 0), object.get(a, "to_port", 65535))
	v := {
		"rule": "NET_001",
		"resource": r.address,
		"msg": sprintf("ingress from %s exposes admin port %d", [cidr, port]),
	}
}
