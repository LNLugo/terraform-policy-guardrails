# ADR-0001: Enforce infrastructure guardrails as policy-as-code on Terraform plans

- **Status:** Accepted
- **Date:** 2026-10-28
- **Decider:** Luis N. Lugo

## Context

Architecture standards for cloud infrastructure (tagging, encryption, public
exposure, approved regions) were checked by people during design review. Review
happened late, findings caused rework, and the same comments repeated across teams.
Standards written as prose also drift in interpretation from one reviewer to the next.

## Decision

Express each standard as a Rego rule with a stable id (for example `S3_003`) and
evaluate it with Conftest against the JSON output of `terraform plan` on every
pull request. A failing rule blocks the merge.

- Evaluate the **plan**, not the HCL source, so variables, defaults and module
  inputs are resolved before the check.
- Read cross-resource links (bucket to public access block, bucket to encryption)
  from the plan's `configuration` references, because resource ids are unknown
  until apply.
- Keep policy decisions (OPA) separate from enforcement (the CI job), so the same
  rules can later run at other enforcement points.
- Waivers live in `data/exceptions.json`, each tied to an ADR, an owner and an
  expiry date. Expired waivers fail the build.

## Alternatives considered

| Option | Why not chosen |
|---|---|
| Manual design review only | Late feedback, inconsistent, does not scale |
| HashiCorp Sentinel | Tied to Terraform Cloud / Enterprise licensing |
| Static HCL scanners only (Checkov, Trivy) | Good for common misconfigurations, weaker for organization-specific rules and computed values; can run alongside this gate |
| Detective controls only (AWS Config, Azure Policy) | Catch problems after deployment; still needed for drift, but not a substitute for preventing the change |

## Consequences

- Standards become testable: each rule ships with unit tests (`opa test`).
- Review effort shifts from repeated checklist comments to genuine design questions.
- Policy changes now need versioning and a rollout path (warn first, then deny).
- Plan-time checks cannot see drift or console changes; detective controls remain required.
