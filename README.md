# terraform-policy-guardrails

[![policy-gate](https://github.com/LNLugo/terraform-policy-guardrails/actions/workflows/policy-gate.yml/badge.svg)](https://github.com/LNLugo/terraform-policy-guardrails/actions/workflows/policy-gate.yml)

Architecture standards for cloud infrastructure, written as code and enforced
in the pipeline. Every pull request runs `terraform plan`, converts the plan to
JSON, and evaluates it against Rego policies with
[Open Policy Agent](https://www.openpolicyagent.org/) via
[Conftest](https://www.conftest.dev/). A failing rule blocks the merge. Approved
deviations are waived through an exception register tied to architecture
decision records (ADRs) with an owner and an expiry date.

The point is **governance by design**: the compliant path is the default path,
reviewers stop repeating checklist comments, and every exception is visible,
owned and time-boxed.

## How it works

```
 Pull request
     │
     ▼
 terraform plan ──► terraform show -json ──► plan.json
                                                │
          policy/*.rego  (decision: OPA) ◄──────┤
          data/exceptions.json (waivers + ADRs) │
                                                ▼
                          Conftest result ──► CI job (enforcement)
                          deny  → merge blocked
                          warn  → merge allowed, waiver shown in the run summary
```

The policy engine makes the **decision**; the CI job **enforces** it. Keeping
those apart (policy decision point vs. policy enforcement point) means the same
rules can later run at other enforcement points: a Kubernetes admission
controller, an API gateway, or an AI agent's tool-call authorizer.

## Rules

| Id | Standard | Resources |
|---|---|---|
| `TAG_001` | Required tags: `owner`, `cost_center`, `data_classification` | S3, security groups, KMS, EC2, RDS |
| `TAG_002` | `data_classification` is one of `public`, `internal`, `confidential`, `restricted` | same |
| `S3_001` | Public access block sets all four flags to `true` | `aws_s3_bucket_public_access_block` |
| `S3_002` | Every bucket has a public access block | `aws_s3_bucket` |
| `S3_003` | Default encryption uses KMS (`aws:kms`) | `aws_s3_bucket_server_side_encryption_configuration` |
| `S3_004` | Every bucket has a default encryption configuration | `aws_s3_bucket` |
| `NET_001` | No SSH (22) or RDP (3389) open to `0.0.0.0/0` or `::/0` | security groups, ingress rules |
| `GOV_001` | Provider region is approved (`us-east-1`, `us-east-2`) | AWS provider |

## Exceptions

`data/exceptions.json` is the exception register. Each entry names the rule,
the resource address, the ADR that justifies it, an owner and an expiry date.

| State | Gate result |
|---|---|
| No exception | `deny`: build fails |
| Exception active | `warn`: build passes, waiver printed with ADR and owner |
| Exception expired | `deny`: build fails and names the ADR to renew |

See [ADR-0002](docs/adr/0002-access-log-bucket-sse-s3-exception.md) for a
real example: S3 server access logs only support SSE-S3 on the destination
bucket, so `S3_003` is waived for that one resource until 2027-06-30.

## Repository layout

```
policy/           Rego rules (one file per domain) and unit tests
data/             exception register
terraform/
  compliant/      golden path example: must pass the gate
  noncompliant/   deliberately broken example: must be rejected
fixtures/         saved plan JSON for running the gate without Terraform
docs/adr/         architecture decision records
.github/workflows/policy-gate.yml
```

## Run it

Requires [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa) and
[Conftest](https://www.conftest.dev/install/); Terraform for real plans.

```bash
make test                # format check, static check, 18 policy unit tests
make fixtures            # gate on saved plans (no Terraform needed)
make plan-compliant      # real terraform plan + gate (no AWS account needed)
make plan-noncompliant   # expected to fail with 10 findings
```

Expected result on the noncompliant example:

```
FAIL - [GOV_001] provider.aws: region 'eu-west-1' is not approved
FAIL - [NET_001] aws_security_group.jump: ingress from 0.0.0.0/0 exposes admin port 22
FAIL - [S3_001] aws_s3_bucket_public_access_block.exports: block_public_policy must be true
...
11 tests, 1 passed, 0 warnings, 10 failures
```

## CI

`.github/workflows/policy-gate.yml` runs on every pull request:

1. **policy-unit-tests:** `opa fmt`, `opa check --strict`, `opa test`.
2. **plan-gate:** real `terraform plan` on both examples. The job fails if the
   compliant example is rejected **or** if the noncompliant example gets through,
   so a broken policy cannot silently stop enforcing.

Plans run offline (mock credentials, `offline_plan = true`) because create-only
plans need no API calls.

## Design choices

- **Plan, not source.** The plan has variables, defaults and module inputs
  resolved. Static HCL scanners such as Checkov or Trivy are complementary.
- **Cross-resource links from `configuration`.** Bucket ids are unknown until
  apply, so the link from a bucket to its encryption and public access block
  resources is read from the references Terraform records in the plan.
- **Stable rule ids.** Ids make findings searchable, countable and waivable.
- **Expiry on every waiver.** Exceptions that never expire become the standard.

## Known limits

- Cross-resource checks read the root module only. Child module traversal
  (`configuration.root_module.module_calls`) is the next step.
- Plan-time checks cannot see drift or console changes. Detective controls
  (AWS Config, Azure Policy) are still required.
- AWS only. The same pattern applies to `azurerm` resources.

## Scaling this to many teams

- **Version the policies.** Publish the `policy/` directory as a versioned bundle
  to an OCI registry (`conftest push`) and have each team pin a version
  (`conftest pull`). Breaking rule changes go out as a new major version.
- **Roll out new rules as `warn` first,** publish the findings, then switch to
  `deny` on a known date.
- **Measure:** first-time pass rate of plans, top failing rules, number and age
  of active exceptions, time from failure to fix.

## License

MIT
