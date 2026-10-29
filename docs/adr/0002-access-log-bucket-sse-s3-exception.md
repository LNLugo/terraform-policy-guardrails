# ADR-0002: Exception to S3_003 for the S3 server access log bucket

- **Status:** Accepted, expires 2027-06-30
- **Date:** 2026-10-28
- **Rule waived:** `S3_003` (server side encryption must use `aws:kms`)
- **Resource:** `aws_s3_bucket_server_side_encryption_configuration.access_logs`
- **Owner:** platform-storage

## Context

S3 server access logging writes to a destination bucket. AWS supports only SSE-S3
(`AES256`) default encryption on that destination bucket, not SSE-KMS. Requiring
KMS on it would break access logging, which is itself a control.

## Decision

Grant a time-boxed exception for this single resource. The data bucket keeps
KMS encryption; only the log destination uses SSE-S3.

## Risk and compensating controls

- Log bucket is private: all four public access block flags are enforced (`S3_001`).
- Log content is classified `internal`, not `confidential`.
- Access restricted to the logging service and the security team.

## Remediation path

Review at expiry. If logging moves to CloudTrail data events or another
destination that supports KMS, remove this exception and the waiver entry.

## Expiry

2027-06-30. After that date the policy gate fails this resource until the ADR
is renewed or the resource is changed.
