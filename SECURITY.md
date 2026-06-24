# Security Policy

## Design posture
This tool is **read-only**: it authenticates to EDR/NGAV APIs with the minimum read
scope and never creates, modifies, or deletes exclusions. Credentials are read from
environment variables, never from config files, and are never written to disk.

## Supported versions
The project is pre-1.0; only the latest release on `main` receives security fixes.

## Reporting a vulnerability
Please **do not** open a public issue for security vulnerabilities.

Instead, use GitHub's private vulnerability reporting:
**Security → Report a vulnerability** (Privately report a security advisory) on the
repository. Include:

- a description of the issue and its impact,
- steps to reproduce, and
- any suggested remediation.

If you cannot use GitHub's private reporting, email the maintainer at
**jch1689@mail.com** with the same details.

You can expect an initial acknowledgement within a few days. Once a fix is available,
we'll coordinate disclosure and credit you if you wish.

## Scope
Examples of in-scope reports:
- any path by which the tool could perform a *write* to a vendor API,
- credential leakage (logged, written to disk, or exposed in output),
- a rule or matcher that could be abused to hide a malicious exclusion from the report.
