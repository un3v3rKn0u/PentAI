# Security Policy

## Supported versions

PentAI is currently pre-release software. Security fixes are applied to the latest
revision of the `main` branch. No released version is supported yet.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability, exposed credential, or
assessment-data leak.

Use GitHub's private vulnerability reporting feature:

1. Open the repository's **Security** tab.
2. Select **Advisories**.
3. Select **Report a vulnerability**.

Include the affected revision, impact, reproduction conditions, and the smallest
synthetic example needed to explain the issue. Do not include real targets, customer
data, credentials, or exploit traffic from an assessment.

You should receive an acknowledgment within seven days. Validation and remediation
timelines depend on severity and reproducibility. Please allow time for a fix and
coordinated disclosure before publishing details.

## Scope

Reports about authorization bypasses, policy ambiguity, canonicalization differences,
audit integrity, unsafe network behavior, sensitive-data exposure, dependency
compromise, and release-signing weaknesses are particularly valuable.

The repository currently implements policy simulation only. It does not issue
ActionGrants or perform target-facing network execution.
