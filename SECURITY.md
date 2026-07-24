# Security policy

## Supported versions

Unpin is pre-1.0 software. Security fixes are provided for the latest published
beta only.

| Version | Supported |
| --- | --- |
| Latest `0.1.0-beta.x` | Yes |
| Older prereleases | No |

## Report a vulnerability

Do not open a public issue for a suspected vulnerability.

Use
[GitHub private vulnerability reporting](https://github.com/IgorArkhipov/unpin/security/advisories/new)
to send the report directly to the maintainer. Include:

- the affected Unpin version or commit;
- the provider, command, and configuration surface involved;
- reproduction steps using sanitized or fixture data;
- the expected and observed safety boundary;
- the potential impact and any suggested mitigation.

Do not include real credentials, provider payloads, private paths, or unrelated
local configuration.

The maintainer aims to acknowledge a new report within seven days. This is a
response target, not a service-level agreement. Publication timing will be
coordinated with the reporter after impact and remediation are understood.

## Security boundaries

Unpin manages local AI-agent configuration and treats mutation, approval,
backup, restore, gateway, session, hook, and credential handling as
safety-critical. Reports about secret disclosure, path traversal, symlink or
lock bypass, stale-plan application, approval replay, backup forgery, restore
confusion, provider-state corruption, or MCP boundary bypass are in scope.

Reports that require unsupported legacy provider versions, historical config
paths, or knowingly modified fixture-only assumptions may be closed as out of
scope unless they also affect a supported surface.
