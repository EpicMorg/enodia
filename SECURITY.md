# Security Policy

## Reporting a vulnerability

Report privately through GitHub Security Advisories:
<https://github.com/EpicMorg/enodia/security/advisories/new>

Or by email to <developer@epicmm.org>.

Please do not open a public issue for a security problem.

Expect an acknowledgement within a few days. This is a small project — there is
no paid security team and no bounty, but reports are taken seriously and
credited unless you prefer otherwise.

## Scope

Enodia holds credentials to production infrastructure. The following are
considered vulnerabilities:

- Credentials appearing in output, logs, exported reports, or the inventory file
- Credentials sent over an unencrypted transport without explicit opt-in
- TLS verification silently skipped when it was not requested
- A probe writing to, or otherwise modifying, a target
- Anything reachable over the network causing code execution
- Path traversal or arbitrary writes through config or output paths

The following are known and deliberate, not vulnerabilities:

- `tls.insecure: true` disables certificate verification. It is opt-in per
  service, warned about on every run, and recorded in the report
- `allow_insecure_transport: true` permits credentials over plain HTTP. Same
  conditions
- The inventory file contains service names, URLs, and versions. Use
  `--redact-urls` before it leaves your network

## Supported versions

Pre-1.0: only the latest release is supported. Once 1.0 ships, this section
will state a real support window.

## Hardening notes

- Run as a non-root user. The container image already does
- Mount configuration read-only
- Keep `credentials.yaml` at mode 0600, or pass secrets through environment
  variables instead
- Give each token the minimum scope needed to read a version string. Most
  products expose their version to an unprivileged account, and several expose
  it with no authentication at all
