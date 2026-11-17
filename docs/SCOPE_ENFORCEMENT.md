# Scope Enforcement

Default policy: localhost lab (`127.0.0.1`, `localhost`, `::1`, `127.0.0.0/8`).

Rejected:
- Out-of-allowlist hosts
- Integer-form IP literals
- Hex-form IP literals

Active scans require an authorized target. Dashboard cannot run arbitrary shell commands.
