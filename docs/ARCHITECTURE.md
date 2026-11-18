# Architecture

## Implemented (v0.1)

- `dragon-guard-core` (Rust, std-only): observation validation, scope policy, registry
- Python stdlib HTTP API + dashboard
- Nmap adapter: detect, scope, execute, parse XML, POST observations

## Planned

Instrument modules (SIGHT, SNIFFER, MUTATOR, PATHFINDER, TRACE, ARENA) and deeper DragonStack connectors are **not** stubbed as empty crates; they will land as working vertical slices.
