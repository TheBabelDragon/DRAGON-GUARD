# DRAGON//GUARD

**DRAGON//GUARD** is the DragonStack security observation engine and scoped testing laboratory.

It is **not** a Kali wrapper dashboard. The core runs without Kali. Adapters integrate real tools when present.

## Status (v0.1)

Implemented:

- Observation schema (`dragon-guard/observation/0.1`)
- Asset registry + scope policy (default localhost lab)
- Host API + browser dashboard (Python stdlib)
- Nmap adapter (detect, authorize, scan, parse XML, POST observations)
- Scope bypass defenses (integer/hex IP forms rejected)
- Tests for schema, scope, and Nmap XML fixture parsing

Planned (not implemented as empty shells):

- Full instrument suite (SIGHT graph UI, MUTATOR, PATHFINDER, ARENA)
- Additional tool adapters (ZAP, Ghidra, Metasploit, …)
- DragonStack deep connectors (Aurora, CANtheon, ECUgate, …)

## Quick start

```bash
# Host API + dashboard (no Kali required)
PYTHONPATH=python python3 -m dragon_guard.server
# open http://127.0.0.1:7700

# Python parser tests
PYTHONPATH=python python3 tests/test_nmap_parser.py

cargo test --workspace

# Scoped nmap (requires nmap + running host)
PYTHONPATH=python python3 -m dragon_guard.adapters.nmap_adapter --target 127.0.0.1
```

## Safety

- Default scope: localhost / `127.0.0.0/8` only
- Active scans require an in-scope target
- No arbitrary command execution from the dashboard
- No autonomous exploitation

## License

MIT
