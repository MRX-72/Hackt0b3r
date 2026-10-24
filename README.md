# Sentinel

Small-network anomaly detector for a gateway Mac: finds port scans, brute force, beaconing and DNS
tunnelling, explains them in plain English (templates or a local LLM), and alerts you on Slack,
Discord or Telegram.

- **How to use it: [USER_GUIDE.md](USER_GUIDE.md)** (install, CLI reference, notifications, LLM, live capture).
- Spec: `SENTINEL_PROJECT.md` (split in `docs/spec/`). Status and open items: `docs/STATE.md`.

```bash
make bootstrap
uv run python tools/make_demo_pcap.py demo.pcap
uv run sentinel replay demo.pcap --show-traffic
```

`make check` runs format, lint, strict types, tests (90% coverage floor), the security test group,
dead-code and dependency checks, and the architecture (import direction) test.
