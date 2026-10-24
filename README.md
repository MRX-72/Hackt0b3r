# Sentinel

Small-network anomaly detector. Spec: `SENTINEL_PROJECT.md` (split in `docs/spec/`). Status: `docs/STATE.md`.

## Setup
```
make bootstrap                 # uv sync, Python 3.13
$EDITOR secrets.env            # webhook URLs / bot token (gitignored; must be chmod 600)
$EDITOR config.toml            # enable notify channels and the LLM
uv run sentinel doctor
```

## Use
```
uv run sentinel replay capture.pcap                  # detect from a pcap, traffic hidden
uv run sentinel replay capture.pcap --show-traffic   # also print every packet event
uv run sentinel replay capture.pcap --notify         # also send Slack/Discord/Telegram messages
sudo uv run sentinel watch --iface bridge100 --show-traffic   # live (interim tcpdump source)
uv run sentinel incidents                            # stored incidents
uv run sentinel notify test slack                    # discord | telegram
uv run sentinel llm test                             # needs [llm] enabled and a running server
```
`--json` on any command prints JSON lines. `[cli] show_traffic` in `config.toml` sets the default;
`--show-traffic` / `--no-traffic` override it per run.

## LLM summaries (any model)
Detection never uses an LLM. Summaries are written by a local model when `[llm] enabled = true`, and
by built-in templates otherwise or when the model's text fails the faithfulness checks.
- Ollama: `runtime = "ollama"`, `base_url = "http://127.0.0.1:11434"`, `model = "<name from ollama list>"`.
- llama.cpp: start `llama-server -m model.gguf --port 8080`, then `runtime = "openai"`,
  `base_url = "http://127.0.0.1:8080"`. Any other OpenAI-compatible server works the same way.
If the server needs a key, put `LLM_API_KEY=` in `secrets.env`.

## Checks
`make check` runs format, lint, strict types, tests (90% coverage floor), the security test group,
dead-code and dependency checks, and the architecture (import direction) test.
