# FACTS
Labels: VERIFIED (ran it / read source, cite) · ASSUMED · UNKNOWN. Update rows as facts are confirmed.

| claim | source | date | label | who |
|---|---|---|---|---|
| Host is Apple Silicon (arm64), macOS 26.3 | `uname -m`, `sw_vers -productVersion` | 2026-10-24 | VERIFIED | claude |
| Default python3 is 3.15.0; 3.12, 3.13, 3.14 also installed | `uv python list --only-installed` | 2026-10-24 | VERIFIED | claude |
| onnxruntime 1.31.0 has no cp315 wheel (has cp311-cp314) | `uv pip install --dry-run onnxruntime` on 3.15 | 2026-10-24 | VERIFIED | claude |
| numpy, scikit-learn, scapy, dpkt, fastapi, uvicorn, pydantic, river, lightgbm, xgboost, ruff, mypy, pytest, vulture, hypothesis have binary wheels on 3.15 (resolve only; not installed or smoke-tested) | `uv pip install --dry-run --only-binary :all:` | 2026-10-24 | VERIFIED (resolution only) | claude |
| hdbscan has no binary wheel on 3.15 | same dry-run | 2026-10-24 | VERIFIED | claude |
| node, npx, mmdc, tcpdump, pfctl, uv, git, make present; ollama NOT installed | `command -v` | 2026-10-24 | VERIFIED | claude |
| mmdc cannot render: puppeteer Chrome cache dirs are empty and download failed | `mmdc` error, `npx puppeteer browsers install` failed | 2026-10-24 | VERIFIED | claude |
| Diagrams parse/render with `termaid` (a Mermaid-subset renderer, NOT the official mermaid parser) | `termaid <file>` exit 0 for all 12 | 2026-10-24 | VERIFIED (weaker than mmdc) | claude |
| Installed `cactus-needle` 3.2.8 CLI exposes "Needle 3" (JAX, `needle run`), not "Needle 2" as the spec says | `.venv/bin/needle --help`, `pip list` | 2026-10-24 | VERIFIED; packaging/behavior of Needle for our use UNKNOWN | claude |
| Internet Sharing bridge is `bridge100`, subnet 192.168.2.0/24 | spec only | | ASSUMED; spike_bridge.sh | |
| Internet Sharing clients can reach each other | spec only | | UNKNOWN; HUMAN_VERIFICATION H-02 | |
| tcpdump on bridge100 sees client traffic | spec only | | UNKNOWN; H-03 | |
| pf anchor can be loaded/removed without breaking Internet Sharing | spec only | | UNKNOWN; H-04 | |
| Gemma 4 E2B tag/size available via Ollama | spec says "verified"; not checked here, Ollama absent | | ASSUMED | |
| EmbeddingGemma license terms | spec says not stated | | UNKNOWN | |
| Prompt Guard 2 availability and license | spec | | UNKNOWN | |
| Chronos-Bolt / TinyTimeMixer packaging and license | spec | | UNKNOWN | |
| ATT&CK IDs T1046, T1110, T1071.004, T1071.001, T1041, T1557.002, T1021 are current | spec | | ASSUMED; check attack.mitre.org before UI use | |
| Slack/Discord/Telegram webhook payload formats and limits | spec | | UNKNOWN; read official docs at notify stage | |
| Keychain access method from Python | spec | | UNKNOWN | |
| Slack incoming webhook: POST JSON to the webhook URL, `text` required, optional Block Kit `blocks`; 200 + body `ok`; 400/403/404 on errors (`invalid_payload`, `no_text`, `no_service`...); channel/username not overridable | https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/ (WebFetch) | 2026-10-24 | VERIFIED | claude |
| Slack rate limit for webhooks and how to stop `<!channel>` mention parsing | not on that page. Plan: escape `& < >` as `&amp; &lt; &gt;` in all untrusted text | 2026-10-24 | UNKNOWN (escape rule ASSUMED from Slack formatting convention) | claude |
| Discord Execute Webhook: `POST /webhooks/{id}/{token}`, JSON `content` (<=2000 chars), `embeds` (<=10), `username`, `allowed_mentions`; 204 on success (wait=false) | https://docs.discord.com/developers/resources/webhook (WebFetch) | 2026-10-24 | VERIFIED | claude |
| Discord `allowed_mentions: {"parse": []}` disables all mention parsing; 429 `retry_after` handling | field exists per docs; exact semantics and 429 body not on the fetched section | 2026-10-24 | ASSUMED | claude |
| Telegram `sendMessage`: `https://api.telegram.org/bot<token>/sendMessage`, JSON body, required `chat_id`, `text` (1-4096 chars); `parse_mode` HTML requires escaping `<`, `>`, `&`; response `{ok, result|description, error_code, parameters.retry_after}` | https://core.telegram.org/bots/api (WebFetch, sendMessage + ResponseParameters) | 2026-10-24 | VERIFIED | claude |
| Telegram `link_preview_options` field shape | not read | 2026-10-24 | UNKNOWN; we send plain text with `parse_mode` HTML and no links | claude |
| Ollama `POST /api/chat`: `model`, `messages[{role,content}]`, `stream:false`, `format` = `"json"` or a JSON schema, `options`, `keep_alive`; reply text in `message.content`; `GET /api/tags` lists models | https://github.com/ollama/ollama/blob/main/docs/api.md (WebFetch) | 2026-10-24 | VERIFIED | claude |
| llama.cpp `llama-server`: OpenAI-compatible `/v1/chat/completions`; `response_format: {"type":"json_schema","schema":{...}}` for constrained JSON; `GET /health` (200 `{"status":"ok"}`, 503 loading); API key as `Authorization: Bearer`; README says default `127.0.0.1:9931` (older docs used 8080: base_url is configurable) | https://raw.githubusercontent.com/ggml-org/llama.cpp/master/tools/server/README.md (WebFetch; page itself says its json_schema example has a typo) | 2026-10-24 | VERIFIED (docs only; no server run here) | claude |
| Ollama / llama-server real behaviour on this Mac | not run; ollama and llama-server not installed | 2026-10-24 | UNKNOWN; H-06 | |
