# PART 5: MODEL ROSTER AND ML ARCHITECTURE


Extends Part 3 (Base Specification) and Part 4 (V2 Addendum). Where they conflict on anything about models, **this part wins**.

**Instructions for Claude Code:** Build the model layer behind a registry (section 3). Every model must be swappable by config, individually disable-able, and must earn its place through the ablation in section 9. Items marked **verify** (name, size, license, availability) must be checked on the real machine or official source before use. Do not download models at demo time; pre-fetch and pin checksums.

---

## 1. Design principle

Right model for the job, smallest model that works. Most of the detection stack should **not** be an LLM.

- Microsecond rules and streaming statistics catch the obvious.
- Small classical and neural specialists handle narrow signals (DNS names, traffic shape, device type).
- Embedding models handle similarity and retrieval.
- Only the final step, explaining an incident in plain English, uses a language model.
- LLMs never make detection or enforcement decisions (unchanged from earlier specs).

A cascade keeps CPU free on the gateway Mac, which is also doing packet capture.

---

## 2. Model roster

### Tier A: classical and streaming ML (no downloads, CPU, milliseconds)

| Role | Model | Notes |
|---|---|---|
| Per-device anomaly baseline | **Isolation Forest** (scikit-learn) | Already in spec. Per device, refit periodically. Return top contributing features. |
| Streaming anomaly score | **Half-Space Trees** or similar online detector (River library, **verify**) | Learns continuously with no refit step. Good for the Learning mode day-one story. |
| Device type classifier | **Gradient-boosted trees** (LightGBM or XGBoost, **verify** which installs cleanly on macOS) | Supervised: features are ports used, service mix, volume, vendor/OUI class, hostname tokens. Labels come from lab devices plus admin corrections. Outputs calibrated probabilities (this is the "confidence"). |
| Peer clustering when types are unknown | **HDBSCAN** or k-means on behavior vectors | Finds natural device groups, so peer comparison works even with no labels. |
| Alert priority ranker | **Gradient-boosted trees** trained on admin feedback (thumbs up/down, dismissed, acted-on) | Cold start: heuristic score (severity x confidence). Switch to the learned ranker only after a minimum number of labeled alerts (config, default 30), and show which one is active. |
| Beaconing detector | **Periodicity analysis** (autocorrelation or FFT over inter-arrival times) | Not a neural net and shouldn't be. Fast and explainable ("connects every 30.2 s, jitter 3%"). |
| Small autoencoder | Tiny MLP autoencoder (under about 100K parameters, PyTorch, exported to ONNX) on per-host feature vectors | Reconstruction error as a second opinion next to Isolation Forest. Keep only if the ablation shows it adds value. |

### Tier B: small neural specialists

| Role | Model | Notes |
|---|---|---|
| DNS tunneling and DGA detection | **Character-level model**: start with char n-gram + logistic regression as the baseline, then a **tiny char-CNN or GRU** (about 100K to 1M parameters) exported to ONNX | Input is the domain name processed inside the detector, never shown to an LLM. Combine with the entropy, length, TXT-share and unique-subdomain rules as an ensemble. Training data section 8. |
| Traffic-volume forecasting | **Tiny time-series foundation model**: Chronos-Bolt (tiny/mini variants exist) or IBM TinyTimeMixer (roughly 1M parameters), **verify names, sizes, licenses** | Forecast each host's bytes/connections per window and flag large residuals. Zero-shot, so it works before a baseline exists. **Must beat a simple seasonal-average baseline in the eval or be dropped.** |
| Prompt-injection guard | **Prompt Guard 2 (86M)** from Meta, with a smaller 22M variant if available, **verify availability and license terms (Llama community license)** | Defense in depth. Run on any free-text that reaches an LLM: the admin's chat questions, rule descriptions, imported documents. Network-derived strings are already excluded from LLM input by the sanitizer, and this is a second layer. |
| Embeddings | **EmbeddingGemma (308M parameters, under 200MB RAM with quantization, 768 dimensions truncatable to 512/256/128 via Matryoshka, 2K token context; verified from Google's announcement)**. Fallback candidates to benchmark: bge-small, all-MiniLM-L6, Qwen3-Embedding-0.6B, nomic-embed (**verify each**) | Only embed text the system or admin authored (sanitized incident summaries, runbooks, rule text, ATT&CK descriptions). See section 5. **Verify the EmbeddingGemma license** before using it; the announcement page didn't state it. |
| Reranker (P1) | Small cross-encoder (MiniLM-class reranker, **verify**) | Reorders retrieved runbook passages before they go to the explanation model. |
| Tool-calling for `sentinel ask` | **Needle 2** (Cactus; 45M parameters, 14MB; verified) | Turns "show me unknown devices from the last hour" into a CLI/API call. See section 6. |

### Tier C: language models (explanation and chat only)

| Slot | Default | Candidates to benchmark (**verify names, sizes, licenses**) |
|---|---|---|
| `explain` (incident text, structured JSON) | **Gemma 4 E2B** (2.3B effective / 5.1B with embeddings, 128K context, Apache 2.0, native function calling; verified) | Qwen3 small models (0.6B to 4B), SmolLM3 3B, Granite small models, Phi-4-mini |
| `explain-lite` (very short rewrites, digest bullets) | A sub-1B model | Qwen3 0.6B class, other sub-1B instruct models |
| `chat` (answering admin questions about the network, summarizing a day) | Gemma 4 E2B, or E4B if RAM allows | Experimental: a 1-bit Bonsai LLM (PrismML; a 1-bit 27B build around 3.9 GB exists, **verify current builds and hardware requirements**) |
| Optional escalation | None by default | An API model, **off by default**, disabled in Air-gapped mode, only for user-initiated "explain deeper", and only with sanitized structured input |

Choose by benchmark (section 9), not by reputation. Keep the slot names stable so models can be swapped without code changes.

---

## 3. Model registry and runtime

`models/registry.yaml`:
```yaml
- id: dns-charcnn-v1
  role: dns_classifier
  runtime: onnx
  path: models/dns_charcnn_v1.onnx
  sha256: "<pinned>"
  license: "own"
  ram_mb: 60
  enabled: true
  load: eager            # always resident
- id: gemma4-e2b
  role: explain
  runtime: ollama        # or llama.cpp / MLX
  model: "<exact tag, verify with ollama list>"
  license: "Apache-2.0"
  ram_mb: 3500
  enabled: true
  load: lazy             # load on first incident, unload after idle N minutes
- id: embeddinggemma
  role: embed
  runtime: onnx | sentence-transformers | ollama   # pick what installs cleanly, verify
  ...
```

Requirements:
- **Runtimes:** ONNX Runtime for small neural specialists (CPU, portable); Ollama or llama.cpp (Metal) for LMs; MLX if the gateway is Apple Silicon (**verify chip**). Document which runtime serves which role.
- **RAM budget:** configurable cap for all resident models, default conservative because capture and the dashboard share the machine. The registry enforces lazy load, idle unload, and refuses to load a model that would exceed the cap (log it, don't crash).
- **Graceful degradation:** each role has a fallback. DNS model down: rules only. Embedding down: skip dedupe/RAG. LLM down: template text. Needle down: CLI-only. Detection must never depend on an LLM or embedding.
- **Latency budget per stage** (measured and shown): rules and streaming under a few ms per window, specialists tens of ms, embeddings under about 100 ms per item, LLM seconds and off the critical path (run asynchronously after the alert is raised; show "explaining..." in the UI).
- **Health:** each model reports loaded/unloaded, last used, p50/p95 latency, error count.

### Supply-chain safety (this is a security product)
- Pre-download everything before the event. No network fetches at runtime.
- Pin SHA-256 checksums in the registry and verify at load; refuse mismatches.
- Prefer safe formats: ONNX or safetensors. **Do not load pickle-based checkpoints from untrusted sources**, and never enable `trust_remote_code`.
- Record license and source URL for every model in `MODELS.md`. Do not ship a model whose license you haven't read.

---

## 4. Detection cascade

```
flow/windows
   │
   ├─► Rules (scan, brute force, DHCP, ARP, canary)              µs–ms
   ├─► Periodicity (beaconing)                                   ms
   ├─► Streaming + IsolationForest (self baseline)               ms
   ├─► Peer comparison (cluster/type, robust z-score)            ms
   ├─► DNS specialist (char model + entropy rules)               tens of ms, only on DNS events
   ├─► Traffic forecaster residuals (optional)                   tens of ms, per window
   ▼
Ensemble scorer ──► calibrated score + "model agreement" ──► Alert
   ▼
Correlation (incidents, ATT&CK) ──► Embedding dedupe / similar past incidents
   ▼
RAG (runbook passages) ──► Explanation LLM ──► Faithfulness check ──► Notify / UI
```

### Ensemble scoring
- Each detector emits a score in [0,1] plus its own evidence.
- Combine with a small calibrated model (logistic regression or the gradient-boosted ranker) or a weighted vote, with weights set by the eval.
- **Model agreement** is a confidence signal: several independent detectors flagging the same host raises confidence; one detector alone lowers it. Show agreement in the UI ("3 of 5 detectors agree").
- Calibrate scores (for example isotonic or Platt scaling on lab data) so "0.9" means roughly the same thing across detectors.
- Explainability: for tree models, show top feature contributions (SHAP if it runs fast enough, **verify**, otherwise feature importances). For others, show the numeric evidence.

---

## 5. Embedding use cases

Embeddings are used for similarity and retrieval, never for detection decisions.

1. **Incident dedupe and grouping:** embed the sanitized incident summary; cluster near-duplicates so the admin sees "12 similar incidents" as one item.
2. **"Seen before" memory:** find the most similar past incidents and how the admin resolved them (dismissed as false positive, acted on). Show "Similar to incident #31, which was dismissed as the printer firmware updater". This reduces repeat noise.
3. **RAG over runbooks:** a local folder of short playbooks (what to do about a port scan, rogue DHCP, compromised lab PC) plus ATT&CK technique descriptions. Retrieve the top passages (rerank in P1) and give them to the explanation model so suggested actions are grounded in the documents rather than invented.
4. **Natural-language search:** `sentinel ask` and the GUI search box match questions against alerts, rules and runbooks.
5. **Rule suggestion:** embed an admin's plain-language description ("alert me if a lab PC talks to anything outside college hours") and match it to rule templates (the rule text is still produced by code from a template, never by an LLM).

Safety: embed only text authored by the system or admin. Do not embed raw network strings. Retrieved passages are treated as data, and the LLM prompt tells the model they are reference material only. Embeddings and the vector index stay local (SQLite with a vector extension, or a flat NumPy index, which is plenty at this scale).

---

## 6. Natural-language interface with Needle 2

`sentinel ask "which devices are new since this morning?"` and a chat box in the GUI.

Flow:
1. Prompt Guard screens the question.
2. **Needle 2** receives the question plus a schema of **allowlisted functions** (decorated Python functions with typed args), picks a function, and fills arguments.
3. The system validates arguments against the schema (types, ranges, enums) and runs the function.
4. Results go to the `chat` LLM (or a template) for a plain-English answer, using structured data only.

Allowlist:
- **Read-only functions by default:** list_devices, list_incidents, get_incident, search_alerts, show_mode, top_talkers, explain_alert.
- **Propose-only functions:** `propose_block(device, reason)` creates a dry-run enforcement proposal that needs the normal approval path. Needle can never apply a rule, change a mode, or edit config.
- Needle should refuse unrelated requests, which is the correct behavior for an action model. If it returns no function, say "I can't do that from here" rather than guessing.
- Log every ask, chosen function and args to the audit log.
- Needle 2 outputs are untrusted input to your own code: validate everything, never `eval`, never pass arguments to a shell.

Verify Needle 2's current packaging (the README mentions a 14MB binary, Python decorators and a `needle playground` command) and that it runs on your Mac before depending on it. Fallback if it doesn't: a keyword/intent router with the same function allowlist.

---

## 7. Faithfulness and output checks for LLM text

LLM-written text can drift. Before it reaches the UI or a notification:

1. **Schema check:** output must match the JSON schema (original spec section 11).
2. **Numeric faithfulness:** every number in the text must appear in the structured evidence (allow unit conversions). Mismatch means discard and use the template.
3. **Entity check:** device names and IPs in the text must be in the allowed set for this incident.
4. **Action check:** the suggested action must come from an allowed action catalog (isolate device, re-image, check printer settings...), not free-form commands.
5. **Length and markup check:** strip markup, links and mentions.
6. On any failure, fall back to the deterministic template and increment a visible "LLM rejected" counter. Report the rejection rate in the eval.

---

## 8. Training and data

- **Never train on or ship real users' traffic.** Use lab-generated data.
- **Benign DNS:** a public popular-domains list (for example Tranco, **verify availability and terms**) plus domains from your lab's normal browsing.
- **DGA/tunnel positives:** generate with your own simple benign generators in the lab (several DGA-style algorithms, base32/base64 subdomain tunneling with random payloads to your own DNS server). Hold out entire generator families for testing, to measure generalization instead of memorization.
- **Device type labels:** your three Macs plus any phones and extra devices around; augment with synthetic profiles (printer, IoT) generated by `baseline_traffic.py` variants. Be honest that three real devices is thin. Report per-class counts and confidence, and prefer rules plus a small model over claiming a robust classifier.
- **Split by scenario or session, not randomly by row.** Random splits leak near-duplicate windows and inflate scores (the same problem that makes public IDS benchmarks look better than they are).
- **Cross-environment test:** train on one capture session, test on another day/network configuration.
- Training scripts live in `training/`, are deterministic (fixed seeds), run on CPU in minutes, and export ONNX with a recorded checksum. Small models mean a hackathon team can actually train them.
- Report model cards (`MODELS.md`): purpose, data, size, license, metrics, known failures.

---

## 9. Evaluation: every model must earn its place

Extend `eval/run_eval.py`:

- **Ablation table:** run the attack suite with each model enabled/disabled (rules only; + Isolation Forest; + peer; + DNS model; + forecaster; + ensemble). Columns: detection rate per attack, time to detect, false positives per hour, CPU %, RAM, added latency.
- **Rule of survival:** a model stays enabled by default only if it improves detection or reduces false positives enough to justify its CPU/RAM. Otherwise ship it disabled and say so honestly.
- **LLM benchmark** across the candidate models in the `explain` slot: schema-valid rate, numeric faithfulness pass rate, p50/p95 latency, RAM, and a small human rating of clarity (3 people rating 20 incidents is enough). Pick the default from the numbers.
- **Embedding benchmark:** recall@k on a small hand-labeled set (similar/not-similar incident pairs, runbook retrieval questions) across the candidate embedding models.
- **Needle benchmark:** function-selection accuracy on about 50 labeled questions, including refusals and malicious phrasing.
- **Prompt-injection suite:** poisoned hostnames, poisoned DNS names, poisoned free-text questions, poisoned runbook text. Measure how often anything gets through to LLM output, notification text or the UI. Target zero for the structured path, and report the guard model's catch rate separately.
- Results shown in a **Models** view in the GUI and written to `eval/results/`.

---

## 10. CLI and GUI additions

CLI:
```
sentinel models list                 # roles, loaded?, RAM, latency, health, license
sentinel models enable|disable <id>
sentinel models bench <role>         # run the benchmark for a role
sentinel models verify               # re-check checksums
sentinel ask "<question>"            # Needle + guard + chat
sentinel similar <incident-id>       # embedding neighbors and how they were resolved
```

GUI:
- **Models view:** each model with role, status, RAM, p50/p95 latency, enable toggle, ablation results, license and checksum status.
- **Incident detail:** show **which detectors fired** and the agreement meter, "similar past incidents", and the grounded runbook passages used.
- **Chat panel:** `ask`, showing the function Needle chose and the arguments before results (transparency builds trust).
- Badges: "LLM text", "template fallback", "rejected by faithfulness check".

---

## 11. Repository additions

```
sentinel/
  models/
    registry.py          # load, unload, RAM cap, health, checksums
    registry.yaml
    runtimes/
      onnx.py
      ollama.py
      mlx.py             # optional
  ml/
    streaming.py         # online detector
    iforest.py
    peers.py             # clustering + robust z
    devicetype.py        # gradient-boosted classifier
    ranker.py            # feedback-trained priority ranker
    periodicity.py       # beaconing
    dns_model.py         # char model inference
    forecast.py          # time-series specialist
    ensemble.py          # calibration + agreement
  nlp/
    embed.py             # embedding service + vector index
    rag.py               # runbook retrieval (+ rerank)
    guard.py             # prompt-injection classifier wrapper
    ask.py               # Needle tool-calling + allowlist + validation
    faithfulness.py      # section 7 checks
  training/
    dns_charcnn.py
    devicetype.py
    make_dns_data.py
  runbooks/              # short markdown playbooks (RAG corpus)
  MODELS.md              # model cards, licenses, sources, checksums
  eval/
    ablation.py
    bench_llm.py
    bench_embed.py
    bench_needle.py
    injection_suite.py
```

---

## 12. Priority tiers

**P0 (must work for the demo):**
- Isolation Forest + peer comparison + beaconing periodicity (Tier A core)
- DNS detection with char n-gram + logistic regression baseline (a tiny char-CNN is P1)
- Model registry with checksums, lazy load, RAM cap, template fallbacks
- `explain` LLM (Gemma 4 E2B) with schema and numeric-faithfulness checks
- Embedding model for incident dedupe and "similar past incidents"
- Needle 2 `sentinel ask` with the read-only allowlist and validation
- Ablation table for at least rules vs rules + ML
- Injection test for hostname and free-text paths

**P1:**
- Tiny char-CNN/GRU DNS model (ONNX)
- Gradient-boosted device-type classifier and feedback-trained priority ranker
- Time-series forecaster specialist
- Prompt Guard model in front of free-text
- RAG with reranker over runbooks
- LLM benchmark across candidates, embedding benchmark, Needle benchmark
- Models view in the GUI
- Small autoencoder, streaming detector, HDBSCAN peers

**P2 (roadmap):**
- Federated or cross-site learning, fine-tuning the explanation model on accepted summaries, quantization experiments with 1-bit models in the chat slot, a distilled single DNS+traffic model.

If time is tight, keep fewer models and make each one measurably useful. A two-model ablation with real numbers beats ten models with none.

---

## 13. Acceptance criteria (additions)

1. `sentinel models list` shows every enabled model with status, RAM and latency, and `verify` passes checksums.
2. Disabling any model (including all LLMs and embeddings) leaves detection working and the UI functional with fallbacks.
3. The ablation table is generated from real runs and shows at least rules-only vs rules + each enabled model.
4. The DNS specialist detects tunnel/DGA traffic from held-out generator families, with false-positive rate reported on benign domains.
5. LLM text that fails the numeric faithfulness check is replaced by the template, and the rejection rate is reported.
6. Poisoned hostname, DNS name and free-text question tests produce no change in LLM output, notifications or UI behavior.
7. `sentinel ask` maps at least 90% of a labeled question set to the correct allowlisted function (report the real number), refuses unrelated or unsafe requests, and cannot trigger enforcement without the approval flow.
8. Incident dedupe and "similar past incidents" work on replayed data and show how earlier incidents were resolved.
9. Total resident model RAM stays under the configured cap, and capture shows no increase in dropped packets while the LLM is running (measure both).
10. `MODELS.md` lists source, license and checksum for every model.

---

## 14. Pitch addition

"Sentinel isn't one big model. It's a team of small ones, each doing one job: statistics and periodicity for the obvious, a tiny DNS network for tunnels, an embedding model that remembers how you handled similar incidents, a 45-million-parameter model that turns your questions into safe commands, and a small language model that only explains what the detectors already found. Every model has to prove itself in our ablation table or it's switched off."

---

## 15. Open items to verify

- Exact Ollama tags and sizes for Gemma 4 E2B on the target machine, and whether the gateway is Apple Silicon (affects MLX and RAM).
- EmbeddingGemma license terms, and runtime packaging (ONNX, sentence-transformers or Ollama) that installs cleanly offline.
- Prompt Guard 2 availability (86M and any smaller variant) and license conditions.
- Chronos-Bolt and TinyTimeMixer packaging, license, and CPU latency. Drop them if they don't beat the seasonal baseline.
- Needle 2 install and runtime on macOS, and its accuracy on your function schema.
- LightGBM/XGBoost, River and HDBSCAN wheels for the Python version in use.
- Whether a sub-1B instruct model is good enough for `explain-lite`. Skip the slot if not.

---
