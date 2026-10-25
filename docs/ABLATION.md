# Ablation: do the two statistical detectors earn their place?

Project rule: a model ships enabled only if an ablation shows it adds something without
hurting normal traffic. Both checks below are automated in `tests/test_ml.py` and
`tests/test_detection_matrix.py`; the numbers were measured on 2026-10-25 on **synthetic** traffic
(seeded generators in `tests/scenarios.py`). They show the mechanism works, not a field accuracy.

| Detector | Added signal | Scenario | Rules only | With the model |
|---|---|---|---|---|
| DNS n-gram (`ml/ngram.py`) | character-trigram surprisal of DNS names as a 5th signal | slow tunnel: 10 queries per 5 min, 20-char base32 labels (under the length, volume and TXT thresholds) | **missed** (1 signal: entropy 3.88) | **caught** (2 signals: entropy + surprisal 5.69 bits/char) |
| Isolation Forest (`ml/iforest.py`, `detect/behavior.py`) | "unusual" device behaviour vs the network's own recent traffic | 20 s bulk upload (864 KB per 10 s, one long connection) after 40 min of normal browsing by 3 devices | **missed** (no rule covers volume) | **caught** (a LOW/MEDIUM "unusual" alert on the uploading device, `bytes_out` 263x above anything in the baseline, and one on the receiving device) |

Normal traffic must not alert (same tests): 12 seeded benign networks (8 devices browsing,
polling shared services, refused connections, hashed CDN names, 40 minutes each), the lookalike
cases, and 1 hour of ordinary browsing for the forest alone. All raise nothing with both models on.

## What was found while measuring (and changed)

- A plain Isolation Forest **did** raise false alarms on the benign networks: repetitive, small
  data makes ordinary values look isolated. Fix: an alert additionally needs a count or volume
  more than double (and above a floor) anything in the baseline. With that guard the forest score
  threshold could be modest (0.6; with 50 trees and 128-row samples the forest score of a one-feature outlier among 13 features is only about 0.6 to 0.7).
- Anomalous vectors are not added to the baseline, so a long upload keeps alerting instead of
  becoming "normal" (tested).
- While a named attack (scan, brute force, beacon, tunnel) is active on a device, the vague
  "unusual" alert for it is suppressed: it would only add noise and hide the specific explanation.
- The forest says only "unusual", never an attack: its technique id is `RVN001` (not ATT&CK, no
  attack-chain stage), and its severity is capped so it never outranks a named detection.

## Limits (be honest about these)

- The n-gram model is trained on a small built-in seed (`ml/corpus.py`, about 500 common words and
  service names). Legitimate random-looking names (CDN hashes, some tracking domains) score high
  too; the existing "queried by several devices" and `dns_ignore_domains` filters, plus the rule
  that two independent signals must agree, are what keep these quiet. Entropy and surprisal are
  correlated, so they are not fully independent evidence.
- The forest needs a warm-up (`if_min_samples`, 200 active device-windows, roughly 35 minutes for
  one busy device) and learns whatever the network does in that time. If an attack is already
  running during warm-up, it becomes part of "normal".
- Its false-alarm rate on real networks is UNKNOWN. Both models are switchable
  (`[detection.ml]` `ngram_dns`, `isolation_forest`); see H-12 in `docs/HUMAN_VERIFICATION.md`.
- Pure Python, no numeric library: fine for tens of devices, not for thousands.

## Configuration reference

Both statistical detectors can be configured in `~/.raven/config.toml` under `[detection.ml]`:

```toml
[detection.ml]
ngram_dns = true            # character n-gram surprisal signal for DNS tunnels
isolation_forest = true     # Isolation Forest volume outlier detector
if_threshold = 0.6          # anomaly score threshold (0.0 to 1.0)
if_min_samples = 200        # warm-up window count before forest activates (~35 min)
```

See [README.md](../README.md#configuration-and-data) and [DECISIONS.md](DECISIONS.md) for architectural context and design rationale.
