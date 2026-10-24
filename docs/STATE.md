# STATE
Last updated: 2026-10-24

## Stage
Stage 1 (core). Gate 0 closed 2026-10-24 (diagrams validated with termaid only). Gate 1 not reached.

## Done
- Stage 0 (see git log) plus gap closure: contracts package + JSON Schema export test, security marker group, 90% coverage floor.
- Component 1/13 storage: done.
- Component 2/13 flow model + parser: done.

## In progress
- Nothing. Next: component 3, replay source (pcap -> parser -> storage via the real pipeline path). Needs a Scapy-or-struct pcap fixture generator with labels.

## Blockers
- None.

## Done reports
| component | commit | requirements | tests added | make check | open issues | labels |
|---|---|---|---|---|---|---|
| 1 storage | see git log | R-STO-001/003, R-STO-002 (partial), R-DET-009 (partial), R-PRC-001 (partial) | 22 total in suite (12 storage, 7 contracts, 3 arch) | green, coverage 98% | not yet wired into a pipeline (none exists); migration tested on SQLite 3.54.1 only | SQLite 3.54.1 VERIFIED; behavior under concurrent writers UNKNOWN (single connection by design) |
| 2 parser | see git log | R-FLW-001, R-SAF-006 | 30 (parser) | green, coverage 98.6% | not wired into a pipeline until replay; snaplen vs DNS (D-011); mDNS-non-response branch uncovered | dpkt 1.9.8 behavior VERIFIED by tests/fuzz; real-capture frames UNVERIFIED (H-03) |

## Last make check
Green after storage; mutation checks done: removing audit triggers, dropping flow indexes, disabling foreign_keys, inverting prune cutoff each fail a test.
