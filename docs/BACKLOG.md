# BACKLOG
Ideas that are not current work. Do not build from here without moving to REQUIREMENTS.csv.
- Parse DNS over TCP (2-byte length prefix); currently only UDP/53 is parsed.
- 802.1Q-tagged and tunneled frames are not specifically tested.
- Console: Incidents tab (acknowledge, dismiss, resolve) and a Stats tab (alerts over time, noisiest devices); both are served by data that already exists.
- Console: editable allow-lists (`trusted_ips`, ignored domains) with validation; needs the page to write `config.toml`.
- Devices: group several MACs into one named device (a laptop's Wi-Fi and Ethernet), and show hostnames from sanitised mDNS names.
- Isolation Forest: per-device baselines next to the network-wide one, and a persisted baseline so the warm-up is not repeated after a restart.
- Test-send results are not stored in the delivery log (no incident to attach them to); a "test" pseudo-incident would fix that.
- A launchd job for a background capture, with the file-ownership handback verified under a real `sudo` (H-12 style checklist item).
