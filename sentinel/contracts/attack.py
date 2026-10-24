"""ATT&CK technique names and attack-chain stages. IDs come from the spec: ASSUMED current."""

# technique id -> (name, stage). Stage order is the plausible attack progression:
# 1 discovery, 2 credential access, 3 command and control / exfiltration.
TECHNIQUES: dict[str, tuple[str, int]] = {
    "T1046": ("Network Service Discovery", 1),
    "T1110": ("Brute Force", 2),
    "T1071.001": ("Application Layer Protocol: Web Protocols", 3),
    "T1071.004": ("Application Layer Protocol: DNS", 3),
    "T1041": ("Exfiltration Over C2 Channel", 3),
    "T1557.002": ("Adversary-in-the-Middle: ARP Cache Poisoning", 1),
    # Not ATT&CK: the statistical detector only knows "unusual", so it has no stage (0).
    "SENT001": ("Unusual behaviour (statistical, not an ATT&CK technique)", 0),
}
