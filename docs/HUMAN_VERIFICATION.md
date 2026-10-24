# HUMAN VERIFICATION
Run these on the gateway Mac (Mac C) unless noted. Report the printed PASS/FAIL line and any output. None of these are verified yet.

| id | assumption | command | report back |
|---|---|---|---|
| H-01 | Internet Sharing creates `bridge100` on 192.168.2.0/24 | `spikes/spike_bridge.sh` | PASS/FAIL line + `ifconfig bridge100` |
| H-02 | Mac A can ping Mac B through the gateway (no client isolation) | on Mac A: `ping -c 3 <Mac B IP>` | packet loss % |
| H-03 | `tcpdump` on the bridge sees a port scan from Mac B | `sudo tcpdump -i bridge100 -c 20 'tcp[tcpflags] & tcp-syn != 0'` while running `nmap -p 1-200 <Mac A IP>` on Mac B | whether SYNs appear |
| H-04 | pf anchor loads/removes without breaking sharing | `sudo spikes/spike_pf_anchor.sh` | PASS/FAIL, and whether Mac A still has internet/DHCP after |
| H-05 | Capture throughput with ring buffer | later, after daemon exists | packets/s, CPU %, drops |
| H-06 | Ollama + Gemma 4 E2B tag, constrained JSON | `ollama list`; `ollama show <tag>` | exact tag, size |
| H-07 | Needle runs on this Mac for our schema | later, at `ask` stage | accuracy on labeled set |
| H-08 | Slack/Discord/Telegram real send | later, human supplies webhook via env/Keychain | message received? |
