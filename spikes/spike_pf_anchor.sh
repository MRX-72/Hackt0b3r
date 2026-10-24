#!/bin/sh
# H-04: load an empty-effect anchor "sentinel_spike", list it, remove it. Requires sudo.
# Does not touch the main ruleset. Run with Internet Sharing ON, then check a client still has connectivity.
set -e
echo "pass out quick proto tcp from 203.0.113.1 to 203.0.113.2 port 9" | pfctl -a sentinel_spike -f - 2>&1
pfctl -a sentinel_spike -sr
pfctl -a sentinel_spike -F rules
pfctl -a sentinel_spike -sr
echo "DONE: now confirm Mac A still has internet/DHCP and report PASS/FAIL"
