#!/bin/sh
# H-01: prints PASS if bridge100 exists with a 192.168.2.x address. Read-only.
if ifconfig bridge100 2>/dev/null | grep -q 'inet 192\.168\.2\.'; then
  echo "PASS bridge100 has 192.168.2.x"
else
  echo "FAIL bridge100 missing or different subnet; interfaces: $(ifconfig -l)"
fi
