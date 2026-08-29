#!/bin/bash
# Samples FPM pool saturation for web721. A wp-login hang that never reaches
# PHP (request queued while all workers are busy) is invisible to both the FPM
# slowlog and the in-request probe, so it has to be measured from outside.
SOCK=/run/php/web721.sock
DIR=/root/rip-hang
OUT="$DIR/pool-saturation.txt"
mkdir -p "$DIR"
recvq=$(ss -xl 2>/dev/null | awk -v s="$SOCK" '$0 ~ s {print $3; exit}')
[ -z "$recvq" ] && recvq=-1
total=0
busy=0
for p in $(pgrep -f "pool web721" 2>/dev/null); do
  total=$((total + 1))
  fds=$(ls /proc/"$p"/fd 2>/dev/null | wc -l)
  [ "$fds" -gt 6 ] && busy=$((busy + 1))
done
line="$(date -Is) recvq=$recvq workers=$total busy=$busy"
if [ "$recvq" -gt 0 ] || [ "$busy" -ge 20 ]; then
  echo "$line SATURATED" >> "$OUT"
elif [ "$(date +%M)" = "00" ]; then
  echo "$line" >> "$OUT"
fi
