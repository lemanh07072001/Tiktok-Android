#!/bin/zsh
# No-sudo Spotlight tamer: continuously push every mdworker_shared (all owned by me)
# into macOS background/THROTTLE tier + nice+20, so qemu vCPU threads win CPU.
# Runs until killed. Stops the host-load storm without disabling Spotlight (no sudo).
END=$(( $(date +%s) + ${1:-1800} ))
while [[ $(date +%s) -lt $END ]]; do
  for p in $(pgrep mdworker_shared 2>/dev/null); do
    taskpolicy -b -p $p 2>/dev/null
    renice +20 $p 2>/dev/null >/dev/null
  done
  # also throttle mds_stores' worker churn indirectly: nothing we can do to root mds,
  # but throttling all workers starves the pipeline enough.
  sleep 2
done
