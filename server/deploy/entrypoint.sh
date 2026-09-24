#!/bin/sh
# Container entrypoint. Needs `--cgroupns=private` and, for this script only, SYS_ADMIN (the remount;
# on AppArmor hosts also `--security-opt apparmor=unconfined`), CHOWN, SETUID and SETGID: it
# remounts the container's private cgroup namespace writable and hands it to the unprivileged
# `templar` user (cgroup delegation), then drops every capability and starts the server, which
# (with `cgroup_root = "self"`) runs each step in its own sibling group (spec §9, PS-14).
set -eu
mount -o remount,rw /sys/fs/cgroup
# cgroup v2 enables controllers for children only of a group with no member processes: move every
# process (the init, this script) into a `server` leaf; the server runs its steps in siblings.
mkdir -p /sys/fs/cgroup/server
for pid in $(cat /sys/fs/cgroup/cgroup.procs); do echo "$pid" > /sys/fs/cgroup/server/cgroup.procs 2>/dev/null || true; done
chown -R templar:templar /sys/fs/cgroup/server
for f in /sys/fs/cgroup /sys/fs/cgroup/cgroup.procs /sys/fs/cgroup/cgroup.subtree_control /sys/fs/cgroup/cgroup.threads; do
  chown templar:templar "$f"
done
# The data directory belongs to `templar` (the image creates it; a named volume copies it); the
# server creates its job directory there itself.
exec setpriv --reuid=templar --regid=templar --init-groups --inh-caps=-all --bounding-set=-all --no-new-privs \
  /usr/local/bin/templar-prover serve "${TEMPLAR_CONFIG:-/etc/templar/prover.toml}"
