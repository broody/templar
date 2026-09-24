#!/bin/sh
# Container entrypoint. Needs `--cgroupns=private` and, for this script only, CAP_SYS_ADMIN: it
# remounts the container's private cgroup namespace writable and hands it to the unprivileged
# `templar` user (cgroup delegation), then drops every capability and starts the server, which
# (with `cgroup_root = "self"`) runs each step in its own sibling group (spec §9, PS-14).
set -eu
mount -o remount,rw /sys/fs/cgroup
for f in /sys/fs/cgroup /sys/fs/cgroup/cgroup.procs /sys/fs/cgroup/cgroup.subtree_control /sys/fs/cgroup/cgroup.threads; do
  chown templar:templar "$f"
done
mkdir -p /var/lib/templar-prover/jobs
chown -R templar:templar /var/lib/templar-prover
exec setpriv --reuid=templar --regid=templar --init-groups --inh-caps=-all --bounding-set=-all --no-new-privs \
  /usr/local/bin/templar-prover serve "${TEMPLAR_CONFIG:-/etc/templar/prover.toml}"
