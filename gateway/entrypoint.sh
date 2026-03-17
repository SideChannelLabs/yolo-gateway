#!/bin/bash
set -e

# Copy host SSH keys with correct permissions (SSH requires 600)
mkdir -p /root/.ssh
if [ -d /root/.ssh-host ]; then
    cp /root/.ssh-host/* /root/.ssh/ 2>/dev/null || true
    chmod 700 /root/.ssh
    chmod 600 /root/.ssh/id_* 2>/dev/null || true
    chmod 644 /root/.ssh/*.pub 2>/dev/null || true
fi
ssh-keyscan bitbucket.org >> /root/.ssh/known_hosts 2>/dev/null
ssh-keyscan github.com >> /root/.ssh/known_hosts 2>/dev/null
chmod 644 /root/.ssh/known_hosts

# Allow git operations on workspace repos (owned by different uid)
git config --global --add safe.directory '*'
git config --global user.email "yolo-gateway@local"
git config --global user.name "YOLO Gateway"

exec "$@"
