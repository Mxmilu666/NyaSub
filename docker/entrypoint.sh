#!/bin/sh
set -e

DATA_DIR="${APP_DATA_DIR:-/data}"
mkdir -p "$DATA_DIR"
# Named volumes are created as root. Fix ownership once, then drop privileges.
chown -R nyasub:nyasub "$DATA_DIR"

exec su-exec nyasub:nyasub /usr/local/bin/nyasub
