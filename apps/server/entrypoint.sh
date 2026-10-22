#!/usr/bin/env bash
# runs the services named in IONO_SERVICES, all four by default, so one image
# serves every container class. if any one exits the container exits with it
set -u

services="${IONO_SERVICES:-gateway ingest viewer janitor}"
pids=()

for service in $services; do
    case "$service" in
        gateway | ingest | viewer | janitor) "iono-$service" & pids+=($!) ;;
        *) echo "unknown service: $service" >&2; exit 64 ;;
    esac
done

trap 'kill -TERM "${pids[@]}" 2>/dev/null; wait "${pids[@]}"' TERM INT
wait -n
