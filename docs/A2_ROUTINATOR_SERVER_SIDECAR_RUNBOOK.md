# A2 Routinator Server Sidecar Runbook

This runbook describes how to test a local Routinator HTTP sidecar on a probe
node without replacing the current live MSAL cron.

## Purpose

A2 tests whether a long-running Routinator server can refresh in the background
and serve live VRPs over HTTP for:

```bash
probe/export_routinator_live_snapshot.py --capture-mode http
```

The sidecar test is intentionally isolated. It writes acceptance output under:

```text
data/probe/a2_routinator_server/
```

It does not change A/B/D/E1/E2/E3/E4/E5 scripts, does not modify cron, and does
not install a systemd service.

## Why It Does Not Replace The Current Cron

The current production path still uses the existing hourly live MSAL cycle. A2
is only a readiness test for a future switch to HTTP mode. The switch should not
happen until the sidecar passes repeatedly and E3 cron health remains stable
while the sidecar is running.

The sidecar changes the freshness model from per-command capture to background
refresh plus HTTP readout. That needs separate operational confidence before it
is used by the main cron.

## Start

From the repository root on CD2:

```bash
chmod +x scripts/runtime/test_routinator_server_http_sidecar.sh

scripts/runtime/test_routinator_server_http_sidecar.sh \
  --http-port 28114 \
  --max-wait-sec 2400
```

Defaults:

- HTTP bind address: `127.0.0.1:28114`
- refresh interval: `600` seconds
- Python: `/home/zhangxiaohui/installers/ENTER/envs/s3-radar/bin/python`
- Routinator: `/home/zhangxiaohui/.cargo/bin/routinator`
- acceptance file:
  `data/probe/a2_routinator_server/checks/A2_ROUTINATOR_SERVER_HTTP_ACCEPTANCE.txt`

The script starts Routinator with HTTP bound to localhost only. It does not pass
an RTR listen port by default. If the installed Routinator supports `--no-rtr`,
the script adds it automatically.

By default the script leaves the sidecar running after a successful test. To stop
it automatically after the exporter validation:

```bash
scripts/runtime/test_routinator_server_http_sidecar.sh \
  --http-port 28114 \
  --max-wait-sec 2400 \
  --stop-after-test
```

## Check

Inspect the acceptance file:

```bash
cat data/probe/a2_routinator_server/checks/A2_ROUTINATOR_SERVER_HTTP_ACCEPTANCE.txt
```

PASS requires:

- Routinator version can be read.
- The PID file is clear or stale.
- The HTTP port was free before startup.
- The server starts and listens on `127.0.0.1:<port>`.
- `/api/v1/status` becomes ready.
- The HTTP exporter exits with code zero.
- The exported VRP count is greater than zero.

Useful follow-up checks:

```bash
ss -ltnp | grep ':28114'
curl -sS http://127.0.0.1:28114/api/v1/status
python -m json.tool data/probe/a2_routinator_server/live_vrp_snapshots/probe-cd/latest_metadata.json
```

The exporter output lives under:

```text
data/probe/a2_routinator_server/live_vrp_snapshots/
```

This keeps A2 artifacts away from the E2/E3 cron run directories.

## Stop

If the test left the sidecar running:

```bash
kill "$(cat data/probe/a2_routinator_server/routinator_http_sidecar_28114.pid)"
rm -f data/probe/a2_routinator_server/routinator_http_sidecar_28114.pid
```

Verify the port is closed:

```bash
ss -ltnp | grep ':28114' || true
```

If the process has already exited, remove the stale PID file and inspect:

```bash
tail -n 100 data/probe/a2_routinator_server/routinator_http_sidecar_28114.log
```

## Initial Validation Ongoing

`Initial validation ongoing` means Routinator has started but has not completed
its first validation pass. During this phase `/api/v1/status` can return a
temporary not-ready response and `/json` may be unavailable or incomplete.

The sidecar script waits until `/api/v1/status` no longer contains that phrase,
up to `--max-wait-sec`. On CD2 the first run can take much longer than later
runs if the cache is cold or the network is slow.

If it times out:

- increase `--max-wait-sec`;
- check the Routinator log for repository fetch failures;
- check disk space and cache health;
- avoid switching the main exporter to HTTP mode.

## Handling 503, 404, And Timeout

`503` usually means the server is alive but not ready, often during initial
validation. Wait for readiness or increase `--max-wait-sec`.

`404` means the endpoint path may not exist for the installed Routinator version.
The sidecar waits on `/api/v1/status` because that is the A2 test contract. If
CD2 returns persistent 404, inspect:

```bash
/home/zhangxiaohui/.cargo/bin/routinator server --help
curl -sS http://127.0.0.1:28114/status
```

`timeout` means the HTTP server did not respond within the curl or exporter
timeout. Check CPU, memory, disk I/O, and the Routinator log. Do not wire this
sidecar into cron until timeouts are understood.

## CD2 Local Acceptance

```bash
cd /path/to/RP_monitor

bash -n scripts/runtime/test_routinator_server_http_sidecar.sh

scripts/runtime/test_routinator_server_http_sidecar.sh --help

scripts/runtime/test_routinator_server_http_sidecar.sh \
  --http-port 28114 \
  --max-wait-sec 2400

cat data/probe/a2_routinator_server/checks/A2_ROUTINATOR_SERVER_HTTP_ACCEPTANCE.txt

grep -q '^A2_ROUTINATOR_SERVER_HTTP=PASS$' \
  data/probe/a2_routinator_server/checks/A2_ROUTINATOR_SERVER_HTTP_ACCEPTANCE.txt

grep -q '^status_ready=true$' \
  data/probe/a2_routinator_server/checks/A2_ROUTINATOR_SERVER_HTTP_ACCEPTANCE.txt

grep -q '^exporter_exit_zero=true$' \
  data/probe/a2_routinator_server/checks/A2_ROUTINATOR_SERVER_HTTP_ACCEPTANCE.txt

grep -q '^vrp_count_gt_zero=true$' \
  data/probe/a2_routinator_server/checks/A2_ROUTINATOR_SERVER_HTTP_ACCEPTANCE.txt
```

