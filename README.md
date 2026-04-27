

本工程实现：

1. 三地 probe 按 PP 轮询 RRDP `notification.xml`
2. 生成并上报 `Level1Record`
3. Collector 使用 SQLite 持久化 Level-1
4. Collector 自动聚合 `E3-1` / `E3-2`
5. Probe 缓存并响应最小 Level-2：
   - `notif_refs`
   - `path_evidence`
6. 预留 Routinator 适配层，默认关闭

## 目录

```text
collector/
probe/
shared/
rp_adapters/
config/
scripts/
```

## 启动

### 成都 collector

```bash
cd ~/s3_stage1_v4_code
bash scripts/bootstrap_conda.sh s3-radar
bash scripts/run_collector.sh config/collector.yaml
```

### 北京 probe

```bash
cd ~/s3_stage1_v4_code
bash scripts/bootstrap_conda.sh s3-radar
bash scripts/run_probe.sh config/probe_bj.yaml
```

### 成都 probe

```bash
bash scripts/run_probe.sh config/probe_cd.yaml
```

### 新加坡 probe

```bash
bash scripts/run_probe.sh config/probe_sg.yaml
```

## 验证

```bash
curl http://47.108.137.128:28081/api/v1/health
curl http://166.111.121.63:28089/api/v1/health
curl http://47.108.137.128:28089/api/v1/health
curl http://8.219.129.95:28089/api/v1/health
```

## 查看最新 Level-1

```bash
curl 'http://47.108.137.128:28081/api/v1/level1/latest?pp_id=arin-rrdp' | python -m json.tool
```

## 查看事件

```bash
curl 'http://47.108.137.128:28081/api/v1/events?limit=20' | python -m json.tool
```

## 手动触发最小 Level-2

### notif_refs

```bash
curl -X POST http://47.108.137.128:28081/api/v1/l2/request \
  -H 'Content-Type: application/json' \
  -d '{"event_id":"evt-manual-1","pp_id":"arin-rrdp","request_type":"notif_refs"}'
```

### path_evidence

```bash
curl -X POST http://47.108.137.128:28081/api/v1/l2/request \
  -H 'Content-Type: application/json' \
  -d '{"event_id":"evt-manual-2","pp_id":"arin-rrdp","request_type":"path_evidence"}'
```

## 当前边界

本版只实现第一阶段最小 Level-2，不实现：

1. `object_set_root` 自动构建
2. snapshot/delta 全量对象层取证
3. 输出层 `vrp_digest/validated_object_root` 自动采集
4. Routinator 自动联动抓取


## Auto L2 trigger defaults

Collector can now auto-trigger L2 for E3-1/E3-2. Default policy is conservative:
- E3-1 triggers notif_refs only when serial_gap >= 3 or session divergence is observed, and skew <= 120s.
- E3-2 triggers path_evidence when at least one probe fails and at least one success probe exists; notif_refs is added when there are at least 2 success probes for comparison.

## Event status/confidence backfill from L2

Collector will backfill `event.status` / `event.confidence` after L2 actions:

- After a successful L2 dispatch: `status=l2_dispatched`
- If dispatch is partially failed: `status=l2_dispatch_partial`
- When L2 evidence is ingested (`notif_refs` or `path_evidence` with `event_id`): `status=l2_evidence_received`
- Each ingested evidence bumps `confidence` one step: `low -> medium -> high`


## Routinator adapter

This stage-1 code skeleton now includes a minimal Routinator adapter with three probe-local collection methods:

- `collect_cycle_metadata()`
- `collect_repository_status()`
- `collect_output_summary()`

When `routinator.enabled: true` is set in a probe config, the probe will periodically collect these three views and expose them through:

- `GET /api/v1/rp/cycle-metadata`
- `GET /api/v1/rp/repository-status`
- `GET /api/v1/rp/output-summary`

These endpoints are probe-local scaffolding only in stage 1. They are intentionally not part of the collector ingestion path yet.


## Validator samples and evidence pack

Collector now ingests Routinator minimal adapter samples via:
- /api/v1/ingest/rp/cycle-metadata
- /api/v1/ingest/rp/repository-status
- /api/v1/ingest/rp/output-summary

Evidence packs can be queried via:
- /api/v1/events/{event_id}/evidence-pack


## Automatic attribution from Routinator samples

Collector evidence packs now derive `candidate_causes`, `evidence_basis`, and `remediation` from Level-1/L2 plus Routinator cycle/repository/output samples. A dedicated endpoint is available at `/api/v1/events/{event_id}/remediation`.
