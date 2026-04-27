from __future__ import annotations

import json
from typing import Any


def _safe_float(v: Any) -> float | None:
    try:
        if v is None:
            return None
        return float(v)
    except Exception:
        return None


def _has_keywords(obj: Any, keywords: tuple[str, ...]) -> bool:
    text = json.dumps(obj, ensure_ascii=False).lower()
    return any(k in text for k in keywords)


def _collect_fetch_error_types(pack: dict[str, Any]) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in pack.get('level1_records', []) or []:
        fet = row.get('fetch_error_type') or 'none'
        if fet != 'none':
            out[fet] = out.get(fet, 0) + 1
    for row in pack.get('path_evidence', []) or []:
        fet = row.get('fetch_error_type') or 'none'
        if fet != 'none':
            out[fet] = out.get(fet, 0) + 1
    return out


def _derive_validator_evidence(pack: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    causes: list[str] = []
    basis: list[str] = []
    advice: list[str] = []

    cycle = pack.get('validator_cycle_metadata', []) or []
    repo = pack.get('validator_repository_status', []) or []
    out = pack.get('validator_output_summary', []) or []

    if cycle:
        basis.append('validator_cycle_metadata_present')
        lag_probes = []
        err_probes = []
        for rec in cycle:
            if rec.get('last_error') not in (None, '', {}, []):
                err_probes.append(rec.get('probe_id'))
            if rec.get('last_update_done') in (None, ''):
                lag_probes.append(rec.get('probe_id'))
        if err_probes:
            causes.append('validator_update_error_observed')
            basis.append('validator_cycle_last_error_present')
            advice.append('核查这些探针上的 Routinator 最近一次更新错误与 repository 级状态。')
        if lag_probes:
            causes.append('validator_update_lag_or_incomplete_cycle')
            basis.append('validator_cycle_last_update_done_missing')
            advice.append('检查 validator 更新周期是否尚未完成，并避免将未完成周期直接解释为视图冲突。')

    if repo:
        basis.append('validator_repository_status_present')
        bad_repo_probes = []
        for rec in repo:
            payload = {'repositories': rec.get('repositories'), 'raw': rec.get('raw')}
            if _has_keywords(payload, ('error', 'failed', 'failure', 'stale', 'timeout', 'unreachable', 'invalid')):
                bad_repo_probes.append(rec.get('probe_id'))
        if bad_repo_probes:
            causes.append('validator_repository_sync_issue')
            basis.append('validator_repository_status_contains_failure_signals')
            advice.append('对异常探针比对 validator repository 状态、RRDP/rsync 可达性与本地网络路径。')

    if out:
        basis.append('validator_output_summary_present')
        vrps = {}
        for rec in out:
            val = _safe_float(rec.get('vrp_count'))
            if val is not None:
                vrps[rec.get('probe_id')] = val
        if len(vrps) >= 2:
            uniq = sorted(set(vrps.values()))
            if len(uniq) == 1:
                basis.append('validator_output_consistent_by_vrp_count')
            else:
                causes.append('validator_output_divergence_candidate')
                basis.append('validator_output_vrp_count_diverges')
                advice.append('比较不同探针的 validator 指纹、策略例外和本地缓存状态，确认是否存在输出层差异。')
    return causes, basis, advice


def derive_event_enrichment(pack: dict[str, Any]) -> dict[str, Any]:
    event = pack.get('event', {}) or {}
    event_type = event.get('event_type')
    summary = event.get('summary', {}) or {}
    statuses = summary.get('statuses', {}) or {}
    serial_gap = int(summary.get('serial_gap') or 0)
    session_ids = summary.get('session_ids', []) or []
    causes: list[str] = []
    basis: list[str] = []
    actions: list[str] = []

    if pack.get('level1_records'):
        basis.append('level1_window_records')
    if pack.get('notif_refs'):
        basis.append('l2_notif_refs_present')
    if pack.get('path_evidence'):
        basis.append('l2_path_evidence_present')

    fetch_errors = _collect_fetch_error_types(pack)
    if event_type == 'E3-1':
        if len(session_ids) == 1 and serial_gap <= 5:
            causes.append('fast_upstream_updates_or_poll_skew')
            basis.append('single_session_with_limited_serial_gap')
            actions.append('继续观察该 PP 的连续窗口，必要时适度增大轮询密度或缩小聚合窗口以区分时间错位。')
        if len(session_ids) > 1:
            causes.append('session_divergence_candidate')
            basis.append('multiple_session_ids_observed')
            actions.append('优先复取 notification 并核查 session reset、发布流程异常或仓库重建。')
        if pack.get('notif_refs'):
            actions.append('对比不同探针的 snapshot_ref 与 delta_refs，判断是否只是版本推进差异。')
    elif event_type == 'E3-2':
        if statuses:
            failed = [p for p, s in statuses.items() if s != 'success']
            succ = [p for p, s in statuses.items() if s == 'success']
            if failed and succ:
                basis.append('failed_probe_has_success_controls')
        if fetch_errors.get('dns_failure', 0) > 0:
            causes.append('probe_path_dns_failure')
            actions.append('核查失败探针的解析器、DNS TTL、返回地址集合及其与成功探针的差异。')
        if fetch_errors.get('tcp_connect_failure', 0) > 0:
            causes.append('probe_path_tcp_connect_failure')
            actions.append('检查失败探针到 PP/collector 的 TCP 可达性、ACL 与目标端口开放状态。')
        if fetch_errors.get('tls_failure', 0) > 0:
            causes.append('probe_path_tls_failure')
            actions.append('复核失败探针的 TLS 握手、证书校验和中间件代理行为。')
        if fetch_errors.get('http_status_failure', 0) > 0 or fetch_errors.get('http_protocol_failure', 0) > 0:
            causes.append('http_layer_fetch_failure')
            actions.append('检查 PP 返回状态码、协议错误和缓存/代理行为。')
        if fetch_errors.get('timeout', 0) > 0:
            causes.append('transient_timeout_or_stalling')
            actions.append('持续观测失败探针的 timeout 是否集中出现，并结合路径证据判断是否为 stalling。')
        if not causes:
            causes.append('single_probe_fetch_anomaly')
            actions.append('先将其视为局部采集异常，继续补充 path_evidence 与 validator repository 状态。')

    v_causes, v_basis, v_advice = _derive_validator_evidence(pack)
    for x in v_causes:
        if x not in causes:
            causes.append(x)
    for x in v_basis:
        if x not in basis:
            basis.append(x)
    for x in v_advice:
        if x not in actions:
            actions.append(x)

    # downgrade severe interpretation when validator output appears consistent
    if 'validator_output_consistent_by_vrp_count' in basis and event_type in ('E3-1', 'E3-2'):
        basis.append('no_output_layer_divergence_evidence_yet')
        actions.append('当前可优先解释为仓库宣告层/路径层异常，暂不自动升级为输出层分化事件。')

    advice_level = 'observe'
    if any(c in causes for c in ('validator_output_divergence_candidate', 'session_divergence_candidate')):
        advice_level = 'investigate'
    if event_type == 'E3-2' and any(c.endswith('failure') or 'timeout' in c for c in causes):
        advice_level = 'triage'

    return {
        'candidate_causes': causes,
        'evidence_basis': basis,
        'remediation': {
            'event_id': event.get('event_id'),
            'advice_level': advice_level,
            'recommended_actions': actions,
            'evidence_basis': basis,
            'candidate_causes': causes,
        },
    }
