#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from typing import Any, Dict

from scripts.p3.m17.scanners.common import serials_nearby, seconds_skew, unique_nonempty


def _classify_advertised(signal: Dict[str, Any], *, window_seconds: int) -> Dict[str, Any]:
    anomaly_type = signal.get("anomaly_type")
    trig = signal.get("trigger_signals") or {}

    if anomaly_type == "A2_NOTIFICATION_DIGEST_DIVERGENCE":
        signal["temporal_skew_class"] = "not_temporal_skew"
        signal["requires_resample"] = False
        signal["severity"] = "high"
        return signal

    if anomaly_type == "A3_RRDP_VERSION_SKEW":
        sessions = trig.get("sessions") or {}
        serials = trig.get("serials") or {}
        digests = trig.get("digests") or {}
        observed = trig.get("observed_at_utc") or {}

        unique_sessions = unique_nonempty(sessions.values())
        unique_serials = unique_nonempty(serials.values())

        skew = trig.get("max_probe_time_skew_seconds")
        if skew is None:
            skew = seconds_skew(observed.values())

        same_session = len(unique_sessions) == 1
        nearby = serials_nearby(unique_serials, max_gap=10)

        if same_session and nearby and (skew is None or skew <= window_seconds):
            signal["temporal_skew_class"] = "normal_rrdp_version_skew_likely"
            signal["requires_resample"] = True
            signal["severity"] = "warning"
        else:
            signal["temporal_skew_class"] = "persistent_or_non_adjacent_rrdp_skew_suspected"
            signal["requires_resample"] = True
            signal["severity"] = "high"

        return signal

    return signal


def _classify_object(signal: Dict[str, Any]) -> Dict[str, Any]:
    anomaly_type = signal.get("anomaly_type")
    trig = signal.get("trigger_signals") or {}
    root_key = str(trig.get("root_key") or "").lower()

    if anomaly_type == "O7_OBJECT_EXPORT_MISSING_OR_STALE":
        signal["temporal_skew_class"] = "context_stale"
        signal["requires_resample"] = True
        signal["severity"] = "warning"
        return signal

    if anomaly_type == "O1_OBJECT_ROOT_DIVERGENCE":
        if root_key == "semantic_object_root":
            signal["temporal_skew_class"] = "object_semantic_root_divergent_requires_diff"
        elif root_key in {"object_set_root", "effective_object_root", "all_object_root"}:
            signal["temporal_skew_class"] = "object_root_divergent_requires_diff"
        else:
            signal["temporal_skew_class"] = "object_root_divergent_requires_diff"

        signal["requires_resample"] = True
        signal["severity"] = "high"
        return signal

    if anomaly_type == "O2_MFT_ROOT_DIVERGENCE":
        signal["temporal_skew_class"] = "manifest_version_skew_possible"
        signal["requires_resample"] = True
        signal["severity"] = "warning"
        return signal

    if anomaly_type == "O3_ROA_ROOT_DIVERGENCE":
        if "vrp_key" in root_key or "candidate_key" in root_key:
            signal["temporal_skew_class"] = "not_temporal_skew"
            signal["requires_resample"] = False
            signal["severity"] = "critical"
        else:
            signal["temporal_skew_class"] = "roa_semantic_diff_requires_mapping"
            signal["requires_resample"] = True
            signal["severity"] = "high"
        return signal

    if anomaly_type == "O4_CER_ROOT_DIVERGENCE":
        ctx = signal.get("context_summary") or {}
        diff_summary = ctx.get("diff_summary") or {}
        root_keys = diff_summary.get("root_keys") or {}

        resource_aligned = (root_keys.get("cer_resource_root") or {}).get("aligned")
        chain_aligned = (root_keys.get("cer_chain_index_root") or {}).get("aligned")

        if root_key == "cer_semantic_root" and resource_aligned is True and chain_aligned is True:
            signal["temporal_skew_class"] = "cer_semantic_diff_resource_chain_aligned"
            signal["requires_resample"] = True
            signal["severity"] = "warning"
        else:
            signal["temporal_skew_class"] = "cer_semantic_or_resource_diff_requires_check"
            signal["requires_resample"] = True
            signal["severity"] = "high"

        return signal

    if anomaly_type == "O5_CRL_ROOT_DIVERGENCE":
        if root_key in {"crl_freshness_root", "crl_live_semantic_root"}:
            signal["temporal_skew_class"] = "crl_freshness_skew_possible"
            signal["requires_resample"] = True
            signal["severity"] = "warning"

        elif root_key == "crl_frozen_hash_root":
            signal["temporal_skew_class"] = "crl_frozen_hash_diff_requires_semantic_check"
            signal["requires_resample"] = True
            signal["severity"] = "high"

        elif root_key == "crl_revoked_set_root":
            signal["temporal_skew_class"] = "crl_revoked_set_diff_requires_impact_check"
            signal["requires_resample"] = True
            signal["severity"] = "high"

        elif root_key == "crl_issuer_aki_root":
            signal["temporal_skew_class"] = "crl_issuer_aki_diff_not_temporal"
            signal["requires_resample"] = False
            signal["severity"] = "high"

        else:
            signal["temporal_skew_class"] = "crl_diff_requires_semantic_check"
            signal["requires_resample"] = True
            signal["severity"] = "high"

        return signal

    if anomaly_type == "O6_AUXILIARY_OBJECT_ROOT_DIVERGENCE":
        signal["temporal_skew_class"] = "auxiliary_root_diff_requires_hash_level_check"
        signal["requires_resample"] = True
        signal["severity"] = "warning"
        return signal

    return signal


def _classify_validation(signal: Dict[str, Any], *, strong_cycle_skew_seconds: int) -> Dict[str, Any]:
    anomaly_type = signal.get("anomaly_type")
    trig = signal.get("trigger_signals") or {}

    if anomaly_type in {
        "V1_VALIDATOR_OUTPUT_COUNT_DIVERGENCE",
        "V2_VALIDATOR_OUTPUT_ROOT_DIVERGENCE",
        "V4_VALIDATOR_CYCLE_SKEW",
    }:
        skew = trig.get("validator_cycle_skew_seconds")

        if skew is not None and float(skew) > strong_cycle_skew_seconds:
            signal["temporal_skew_class"] = "validator_cycle_skew_likely"
            signal["requires_resample"] = True
            signal["severity"] = "warning" if anomaly_type != "V2_VALIDATOR_OUTPUT_ROOT_DIVERGENCE" else "high"
        else:
            signal["temporal_skew_class"] = "validator_output_diff_requires_synchronized_export"
            signal["requires_resample"] = True

        return signal

    if anomaly_type == "V5_VALIDATOR_CONFIG_DRIFT":
        signal["temporal_skew_class"] = "not_temporal_skew"
        signal["requires_resample"] = False
        signal["severity"] = "warning"
        return signal

    return signal


def refine_signal(
    signal: Dict[str, Any],
    *,
    window_seconds: int = 300,
    strong_cycle_skew_seconds: int = 120,
) -> Dict[str, Any]:
    layer = signal.get("layer")

    if layer == "advertised_view":
        return _classify_advertised(signal, window_seconds=window_seconds)

    if layer == "object_view":
        return _classify_object(signal)

    if layer == "validation_output_view":
        return _classify_validation(signal, strong_cycle_skew_seconds=strong_cycle_skew_seconds)

    return signal
