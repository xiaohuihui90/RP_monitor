#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CER semantic parser for RPKI resource certificates.

Scope:
  - Parse DER X.509 certificate objects collected by S3.
  - Extract semantic fields useful for cross-probe object-layer comparison.
  - Do NOT validate certificate signatures.
  - Do NOT build full RFC 6487 certification paths.
"""

from __future__ import annotations

import hashlib
from datetime import timezone
from typing import Any, Dict, List

try:
    from asn1crypto import x509
except Exception as exc:  # pragma: no cover
    raise RuntimeError("asn1crypto is required for CER parsing") from exc

from scripts.p3.rpki_objects.semantic_hash import canonical_json_hash


OID_SKI = "2.5.29.14"
OID_AKI = "2.5.29.35"
OID_KEY_USAGE = "2.5.29.15"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_CRLDP = "2.5.29.31"
OID_AIA = "1.3.6.1.5.5.7.1.1"
OID_SIA = "1.3.6.1.5.5.7.1.11"
OID_IP_RESOURCES = "1.3.6.1.5.5.7.1.7"
OID_AS_RESOURCES = "1.3.6.1.5.5.7.1.8"


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def bytes_to_hex(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, bytes):
        return v.hex()
    if isinstance(v, bytearray):
        return bytes(v).hex()
    return v


def iso_datetime(v: Any) -> str | None:
    if v is None:
        return None
    try:
        if hasattr(v, "astimezone"):
            return v.astimezone(timezone.utc).isoformat()
        return str(v)
    except Exception:
        return str(v)


def collect_uris(obj: Any) -> List[str]:
    out: List[str] = []

    def walk(x: Any) -> None:
        if isinstance(x, str):
            if x.startswith(("rsync://", "https://", "http://")):
                out.append(x)
        elif isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, (list, tuple, set)):
            for v in x:
                walk(v)

    walk(obj)
    return sorted(set(out))


def name_to_info(name: Any) -> Dict[str, Any]:
    try:
        human = name.human_friendly
    except Exception:
        human = str(name.native)

    try:
        native = name.native
    except Exception:
        native = None

    try:
        der = name.dump()
        der_hash = sha256_hex(der)
    except Exception:
        der_hash = None

    return {
        "human_friendly": human,
        "native": native,
        "der_sha256": der_hash,
    }


def locate_der_certificate(raw: bytes) -> Dict[str, Any]:
    """
    Locate a DER X.509 certificate in raw bytes.

    Most .cer files are raw DER. Some cache formats may prepend metadata, so
    we scan candidate SEQUENCE offsets.
    """
    best_error = None

    for offset, b in enumerate(raw):
        if b != 0x30:
            continue
        try:
            cert = x509.Certificate.load(raw[offset:], strict=False)
            der = cert.dump()

            # Basic sanity checks.
            _ = cert["tbs_certificate"]["serial_number"].native
            _ = cert["tbs_certificate"]["subject"].native
            _ = cert["tbs_certificate"]["issuer"].native

            return {
                "cert": cert,
                "der": der,
                "der_offset": offset,
                "der_len": len(der),
                "wrapper_detected": offset > 0,
                "wrapper_type": "prefixed_der_certificate" if offset > 0 else "none",
            }
        except Exception as exc:
            best_error = exc
            continue

    raise ValueError(f"no_der_x509_certificate_found:{best_error!r}")


def get_extensions(cert: x509.Certificate) -> List[Any]:
    tbs = cert["tbs_certificate"]
    try:
        exts = tbs["extensions"]
        if exts.native is None:
            return []
        return list(exts)
    except Exception:
        return []


def find_extension(cert: x509.Certificate, oid: str) -> Any | None:
    for ext in get_extensions(cert):
        try:
            if ext["extn_id"].dotted == oid:
                return ext
        except Exception:
            continue
    return None


def ext_critical(ext: Any | None) -> bool | None:
    if ext is None:
        return None
    try:
        return bool(ext["critical"].native)
    except Exception:
        return False


def ext_value_der(ext: Any | None) -> bytes | None:
    if ext is None:
        return None
    try:
        # Contents of the OCTET STRING, i.e. the DER-encoded extension value.
        return bytes(ext["extn_value"].contents)
    except Exception:
        try:
            return ext["extn_value"].dump()
        except Exception:
            return None


def ext_digest(ext: Any | None) -> str | None:
    der = ext_value_der(ext)
    return sha256_hex(der) if der is not None else None


def ext_parsed_native(ext: Any | None) -> Any:
    if ext is None:
        return None
    try:
        return ext["extn_value"].parsed.native
    except Exception:
        try:
            return ext["extn_value"].native
        except Exception:
            return None


def extract_ski(cert: x509.Certificate) -> str | None:
    ext = find_extension(cert, OID_SKI)
    native = ext_parsed_native(ext)
    return bytes_to_hex(native)


def extract_aki(cert: x509.Certificate) -> str | None:
    ext = find_extension(cert, OID_AKI)
    native = ext_parsed_native(ext)

    if isinstance(native, dict):
        for key in ["key_identifier", "keyIdentifier"]:
            if native.get(key) is not None:
                return bytes_to_hex(native.get(key))
    return bytes_to_hex(native)


def extract_key_usage(cert: x509.Certificate) -> List[str]:
    ext = find_extension(cert, OID_KEY_USAGE)
    native = ext_parsed_native(ext)
    if native is None:
        return []

    if isinstance(native, set):
        return sorted(str(x) for x in native)
    if isinstance(native, list):
        return sorted(str(x) for x in native)
    if isinstance(native, tuple):
        return sorted(str(x) for x in native)
    return [str(native)]


def extract_basic_constraints(cert: x509.Certificate) -> Dict[str, Any]:
    ext = find_extension(cert, OID_BASIC_CONSTRAINTS)
    native = ext_parsed_native(ext)

    ca = None
    path_len = None

    if isinstance(native, dict):
        ca = native.get("ca")
        path_len = native.get("path_len_constraint")

    return {
        "present": ext is not None,
        "critical": ext_critical(ext),
        "ca": bool(ca) if ca is not None else None,
        "path_len_constraint": path_len,
        "digest": ext_digest(ext),
    }


def extract_access_descriptions(cert: x509.Certificate, oid: str) -> List[Dict[str, Any]]:
    ext = find_extension(cert, oid)
    if ext is None:
        return []

    rows: List[Dict[str, Any]] = []
    try:
        parsed = ext["extn_value"].parsed
        for ad in parsed:
            try:
                method = ad["access_method"].native
            except Exception:
                method = None
            try:
                location = ad["access_location"].native
            except Exception:
                location = None
            rows.append({"access_method": method, "access_location": location})
    except Exception:
        native = ext_parsed_native(ext)
        if isinstance(native, list):
            for item in native:
                rows.append({"native": item})
        elif native is not None:
            rows.append({"native": native})

    return rows


def group_sia(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    ca_repo = []
    mft = []
    signed = []
    other = []

    for r in rows:
        method = str(r.get("access_method") or r.get("native") or "")
        loc = r.get("access_location")
        if loc is None:
            locs = collect_uris(r)
        else:
            locs = collect_uris(loc)

        if "ca_repository" in method:
            ca_repo.extend(locs)
        elif "rpki_manifest" in method or "manifest" in method:
            mft.extend(locs)
        elif "signed_object" in method or "signedObject" in method:
            signed.extend(locs)
        else:
            other.extend(locs)

    return {
        "ca_repository_uris": sorted(set(ca_repo)),
        "rpki_manifest_uris": sorted(set(mft)),
        "signed_object_uris": sorted(set(signed)),
        "other_uris": sorted(set(other)),
        "raw_access_descriptions": rows,
    }


def group_aia(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    ca_issuers = []
    ocsp = []
    other = []

    for r in rows:
        method = str(r.get("access_method") or r.get("native") or "")
        loc = r.get("access_location")
        if loc is None:
            locs = collect_uris(r)
        else:
            locs = collect_uris(loc)

        if "ca_issuers" in method or "caIssuers" in method:
            ca_issuers.extend(locs)
        elif "ocsp" in method:
            ocsp.extend(locs)
        else:
            other.extend(locs)

    return {
        "ca_issuer_uris": sorted(set(ca_issuers)),
        "ocsp_uris": sorted(set(ocsp)),
        "other_uris": sorted(set(other)),
        "raw_access_descriptions": rows,
    }


def extract_crldp_uris(cert: x509.Certificate) -> List[str]:
    ext = find_extension(cert, OID_CRLDP)
    native = ext_parsed_native(ext)
    return collect_uris(native)


def extract_resource_ext(cert: x509.Certificate, oid: str) -> Dict[str, Any]:
    ext = find_extension(cert, oid)
    if ext is None:
        return {
            "parse_status": "absent",
            "mode": "absent",
            "critical": None,
            "digest": None,
            "canonical_items": [],
        }

    digest = ext_digest(ext)
    critical = ext_critical(ext)

    # 首版以 raw DER digest 为稳定比较依据。canonical_items 后续再增强。
    return {
        "parse_status": "raw_der_only",
        "mode": "present",
        "critical": critical,
        "digest": digest,
        "canonical_items": [],
    }


def classify_certificate_role(
    basic_constraints: Dict[str, Any],
    key_usage: List[str],
    sia: Dict[str, Any],
) -> Dict[str, Any]:
    ku = set(key_usage)
    evidence = []

    bc_present = bool(basic_constraints.get("present"))
    bc_ca = basic_constraints.get("ca")

    if bc_ca is True:
        evidence.append("basic_constraints_ca_true")
    if "key_cert_sign" in ku or "keyCertSign" in ku:
        evidence.append("key_usage_key_cert_sign")
    if "crl_sign" in ku or "cRLSign" in ku:
        evidence.append("key_usage_crl_sign")
    if "digital_signature" in ku or "digitalSignature" in ku:
        evidence.append("key_usage_digital_signature")

    has_ca_ku = (
        ("key_cert_sign" in ku or "keyCertSign" in ku)
        and ("crl_sign" in ku or "cRLSign" in ku)
    )
    has_ee_ku = ("digital_signature" in ku or "digitalSignature" in ku)

    if bc_ca is True and has_ca_ku:
        role = "ca"
    elif (not bc_present or bc_ca is False or bc_ca is None) and has_ee_ku:
        role = "ee"
    else:
        role = "unknown"

    return {
        "certificate_role": role,
        "role_evidence": evidence,
    }


def parse_cer_der(cert_der: bytes) -> Dict[str, Any]:
    located = locate_der_certificate(cert_der)
    cert = located["cert"]
    der = located["der"]

    tbs = cert["tbs_certificate"]

    serial_native = tbs["serial_number"].native
    try:
        serial_number = format(int(serial_native), "x")
    except Exception:
        serial_number = str(serial_native)

    issuer_info = name_to_info(tbs["issuer"])
    subject_info = name_to_info(tbs["subject"])

    validity = tbs["validity"]
    not_before = iso_datetime(validity["not_before"].native)
    not_after = iso_datetime(validity["not_after"].native)

    ski = extract_ski(cert)
    aki = extract_aki(cert)
    key_usage = extract_key_usage(cert)
    basic_constraints = extract_basic_constraints(cert)

    sia_rows = extract_access_descriptions(cert, OID_SIA)
    aia_rows = extract_access_descriptions(cert, OID_AIA)
    sia = group_sia(sia_rows)
    aia = group_aia(aia_rows)
    crldp_uris = extract_crldp_uris(cert)

    ip_resources = extract_resource_ext(cert, OID_IP_RESOURCES)
    as_resources = extract_resource_ext(cert, OID_AS_RESOURCES)

    role_info = classify_certificate_role(basic_constraints, key_usage, sia)

    fields = {
        "serial_number": serial_number,
        "issuer": issuer_info["human_friendly"],
        "issuer_native": issuer_info["native"],
        "issuer_hash": issuer_info["der_sha256"],
        "subject": subject_info["human_friendly"],
        "subject_native": subject_info["native"],
        "subject_hash": subject_info["der_sha256"],
        "not_before": not_before,
        "not_after": not_after,
        "ski": ski,
        "aki": aki,
        "certificate_role": role_info["certificate_role"],
        "role_evidence": role_info["role_evidence"],
        "basic_constraints": basic_constraints,
        "basic_constraints_ca": basic_constraints.get("ca"),
        "key_usage": key_usage,
        "sia": sia,
        "aia": aia,
        "crldp_uris": crldp_uris,
        "ip_resources": ip_resources,
        "as_resources": as_resources,
        "chain_keys": {
            "subject_ski_key": f"ski:{ski}" if ski else None,
            "issuer_aki_key": f"aki:{aki}" if aki else None,
            "subject_hash_key": f"subject_hash:{subject_info['der_sha256']}" if subject_info.get("der_sha256") else None,
            "issuer_hash_key": f"issuer_hash:{issuer_info['der_sha256']}" if issuer_info.get("der_sha256") else None,
        },
    }

    semantic_payload = {
        "object_type": "cer",
        "serial_number": fields["serial_number"],
        "issuer_hash": fields["issuer_hash"],
        "subject_hash": fields["subject_hash"],
        "not_before": fields["not_before"],
        "not_after": fields["not_after"],
        "ski": fields["ski"],
        "aki": fields["aki"],
        "certificate_role": fields["certificate_role"],
        "key_usage": sorted(fields["key_usage"]),
        "sia": fields["sia"],
        "aia": fields["aia"],
        "crldp_uris": fields["crldp_uris"],
        "ip_resource_digest": fields["ip_resources"]["digest"],
        "as_resource_digest": fields["as_resources"]["digest"],
    }

    chain_payload = {
        "subject_hash": fields["subject_hash"],
        "issuer_hash": fields["issuer_hash"],
        "ski": fields["ski"],
        "aki": fields["aki"],
        "certificate_role": fields["certificate_role"],
    }

    resource_payload = {
        "ip_resource_digest": fields["ip_resources"]["digest"],
        "as_resource_digest": fields["as_resources"]["digest"],
    }

    return {
        "parse_status": "ok",
        "der_sha256": sha256_hex(der),
        "der_offset": located["der_offset"],
        "der_len": located["der_len"],
        "wrapper_detected": located["wrapper_detected"],
        "wrapper_type": located["wrapper_type"],
        "semantic_fields": fields,
        "semantic_object_hash": canonical_json_hash(semantic_payload),
        "chain_index_hash": canonical_json_hash(chain_payload),
        "resource_set_hash": canonical_json_hash(resource_payload),
        "warnings": [],
    }
