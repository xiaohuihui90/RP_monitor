#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import hashlib
from datetime import timezone
from typing import Any, Dict, List

try:
    from asn1crypto import crl
except Exception as exc:
    raise RuntimeError("asn1crypto is required for CRL parsing") from exc

from scripts.p3.rpki_objects.semantic_hash import canonical_json_hash


OID_AKI = "2.5.29.35"
OID_CRL_NUMBER = "2.5.29.20"


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
        der_hash = sha256_hex(name.dump())
    except Exception:
        der_hash = None

    return {
        "human_friendly": human,
        "native": native,
        "der_sha256": der_hash,
    }


def locate_der_crl(raw: bytes) -> Dict[str, Any]:
    best_error = None

    for offset, b in enumerate(raw):
        if b != 0x30:
            continue
        try:
            cert_list = crl.CertificateList.load(raw[offset:], strict=False)
            der = cert_list.dump()

            _ = cert_list["tbs_cert_list"]["issuer"].native
            _ = cert_list["tbs_cert_list"]["this_update"].native

            return {
                "cert_list": cert_list,
                "der": der,
                "der_offset": offset,
                "der_len": len(der),
                "wrapper_detected": offset > 0,
                "wrapper_type": "prefixed_der_crl" if offset > 0 else "none",
            }
        except Exception as exc:
            best_error = exc
            continue

    raise ValueError(f"no_der_x509_crl_found:{best_error!r}")


def get_crl_extensions(cert_list: Any) -> List[Any]:
    tbs = cert_list["tbs_cert_list"]
    try:
        exts = tbs["crl_extensions"]
        if exts.native is None:
            return []
        return list(exts)
    except Exception:
        return []


def find_crl_extension(cert_list: Any, oid: str) -> Any | None:
    for ext in get_crl_extensions(cert_list):
        try:
            if ext["extn_id"].dotted == oid:
                return ext
        except Exception:
            continue
    return None


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


def extract_authority_key_identifier(cert_list: Any) -> str | None:
    ext = find_crl_extension(cert_list, OID_AKI)
    native = ext_parsed_native(ext)

    if isinstance(native, dict):
        for key in ["key_identifier", "keyIdentifier"]:
            if native.get(key) is not None:
                return bytes_to_hex(native.get(key))

    return bytes_to_hex(native)


def extract_crl_number(cert_list: Any) -> str | None:
    ext = find_crl_extension(cert_list, OID_CRL_NUMBER)
    native = ext_parsed_native(ext)

    if native is None:
        return None

    try:
        return str(int(native))
    except Exception:
        return str(native)


def extract_revoked_entries(cert_list: Any) -> Dict[str, Any]:
    tbs = cert_list["tbs_cert_list"]

    revoked_serials: List[str] = []
    revoked_entries: List[Dict[str, Any]] = []

    try:
        revoked = tbs["revoked_certificates"]
        if revoked.native is None:
            revoked = []
    except Exception:
        revoked = []

    for item in revoked:
        try:
            serial_native = item["user_certificate"].native
            serial = format(int(serial_native), "x")
        except Exception:
            serial = str(item.get("user_certificate", ""))

        try:
            revocation_date = iso_datetime(item["revocation_date"].native)
        except Exception:
            revocation_date = None

        revoked_serials.append(serial)
        revoked_entries.append({
            "serial_number": serial,
            "revocation_date": revocation_date,
        })

    revoked_serials_sorted = sorted(set(revoked_serials))
    revoked_entries_sorted = sorted(
        revoked_entries,
        key=lambda x: (str(x.get("serial_number")), str(x.get("revocation_date"))),
    )

    return {
        "revoked_certificate_count": len(revoked_serials),
        "revoked_serials": revoked_serials_sorted,
        "revoked_entries": revoked_entries_sorted,
        "revoked_serial_set_digest": canonical_json_hash(revoked_serials_sorted),
        "revoked_entries_digest": canonical_json_hash(revoked_entries_sorted),
    }


def parse_crl_der(crl_der: bytes) -> Dict[str, Any]:
    located = locate_der_crl(crl_der)
    cert_list = located["cert_list"]
    der = located["der"]

    tbs = cert_list["tbs_cert_list"]

    try:
        version = tbs["version"].native
    except Exception:
        version = None

    try:
        signature_algorithm = cert_list["signature_algorithm"]["algorithm"].native
    except Exception:
        signature_algorithm = None

    issuer_info = name_to_info(tbs["issuer"])
    this_update = iso_datetime(tbs["this_update"].native)

    try:
        next_update = iso_datetime(tbs["next_update"].native)
    except Exception:
        next_update = None

    authority_key_identifier = extract_authority_key_identifier(cert_list)
    crl_number = extract_crl_number(cert_list)
    revoked = extract_revoked_entries(cert_list)

    fields = {
        "version": version,
        "signature_algorithm": signature_algorithm,
        "issuer": issuer_info["human_friendly"],
        "issuer_native": issuer_info["native"],
        "issuer_hash": issuer_info["der_sha256"],
        "this_update": this_update,
        "next_update": next_update,
        "authority_key_identifier": authority_key_identifier,
        "crl_number": crl_number,
        **revoked,
    }

    semantic_payload = {
        "object_type": "crl",
        "version": fields["version"],
        "signature_algorithm": fields["signature_algorithm"],
        "issuer_hash": fields["issuer_hash"],
        "this_update": fields["this_update"],
        "next_update": fields["next_update"],
        "authority_key_identifier": fields["authority_key_identifier"],
        "crl_number": fields["crl_number"],
        "revoked_serial_set_digest": fields["revoked_serial_set_digest"],
        "revoked_entries_digest": fields["revoked_entries_digest"],
    }

    issuer_aki_payload = {
        "issuer_hash": fields["issuer_hash"],
        "authority_key_identifier": fields["authority_key_identifier"],
    }

    revoked_payload = {
        "revoked_serial_set_digest": fields["revoked_serial_set_digest"],
    }

    freshness_payload = {
        "crl_number": fields["crl_number"],
        "this_update": fields["this_update"],
        "next_update": fields["next_update"],
    }

    warnings = []
    if not authority_key_identifier:
        warnings.append("authority_key_identifier_missing")
    if not crl_number:
        warnings.append("crl_number_missing")

    return {
        "parse_status": "ok",
        "der_sha256": sha256_hex(der),
        "der_offset": located["der_offset"],
        "der_len": located["der_len"],
        "wrapper_detected": located["wrapper_detected"],
        "wrapper_type": located["wrapper_type"],
        "semantic_fields": fields,
        "crl_semantic_hash": canonical_json_hash(semantic_payload),
        "crl_issuer_aki_hash": canonical_json_hash(issuer_aki_payload),
        "crl_revoked_set_hash": canonical_json_hash(revoked_payload),
        "crl_freshness_hash": canonical_json_hash(freshness_payload),
        "warnings": warnings,
    }
