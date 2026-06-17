from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from asn1crypto import cms, core


SIGNED_DATA_OID_DER = bytes.fromhex("06092a864886f70d010702")

# id-ct-rpkiManifest, RFC 9286 / RFC 6486
RPKI_MANIFEST_ECONTENT_TYPE = "1.2.840.113549.1.9.16.1.26"

HASH_ALG_NAMES = {
    "2.16.840.1.101.3.4.2.1": "sha256",
}


class FileAndHash(core.Sequence):
    _fields = [
        ("file", core.IA5String),
        ("hash", core.BitString),
    ]


class Manifest(core.Sequence):
    _fields = [
        ("version", core.Integer, {"explicit": 0, "default": 0}),
        ("manifest_number", core.Integer),
        ("this_update", core.GeneralizedTime),
        ("next_update", core.GeneralizedTime),
        ("file_hash_alg", core.ObjectIdentifier),
        ("file_list", core.SequenceOf, {"spec": FileAndHash}),
    ]


@dataclass
class NormalizeResult:
    ok: bool
    storage_format: str
    raw_len: int
    raw_sha256: str
    cms_der_offset: int | None = None
    cms_der_len: int | None = None
    cms_der_sha256: str | None = None
    cms_der: bytes | None = None
    error_class: str | None = None
    error: str | None = None


@dataclass
class ManifestParseResult:
    ok: bool
    manifest_number: str | None = None
    this_update: str | None = None
    next_update: str | None = None
    file_hash_alg_oid: str | None = None
    file_hash_alg_name: str | None = None
    filelist_count: int = 0
    filelist: list[dict[str, Any]] | None = None
    econtent_type: str | None = None
    error_class: str | None = None
    error: str | None = None


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_prefixed(data: bytes) -> str:
    return "sha256:" + sha256_hex(data)


def _try_load_content_info(data: bytes) -> tuple[bool, cms.ContentInfo | None, str | None]:
    try:
        ci = cms.ContentInfo.load(data)
        if ci["content_type"].native != "signed_data":
            return False, None, f"unexpected_content_type:{ci['content_type'].native}"
        # Force full decode of SignedData.
        _ = ci["content"]
        return True, ci, None
    except Exception as exc:  # noqa: BLE001
        return False, None, repr(exc)


def _candidate_sequence_offsets(raw: bytes, oid_pos: int, scan_back: int = 256) -> list[int]:
    start = max(0, oid_pos - scan_back)
    offsets = [i for i in range(start, oid_pos + 1) if raw[i] == 0x30]

    # Longer outer SEQUENCE usually appears earlier.
    # Try earlier offsets first.
    return offsets


def normalize_signed_object_der(raw: bytes) -> NormalizeResult:
    raw_sha = sha256_prefixed(raw)

    if not raw:
        return NormalizeResult(
            ok=False,
            storage_format="unknown",
            raw_len=0,
            raw_sha256=raw_sha,
            error_class="empty_object",
            error="input object is empty",
        )

    # Case 1: already DER CMS ContentInfo.
    if raw[0] == 0x30:
        ok, ci, err = _try_load_content_info(raw)
        if ok and ci is not None:
            der = ci.dump()
            return NormalizeResult(
                ok=True,
                storage_format="der_cms",
                raw_len=len(raw),
                raw_sha256=raw_sha,
                cms_der_offset=0,
                cms_der_len=len(der),
                cms_der_sha256=sha256_prefixed(der),
                cms_der=der,
            )

    # Case 2: Routinator cache wrapper or other wrapper containing CMS signedData.
    oid_pos = raw.find(SIGNED_DATA_OID_DER)
    if oid_pos < 0:
        return NormalizeResult(
            ok=False,
            storage_format="unknown",
            raw_len=len(raw),
            raw_sha256=raw_sha,
            error_class="signed_data_oid_not_found",
            error="CMS signedData OID not found in object bytes",
        )

    last_error = None
    for off in _candidate_sequence_offsets(raw, oid_pos):
        ok, ci, err = _try_load_content_info(raw[off:])
        if ok and ci is not None:
            der = ci.dump()
            return NormalizeResult(
                ok=True,
                storage_format="routinator_cache_wrapper",
                raw_len=len(raw),
                raw_sha256=raw_sha,
                cms_der_offset=off,
                cms_der_len=len(der),
                cms_der_sha256=sha256_prefixed(der),
                cms_der=der,
            )
        last_error = err

    return NormalizeResult(
        ok=False,
        storage_format="routinator_cache_wrapper",
        raw_len=len(raw),
        raw_sha256=raw_sha,
        error_class="embedded_cms_der_not_found",
        error=last_error or "failed to locate valid CMS ContentInfo before signedData OID",
    )


def _extract_econtent_bytes(ci: cms.ContentInfo) -> tuple[bytes | None, str | None, str | None]:
    try:
        signed_data = ci["content"]
        encap = signed_data["encap_content_info"]

        econtent_type_obj = encap["content_type"]
        econtent_type = econtent_type_obj.dotted

        content = encap["content"]
        if content is None or content.native is None:
            return None, econtent_type, "manifest_econtent_missing"

        # asn1crypto may represent eContent as ParsableOctetString or OctetString.
        if hasattr(content, "parsed"):
            try:
                parsed = content.parsed
                if hasattr(parsed, "dump"):
                    return parsed.dump(), econtent_type, None
            except Exception:
                pass

        if hasattr(content, "native") and isinstance(content.native, bytes):
            return content.native, econtent_type, None

        if hasattr(content, "contents"):
            return bytes(content.contents), econtent_type, None

        return None, econtent_type, "manifest_econtent_unknown_representation"
    except Exception as exc:  # noqa: BLE001
        return None, None, f"manifest_econtent_extract_failed:{repr(exc)}"


def _bit_string_to_hash_hex(value: core.BitString) -> str:
    contents = bytes(value.contents)
    if not contents:
        return ""

    unused_bits = contents[0]
    hash_bytes = contents[1:]

    # RPKI manifest hashes should be byte-aligned.
    # Preserve bytes even if unused_bits is non-zero, but caller can inspect if needed.
    _ = unused_bits

    return hash_bytes.hex()


def parse_rpki_manifest(cms_der: bytes) -> ManifestParseResult:
    try:
        ci = cms.ContentInfo.load(cms_der)
    except Exception as exc:  # noqa: BLE001
        return ManifestParseResult(
            ok=False,
            error_class="cms_parse_failed",
            error=repr(exc),
        )

    try:
        if ci["content_type"].native != "signed_data":
            return ManifestParseResult(
                ok=False,
                error_class="cms_content_type_unexpected",
                error=f"content_type={ci['content_type'].native}",
            )

        econtent_bytes, econtent_type, econtent_err = _extract_econtent_bytes(ci)

        if econtent_err:
            return ManifestParseResult(
                ok=False,
                econtent_type=econtent_type,
                error_class=econtent_err.split(":", 1)[0],
                error=econtent_err,
            )

        if econtent_type != RPKI_MANIFEST_ECONTENT_TYPE:
            return ManifestParseResult(
                ok=False,
                econtent_type=econtent_type,
                error_class="manifest_econtent_type_unexpected",
                error=f"econtent_type={econtent_type}",
            )

        if not econtent_bytes:
            return ManifestParseResult(
                ok=False,
                econtent_type=econtent_type,
                error_class="manifest_econtent_missing",
                error="empty eContent",
            )

        manifest = Manifest.load(econtent_bytes)
        file_hash_alg_oid = manifest["file_hash_alg"].dotted
        file_hash_alg_name = HASH_ALG_NAMES.get(file_hash_alg_oid, file_hash_alg_oid)

        filelist: list[dict[str, Any]] = []
        for item in manifest["file_list"]:
            file_name = item["file"].native
            hash_hex = _bit_string_to_hash_hex(item["hash"])
            filelist.append(
                {
                    "file_name": file_name,
                    "file_hash_alg_oid": file_hash_alg_oid,
                    "file_hash_alg": file_hash_alg_name,
                    "file_hash_hex": hash_hex,
                    "file_hash": f"{file_hash_alg_name}:{hash_hex}",
                }
            )

        return ManifestParseResult(
            ok=True,
            manifest_number=str(manifest["manifest_number"].native),
            this_update=manifest["this_update"].native.isoformat(),
            next_update=manifest["next_update"].native.isoformat(),
            file_hash_alg_oid=file_hash_alg_oid,
            file_hash_alg_name=file_hash_alg_name,
            filelist_count=len(filelist),
            filelist=filelist,
            econtent_type=econtent_type,
        )
    except Exception as exc:  # noqa: BLE001
        return ManifestParseResult(
            ok=False,
            error_class="manifest_asn1_parse_failed",
            error=repr(exc),
        )


def parse_manifest_filelist_from_storage_bytes(raw: bytes) -> dict[str, Any]:
    norm = normalize_signed_object_der(raw)

    base: dict[str, Any] = {
        "unwrap_ok": norm.ok,
        "storage_format": norm.storage_format,
        "raw_len": norm.raw_len,
        "raw_sha256": norm.raw_sha256,
        "cms_der_offset": norm.cms_der_offset,
        "cms_der_len": norm.cms_der_len,
        "cms_der_sha256": norm.cms_der_sha256,
    }

    if not norm.ok or norm.cms_der is None:
        base.update(
            {
                "parse_status": "parse_failed",
                "parse_error_class": norm.error_class,
                "parse_error": norm.error,
                "manifest_number": None,
                "this_update": None,
                "next_update": None,
                "file_hash_alg_oid": None,
                "file_hash_alg": None,
                "filelist_count": 0,
                "filelist": [],
            }
        )
        return base

    parsed = parse_rpki_manifest(norm.cms_der)

    if not parsed.ok:
        base.update(
            {
                "parse_status": "parse_failed",
                "parse_error_class": parsed.error_class,
                "parse_error": parsed.error,
                "econtent_type": parsed.econtent_type,
                "manifest_number": None,
                "this_update": None,
                "next_update": None,
                "file_hash_alg_oid": None,
                "file_hash_alg": None,
                "filelist_count": 0,
                "filelist": [],
            }
        )
        return base

    base.update(
        {
            "parse_status": "parsed",
            "parse_error_class": None,
            "parse_error": None,
            "econtent_type": parsed.econtent_type,
            "manifest_number": parsed.manifest_number,
            "this_update": parsed.this_update,
            "next_update": parsed.next_update,
            "file_hash_alg_oid": parsed.file_hash_alg_oid,
            "file_hash_alg": parsed.file_hash_alg_name,
            "filelist_count": parsed.filelist_count,
            "filelist": parsed.filelist or [],
        }
    )
    return base
