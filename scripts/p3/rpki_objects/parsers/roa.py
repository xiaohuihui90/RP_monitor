#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RFC 6482 / RFC 9582 compatible ROA eContent parser.

Scope:
  - Parse ROA eContent only.
  - Do not perform full RPKI validation.
  - Generate candidate VRP keys from ROA payload:
      AS{as_id}|{prefix}|{effective_max_length}

Important:
  candidate_vrp_key != validated VRP.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List

try:
    from asn1crypto import core
except Exception as exc:  # pragma: no cover
    raise RuntimeError("asn1crypto is required for ROA parsing") from exc

from scripts.p3.rpki_objects.semantic_hash import canonical_json_hash


ROA_ECONTENT_TYPE_OID = "1.2.840.113549.1.9.16.1.24"


class ROAIPAddress(core.Sequence):
    _fields = [
        ("address", core.BitString),
        ("maxLength", core.Integer, {"optional": True}),
    ]


class ROAIPAddresses(core.SequenceOf):
    _child_spec = ROAIPAddress


class ROAIPAddressFamily(core.Sequence):
    _fields = [
        ("addressFamily", core.OctetString),
        ("addresses", ROAIPAddresses),
    ]


class ROAIPAddressFamilies(core.SequenceOf):
    _child_spec = ROAIPAddressFamily


class RouteOriginAttestation(core.Sequence):
    _fields = [
        ("version", core.Integer, {"explicit": 0, "default": 0, "optional": True}),
        ("asID", core.Integer),
        ("ipAddrBlocks", ROAIPAddressFamilies),
    ]


def _afi_from_address_family(address_family: bytes) -> tuple[int, str, int]:
    if len(address_family) < 2:
        raise ValueError(f"bad_address_family_length:{len(address_family)}")

    afi = int.from_bytes(address_family[:2], "big")

    if afi == 1:
        return afi, "ipv4", 32
    if afi == 2:
        return afi, "ipv6", 128

    raise ValueError(f"unsupported_afi:{afi}")


def _bit_string_to_prefix(bit_string: core.BitString, address_family: str, max_bits: int) -> tuple[str, int]:
    contents = bit_string.contents
    if not contents:
        raise ValueError("empty_bit_string_contents")

    unused_bits = contents[0]
    payload = contents[1:]

    if unused_bits < 0 or unused_bits > 7:
        raise ValueError(f"bad_unused_bits:{unused_bits}")

    prefix_length = len(payload) * 8 - unused_bits
    if prefix_length < 0 or prefix_length > max_bits:
        raise ValueError(f"bad_prefix_length:{prefix_length}")

    target_len = 4 if address_family == "ipv4" else 16
    padded = payload + b"\x00" * max(0, target_len - len(payload))
    padded = padded[:target_len]

    if address_family == "ipv4":
        addr = ipaddress.IPv4Address(padded)
    else:
        addr = ipaddress.IPv6Address(padded)

    network = ipaddress.ip_network(f"{addr}/{prefix_length}", strict=False)
    return str(network), prefix_length


def _effective_max_length(prefix_length: int, max_length_value: Any, max_bits: int) -> int:
    if max_length_value is None:
        effective = prefix_length
    else:
        effective = int(max_length_value)

    if effective < prefix_length:
        raise ValueError(f"bad_max_length_less_than_prefix:{effective}<{prefix_length}")
    if effective > max_bits:
        raise ValueError(f"bad_max_length_exceeds_afi_limit:{effective}>{max_bits}")

    return effective


def make_vrp_key(as_id: int, prefix: str, effective_max_length: int) -> str:
    return f"AS{int(as_id)}|{prefix}|{int(effective_max_length)}"


def parse_roa_econtent(econtent_der: bytes) -> Dict[str, Any]:
    roa = RouteOriginAttestation.load(econtent_der)

    try:
        version = int(roa["version"].native or 0)
    except Exception:
        version = 0

    as_id = int(roa["asID"].native)

    prefixes: List[Dict[str, Any]] = []
    vrp_keys: List[str] = []

    for family in roa["ipAddrBlocks"]:
        address_family_bytes = family["addressFamily"].native
        if not isinstance(address_family_bytes, (bytes, bytearray)):
            address_family_bytes = bytes(address_family_bytes)

        afi, address_family, max_bits = _afi_from_address_family(bytes(address_family_bytes))

        for item in family["addresses"]:
            prefix, prefix_length = _bit_string_to_prefix(
                item["address"],
                address_family=address_family,
                max_bits=max_bits,
            )

            max_length_value = None
            if "maxLength" in item and item["maxLength"].native is not None:
                max_length_value = int(item["maxLength"].native)

            effective = _effective_max_length(prefix_length, max_length_value, max_bits)
            vrp_key = make_vrp_key(as_id, prefix, effective)

            prefixes.append(
                {
                    "afi": afi,
                    "address_family": address_family,
                    "prefix": prefix,
                    "prefix_length": prefix_length,
                    "max_length": max_length_value,
                    "effective_max_length": effective,
                    "vrp_key": vrp_key,
                }
            )
            vrp_keys.append(vrp_key)

    prefixes = sorted(
        prefixes,
        key=lambda x: (
            x["address_family"],
            x["prefix"],
            int(x["effective_max_length"]),
            x["vrp_key"],
        ),
    )
    vrp_keys = sorted(set(vrp_keys))

    if not vrp_keys:
        raise ValueError("roa_no_vrp_keys")

    stable_payload = {
        "object_type": "roa",
        "econtent_type_oid": ROA_ECONTENT_TYPE_OID,
        "as_id": as_id,
        "vrp_keys": vrp_keys,
    }

    return {
        "profile": "RFC6482-compatible/RFC9582-aware",
        "version": version,
        "as_id": as_id,
        "roa_prefixes": prefixes,
        "vrp_keys": vrp_keys,
        "vrp_key_count": len(vrp_keys),
        "vrp_key_digest": canonical_json_hash(vrp_keys),
        "semantic_object_hash": canonical_json_hash(stable_payload),
    }
