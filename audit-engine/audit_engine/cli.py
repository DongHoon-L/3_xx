"""Operator CLI: python -m audit_engine verify|report|shred|unseal|keygen."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from collections import Counter
from dataclasses import asdict
from datetime import date
from pathlib import Path
from uuid import uuid4

from .chain import HASH_ALGORITHMS, HashChain
from .config import DEFAULT_CHAIN_PATH, DEFAULT_VAULT_PATH
from .crypto import generate_key, vault_record_ids
from .errors import AuditConfigError, AuditError, KeyNotFoundError, SealIntegrityError
from .recorder import AuditRecorder, residual_pii_count
from .retention import RetentionPolicy
from .schema import AuditEvent, utc_now


def _chain_from_args(args: argparse.Namespace) -> HashChain:
    algorithm = os.environ.get("AUDIT_HASH_ALGORITHM", "sha256")
    if algorithm not in HASH_ALGORITHMS:
        raise AuditConfigError(f"AUDIT_HASH_ALGORITHM must be one of {HASH_ALGORITHMS}")
    return HashChain(args.chain or os.environ.get("AUDIT_CHAIN_PATH", DEFAULT_CHAIN_PATH), algorithm)


def _vault_path_from_args(args: argparse.Namespace) -> Path:
    return Path(getattr(args, "vault", None) or os.environ.get("AUDIT_VAULT_PATH", DEFAULT_VAULT_PATH))


def _operator_event(action: str, actor: str, purpose: str, result: str, details: dict[str, str]) -> AuditEvent:
    return AuditEvent(
        timestamp=utc_now(), actor=actor, role="operator", department="audit", action=action,
        asset="audit-engine/vault", record_id=str(uuid4()), source_ip="cli",
        purpose=purpose[:200] or "-", result=result, details=details,
    )


def build_report(chain: HashChain, vault_path: Path, today: date) -> dict:
    verification = chain.verify()
    report: dict = {
        "chain_path": str(chain.path),
        "generated_on": today.isoformat(),
        "verification": asdict(verification),
        "entries": 0,
        "anomalies": [] if verification.valid else ["chain_corrupt"],
    }
    if not verification.valid:
        return report
    entries = list(chain.iter_entries())
    vault_ids = vault_record_ids(vault_path)
    sealed = [e for e in entries if e.sealed is not None]
    expired = [e.record["record_id"] for e in entries if RetentionPolicy.is_expired(e.retention, today)]
    residual = sum(residual_pii_count(e.record) for e in entries)
    report.update({
        "entries": len(entries),
        "by_action": dict(Counter(e.record.get("action", "?") for e in entries)),
        "by_result": dict(Counter(e.record.get("result", "?") for e in entries)),
        "expired_count": len(expired),
        "expired_record_ids": expired,
        "sealed_count": len(sealed),
        "shredded_count": sum(1 for e in sealed if e.record["record_id"] not in vault_ids),
        "residual_plaintext_pii": residual,
    })
    if residual:
        report["anomalies"].append("residual_plaintext_pii")
    return report


def cmd_verify(args: argparse.Namespace) -> int:
    result = _chain_from_args(args).verify()
    print(json.dumps(asdict(result)))
    return 0 if result.valid else 1


def cmd_report(args: argparse.Namespace) -> int:
    report = build_report(_chain_from_args(args), _vault_path_from_args(args), date.today())
    valid = report["verification"]["valid"]
    print(f"chain: {'PASS' if valid else 'FAIL'} ({report['verification']})")
    print(f"entries: {report['entries']}")
    if valid:
        print(f"by_action: {report['by_action']}")
        print(f"by_result: {report['by_result']}")
        print(f"expired: {report['expired_count']}  sealed: {report['sealed_count']}  shredded: {report['shredded_count']}")
        print(f"residual_plaintext_pii: {report['residual_plaintext_pii']}")
    print(f"anomalies: {report['anomalies']}")
    if args.out:
        Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if not report["anomalies"] else 1


def cmd_shred(args: argparse.Namespace) -> int:
    recorder = AuditRecorder.from_env()
    if args.record_id:
        targets = [args.record_id]
        mode = "record_id"
    else:
        today = date.today()
        live = vault_record_ids(recorder.config.vault_path)
        targets = [
            e.record["record_id"] for e in recorder.chain.iter_entries()
            if e.sealed is not None and e.record["record_id"] in live and RetentionPolicy.is_expired(e.retention, today)
        ]
        mode = "expired"
    shredded = [rid for rid in targets if recorder.vault.shred(rid)]
    recorder.record(_operator_event(
        "audit_shred", args.actor, ",".join(targets), f"shredded:{len(shredded)}",
        {"mode": mode, "requested": str(len(targets)), "shredded": str(len(shredded))},
    ))
    print(json.dumps({"requested": targets, "shredded": shredded}))
    return 0 if shredded else 1


def cmd_unseal(args: argparse.Namespace) -> int:
    recorder = AuditRecorder.from_env()
    entry = next((e for e in recorder.chain.iter_entries() if e.record.get("record_id") == args.record_id), None)
    if entry is None:
        print(f"record {args.record_id!r} not found in chain", file=sys.stderr)
        return 1
    try:
        payload = recorder.unseal(entry)
    except (KeyNotFoundError, SealIntegrityError) as exc:
        recorder.record(_operator_event("audit_unseal", args.actor, args.record_id,
                                        f"denied:{exc.__class__.__name__}", {"target": args.record_id}))
        print(f"unseal denied: {exc}", file=sys.stderr)
        return 1
    recorder.record(_operator_event("audit_unseal", args.actor, args.record_id, "unsealed", {"target": args.record_id}))
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    print(base64.b64encode(generate_key()).decode("ascii"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="audit_engine", description="Tamper-evident audit chain operator CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("verify", help="verify the whole hash chain")
    p.add_argument("--chain", help="chain path (default: AUDIT_CHAIN_PATH)")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("report", help="summarize the chain: actions, results, expiry, sealing, residual PII")
    p.add_argument("--chain")
    p.add_argument("--vault", help="vault path (default: AUDIT_VAULT_PATH)")
    p.add_argument("--out", help="write full JSON report here")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("shred", help="destroy data keys (crypto-shredding); audited")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--record-id")
    group.add_argument("--expired", action="store_true", help="shred every sealed entry past its retention_until")
    p.add_argument("--actor", required=True, help="operator identity recorded in the audit_shred event")
    p.set_defaults(func=cmd_shred)

    p = sub.add_parser("unseal", help="decrypt one sealed payload for investigation; audited")
    p.add_argument("--record-id", required=True)
    p.add_argument("--actor", required=True)
    p.set_defaults(func=cmd_unseal)

    p = sub.add_parser("keygen", help="print a fresh 32-byte base64 KEK for AUDIT_KEK_B64")
    p.set_defaults(func=cmd_keygen)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except AuditError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
