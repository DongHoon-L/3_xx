"""Operator CLI: python -m audit_engine verify|report|shred|unseal|keygen."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from collections import Counter
from dataclasses import asdict
from datetime import date, datetime, timezone
from pathlib import Path

from .chain import GENESIS_HASH, HASH_ALGORITHMS, ChainEntry, HashChain
from .config import DEFAULT_CHAIN_PATH, DEFAULT_VAULT_PATH
from .crypto import generate_key, vault_record_ids
from .errors import AuditConfigError, AuditError, AuditStorageError, KeyNotFoundError, SealIntegrityError
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


def _today_utc() -> date:
    return datetime.now(timezone.utc).date()


def _operator_event(action: str, actor: str, record_id: str, result: str, details: dict[str, str]) -> AuditEvent:
    """One event per target. `record_id` is the target id: it is the only unmasked correlation key
    (`purpose`/`details` are masked and truncated, so ids there cannot be relied on)."""
    return AuditEvent(
        timestamp=utc_now(), actor=actor, role="operator", department="audit", action=action,
        asset="audit-engine/vault", record_id=record_id, source_ip="cli",
        purpose=record_id[:200] or "-", result=result, details=details,
    )


def _shredded_ids(entries: list[ChainEntry]) -> set[str]:
    """Targets with a completed audit_shred outcome event."""
    return {
        str(e.record["record_id"]) for e in entries
        if e.record.get("action") == "audit_shred" and e.record.get("result") == "shredded"
    }


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
    # A key with no chain entry, or a missing key with no audit_shred outcome, means the chain was
    # rewritten or a key was destroyed outside the CLI — the tail-truncation signals verify() cannot see.
    orphan_keys = sorted(vault_ids - {str(e.record.get("record_id")) for e in entries})
    audited = _shredded_ids(entries)
    unaudited_shred = sorted(
        {str(e.record["record_id"]) for e in sealed if str(e.record["record_id"]) not in vault_ids} - audited
    )
    report.update({
        "entries": len(entries),
        "by_action": dict(Counter(e.record.get("action", "?") for e in entries)),
        "by_result": dict(Counter(e.record.get("result", "?") for e in entries)),
        "expired_count": len(expired),
        "expired_record_ids": expired,
        "sealed_count": len(sealed),
        "shredded_count": sum(1 for e in sealed if e.record["record_id"] not in vault_ids),
        "residual_plaintext_pii": residual,
        "orphan_key_count": len(orphan_keys),
        "orphan_key_ids": orphan_keys,
        "unaudited_shred_count": len(unaudited_shred),
        "unaudited_shred_ids": unaudited_shred,
    })
    if residual:
        report["anomalies"].append("residual_plaintext_pii")
    if orphan_keys:
        report["anomalies"].append("orphan_keys")
    if unaudited_shred:
        report["anomalies"].append("unaudited_shred")
    return report


def _check_expected_tail(chain: HashChain, expect_tail: str, result: dict) -> None:
    """External anchor: compare the last entry with a (seq, entry_hash) the consumer recorded itself.
    A rewritten or truncated file passes verify() alone; this is what catches it."""
    try:
        seq_text, entry_hash = expect_tail.split(":", 1)
        expected = (int(seq_text), entry_hash.strip())
    except ValueError as exc:
        raise AuditConfigError("--expect-tail must be SEQ:HASH") from exc
    last = None
    for last in chain.iter_entries():
        pass
    actual = (last.seq, last.entry_hash) if last is not None else (0, GENESIS_HASH)
    if actual != expected:
        result.update(valid=False, failed_seq=actual[0], reason="tail_mismatch")


def cmd_verify(args: argparse.Namespace) -> int:
    chain = _chain_from_args(args)
    result = asdict(chain.verify())
    if result["valid"] and args.expect_tail:
        _check_expected_tail(chain, args.expect_tail, result)
    print(json.dumps(result))
    return 0 if result["valid"] else 1


def cmd_report(args: argparse.Namespace) -> int:
    report = build_report(_chain_from_args(args), _vault_path_from_args(args), _today_utc())
    valid = report["verification"]["valid"]
    print(f"chain: {'PASS' if valid else 'FAIL'} ({report['verification']})")
    print(f"entries: {report['entries']}")
    if valid:
        print(f"by_action: {report['by_action']}")
        print(f"by_result: {report['by_result']}")
        print(f"expired: {report['expired_count']}  sealed: {report['sealed_count']}  shredded: {report['shredded_count']}")
        print(f"residual_plaintext_pii: {report['residual_plaintext_pii']}")
        print(f"orphan_keys: {report['orphan_key_count']}  unaudited_shred: {report['unaudited_shred_count']}")
    print(f"anomalies: {report['anomalies']}")
    if args.out:
        try:
            Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError as exc:
            raise AuditStorageError(f"cannot write report {args.out}: {exc.__class__.__name__}") from exc
    return 0 if not report["anomalies"] else 1


def cmd_shred(args: argparse.Namespace) -> int:
    recorder = AuditRecorder.from_env()
    if args.record_id:
        targets = [args.record_id]
        mode = "record_id"
    else:
        today = _today_utc()
        live = vault_record_ids(recorder.config.vault_path)
        targets = [
            e.record["record_id"] for e in recorder.chain.iter_entries()
            if e.sealed is not None and e.record["record_id"] in live and RetentionPolicy.is_expired(e.retention, today)
        ]
        mode = "expired"
    shredded = []
    for target in targets:
        # Write-ahead: the intent to destroy this key is on the chain before the key is touched. If the
        # outcome append fails the intent record still stands, so the operation is never unaudited.
        recorder.record(_operator_event("audit_shred", args.actor, target, "shred_requested", {"mode": mode}))
        destroyed = recorder.vault.shred(target)
        recorder.record(_operator_event(
            "audit_shred", args.actor, target, "shredded" if destroyed else "not_found", {"mode": mode},
        ))
        if destroyed:
            shredded.append(target)
    print(json.dumps({"requested": targets, "shredded": shredded}))
    return 0 if shredded else 1


def cmd_unseal(args: argparse.Namespace) -> int:
    recorder = AuditRecorder.from_env()
    # Operator events now share the target's record_id, so pick the sealed entry when there is one.
    matches = [e for e in recorder.chain.iter_entries() if e.record.get("record_id") == args.record_id]
    sealed_matches = [e for e in matches if e.sealed is not None]
    entry = sealed_matches[0] if sealed_matches else (matches[0] if matches else None)
    if entry is None:
        recorder.record(_operator_event("audit_unseal", args.actor, args.record_id, "not_found", {}))
        print(f"record {args.record_id!r} not found in chain", file=sys.stderr)
        return 1
    try:
        payload = recorder.unseal(entry)
    except (KeyNotFoundError, SealIntegrityError) as exc:
        recorder.record(_operator_event("audit_unseal", args.actor, args.record_id,
                                        f"denied:{exc.__class__.__name__}", {}))
        print(f"unseal denied: {exc}", file=sys.stderr)
        return 1
    recorder.record(_operator_event("audit_unseal", args.actor, args.record_id, "unsealed", {}))
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
    p.add_argument("--expect-tail", metavar="SEQ:HASH",
                   help="externally anchored last entry; a mismatch reports tail_mismatch (detects truncation)")
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
