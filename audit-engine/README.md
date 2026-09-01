# audit-engine

5W1H 감사 이벤트를 **변조 탐지 가능한 append-only 해시체인**에 기록하는 애드온 패키지.
행위자는 가명화(HMAC), 자유 텍스트의 PII는 마스킹, 원문(질문/답변/문맥)은 AES-256-GCM으로 봉인하고,
보존 기한이 지나면 데이터 키를 파기(crypto-shredding)해 원문을 복구 불가능하게 만든다.
설계 근거는 `docs/superpowers/specs/2026-09-01-rag-audit-addon-design.md` §4.

## 사용법 (공개 API)

```python
from audit_engine import AuditEvent, AuditError, AuditRecorder, utc_now

recorder = AuditRecorder.from_env()          # 기동 시 1회. 실패 → AuditConfigError로 기동 중단
event = AuditEvent(
    timestamp=utc_now(), actor="alice", role="analyst", department="rag-users",
    action="agent_query", asset="rag-agent/agent", record_id=request_id,
    source_ip="127.0.0.1", purpose=question[:200], result="answered",
    details={"tool": "rag_answer", "latency_ms": "120"},
)
entry = recorder.record(event, sensitive={"question": q, "answer": a, "contexts": ctx})
```

- **계약은 이 세 가지뿐**이다: `AuditRecorder.from_env().record(event, sensitive)`, `AuditEvent`, `utc_now`,
  그리고 예외 계층(`AuditError` ← `AuditValidationError`, `AuditConfigError`, `ChainCorruptError`,
  `AuditStorageError`, `KeyNotFoundError`, `SealIntegrityError`).
- `HashChain` / `KeyVault` / `RetentionPolicy` / `mask_text` / `pseudonymize_value` 등은 빌딩 블록으로
  export되어 있지만 애드온 계약이 아니다. 직접 쓰면 잠금·순서 보장을 스스로 책임져야 한다.
- `record()`는 실패를 **삼키지 않는다**. 모든 실패는 `AuditError` 하위 예외로 전파된다.

## 환경 변수

| env | 필수 | 기본 | 검증 |
|---|---|---|---|
| `AUDIT_PSEUDONYM_SECRET` | ✅ | — | 16자 이상 |
| `AUDIT_KEK_B64` | ✅ | — | base64 디코드 후 정확히 32B (`python -m audit_engine keygen`) |
| `AUDIT_CHAIN_PATH` | | `./audit-data/chain.jsonl` | |
| `AUDIT_VAULT_PATH` | | `./audit-data/vault.json` | |
| `AUDIT_RETENTION_POLICY` | | 패키지 내 `policies/retention_policy.json` | 존재 + JSON 객체 + 정수 `retention_days` |
| `AUDIT_HASH_ALGORITHM` | | `sha256` | 허용목록 {sha256, sha512, sha3_256} |

비밀값은 `AuditConfig.__repr__`·로그·예외 메시지에 노출되지 않는다.

## CLI (`python -m audit_engine <cmd>`)

| 명령 | 인자 | 동작 | 종료코드 |
|---|---|---|---|
| `verify` | `[--chain P] [--expect-tail SEQ:HASH]` | 전체 검증 JSON. `--expect-tail`은 외부 앵커와 마지막 엔트리를 대조 → 불일치 시 `reason="tail_mismatch"` | 0 / 1 |
| `report` | `[--chain P] [--vault P] [--out r.json]` | 집계 + 만료(UTC 오늘) + 봉인/파기 + 잔여 PII + `orphan_keys`/`unaudited_shred` | 0 / 1(이상 징후 있음) |
| `shred` | `--record-id X` \| `--expired`, `--actor N` | 대상마다 `audit_shred` 2건: `shred_requested`(파기 전) → `shredded`\|`not_found`(파기 후). `record_id`=대상 id | 0(1건 이상 파기) / 1 |
| `unseal` | `--record-id X --actor N` | 원문 JSON 출력 + `audit_unseal` 1건(`unsealed`\|`denied:<Exception>`\|`not_found`) | 0 / 1 |
| `keygen` | | 32B 랜덤 base64 (KEK 생성용) | 0 |

`shred`/`unseal`은 `AuditRecorder`를 쓰므로 서비스와 **동일한 env(비밀값)** 가 필요하다.

## 운영 노트 (인계 사항)

**동시성**
- 체인/볼트 하나당 **서비스 프로세스는 하나**. `uvicorn --workers 1`로 실행할 것. 워커를 늘리면 각 워커가
  같은 파일을 쓴다 — 잠금 덕에 손상되지는 않지만 append마다 O(n) 재검증이 걸려 성능이 무너진다.
- **CLI는 서비스가 떠 있는 상태에서 실행해도 안전하다.** `chain.jsonl.lock` / `vault.json.lock`에 프로세스 간
  배타 잠금(Windows `msvcrt` / POSIX `fcntl`)을 걸고, `append`는 디스크의 꼬리와 메모리 상태가 다르면
  전체를 재검증한 뒤 재동기화한다. 대가: CLI가 쓴 직후 서비스의 첫 append는 O(n). `.lock` 파일은 지우지
  않고 남는다(빈 파일, 정상).
- 잠금 대기 10초 초과 → `AuditStorageError`(fail-closed). 정지된 프로세스가 잠금을 쥐고 있다는 뜻이다.

**성능 / 용량**
- `sensitive`가 있는 record 1건마다 볼트 **전체를 다시 쓰고 fsync**한다(O(볼트 크기)). 체인 append도 fsync한다.
- 기동 시, 그리고 CLI `shred`/`unseal` 실행 시마다 체인 전체를 재검증한다(O(n)).
- 실습 규모에서는 충분하지만, **10^5 레코드를 넘길 계획이라면 append-only 볼트(키별 1줄)로 바꿔야 한다.**

**호출 규약**
- `record()`는 fsync에서 블로킹된다. async 서버에서는 **워커 스레드**에서 호출할 것
  (FastAPI라면 `def` 엔드포인트나 `run_in_threadpool`).
- `AuditError`를 잡아 **503**으로 응답하고 답변은 폐기한다(감사되지 않은 응답은 내보내지 않는다).
- `sensitive`는 JSON 네이티브 타입만(직렬화 불가 → `AuditValidationError("sensitive")`).
- 마스킹 대상은 `purpose`와 `details`뿐이다. `actor`는 가명화되고 나머지 필드(식별자·타임스탬프)는 그대로
  저장된다 — **PII를 다른 필드에 넣지 말 것.**
- 봉인 이벤트의 `record_id`는 유일해야 한다(중복 → `AuditValidationError`, 기존 키는 덮어쓰지 않음).
- `mask_text`/`mask_record`가 돌려주는 `findings` 리스트에는 **원본 PII 값이 들어 있다. 절대 로그에 남기지 말 것.**

**무결성 운영**
- 이 체인은 키 없는 해시체인이다. 내부 변조·중간 줄 삭제는 `verify`가 잡지만, **파일 전체 재작성이나 꼬리
  절단은 `verify` 단독으로 탐지되지 않는다**(스펙 §4.2 "무결성 모델과 잔여 위험").
- **외부 앵커를 운영할 것**: append한 엔트리의 `seq:entry_hash`를 소비자 쪽 로그에 남기고, 점검 시
  `python -m audit_engine verify --expect-tail <seq>:<hash>`로 대조한다.
- `report`의 `orphan_keys`(체인에 없는 볼트 키)와 `unaudited_shred`(키는 사라졌는데 `audit_shred` 기록이 없음)는
  기록 삭제·CLI 밖 파기의 신호다. 둘 다 종료코드 1.

**장애 대응(런북) — append 도중 크래시**
1. 마지막 줄이 잘린 채 남으면 다음 기동의 `HashChain.open`이 `ChainCorruptError`로 **거부**한다(정상 동작).
2. `python -m audit_engine verify`로 확인 → `reason="malformed_line"`, `failed_seq=N`.
3. **잘린 마지막 줄만** 제거해 복구한다. 단, **절단은 공격과 구분되지 않는다.** 먼저 사건을 기록
   (누가·언제·왜 잘렸는지, 앵커된 마지막 `seq:entry_hash`, 파일 해시)한 뒤에 손대고, 복구 후
   `verify --expect-tail`로 앵커와 대조한다.
4. `seq_gap`·`entry_hash_mismatch`는 크래시로 생기지 않는다. 변조로 간주하고 보안 사고로 처리한다.

## 테스트

```powershell
..\..\prism\Scripts\python.exe -m pytest audit-engine
```
