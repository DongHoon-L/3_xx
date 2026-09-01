# PROCESS.md — 작업 기록

> 이 프로젝트에서 수행한 모든 작업을 시간순으로 기록한다.
> 형식: 날짜 / 단계 / 한 일 / 발견 / 결정 / 다음 단계

---

## 2026-09-01 — 세션 1

### [00] 작업 준비
- `CLAUDE.md`(전역 + 프로젝트) 확인. 프로젝트 규칙: AI 플랫폼 보안 엔지니어링 가이드라인(신뢰 경계 명시, 모델 출력 비신뢰, fail-closed, 허용목록, 비밀정보 미출력, 최소 권한, 감사 로그 보존).
- 작업 방식 합의: 구현 전 `superpowers` 워크플로우(brainstorming → writing-plans → TDD) 사용.
- 저장소 초기 상태: `CLAUDE.md`만 존재. 브랜치 `main`, 커밋 2개(`init branch`, `chore: clear inbox`).

### [01] 요구사항 접수
사용자 요구:
1. RAG 시스템에 `3_5`의 감사 엔진(audit engine)을 **Add-on**으로 결합.
2. `3_xx/rag-agent/` ← `../../ch1/1_5`에 있는 rag-agent를 가져온다 (사용자: "아마도").
3. `3_xx/audit-engine/` ← `../3_5`의 audit-engine을 **개선 후** 가져온다.
   - 사용자 표기 `../ch03/3_5`는 실제로 존재하지 않음 → `../3_5` (= `prism/ch3/3_5`)로 확정.
4. 모든 작업을 `PROCESS.md`에 기록.

### [02] 소스 탐색 (brainstorming — 컨텍스트 파악)

#### RAG 측 후보 (두 곳 발견)
| 후보 | 위치 | 구성 | LLM | 비고 |
|---|---|---|---|---|
| A | `ch1/1_xx/` | `1-documents.py` → `2-embeddings.py` → `3-1-llm.py` → `3-2-rag.py`(InMemoryVectorDB, cosine) → `4-agent.py`(규칙 기반 도구 라우팅: list_documents / document_summary / rag / direct_answer) → `5-api.py`(FastAPI: `/agent`, `/rag`, `/documents`, `/tools`, `/health`, 채팅 GUI) | Gemini (`GEMINI_API_KEY` 필수, Mock 없음) | API 제목이 문자 그대로 **"RAG Agent Demo API"** |
| B | `ch1/1_5/` | `lab01_vulnerable_chatbot.py`(SimpleLLM + RAGDatabase dict 조회 + VulnerableChatbotService), `lab01_1_*.py`(.env 로더 추가판), `lab03_threat_modeling_lab.py`(SR-01/02/03 통제 + 추적표), `app.py`(Flask 채팅 UI, RAG 미연결) | OpenRouter (`OPENROUTER_API_KEY`), 키 없으면 **결정적 Mock** | "취약한 RAG 챗봇" 실습. 에이전트/도구 라우팅 없음 |

- `ch1/1_5/.env`에 실제 API 키 존재 → **절대 복사/커밋 금지**. 값은 열람하지 않음(키 이름만 확인).

#### 감사 엔진 (`ch3/3_5/src/audit_engine/`, 7개 모듈 335줄)
| 모듈 | 내용 |
|---|---|
| `schema.py` | `AuditEvent` 5W1H frozen dataclass (timestamp, actor, role, department, action, asset, record_id, source_ip, purpose, result), `AuditStorageEngine` JSON 입출력 |
| `hash_chain.py` | `AuditLogEntry`, `AuditChainEngine` (build/verify/compute_hash sha256·sha512·sha3_256, save/entries_from_raw) |
| `retention.py` | `AuditRetentionEngine` — 정책 JSON(action별 보관일수/법적근거) → `retention_until` |
| `crypto.py` | `CryptoShredderEngine` — **자체 구현 SHA-256 keystream XOR** 암호화, JSON 파일 Key Vault, `shred_key` |
| `masking.py` | 정규식 PII 마스킹(email/phone/rrn/card) + 직접 필드(name/email/phone/address) |
| `deidentification.py` | HMAC 가명화(`pseudonymize_*`), `anonymize_record` |
| (파이프라인) `lab10_step06_integrated_pipeline.py` | 배치 CLI: 로드 → 스키마 검증 → 해시체인 → 보존 → 가명화+마스킹 → 암호화+자기검증 → 병합 → 키 파기 검증 → JSON/MD 보고서 |

- 주의: `lab10_step05_audit_engine.py`는 `src/audit_engine/`를 **삭제 후 재생성**하는 빌더이며 `masking.py`/`deidentification.py`는 생성하지 않음(수동 추가된 모듈). 재실행 시 유실 위험 — 원본 폴더는 건드리지 않음.

#### 감사 엔진 개선 후보 (탐색 중 발견, 설계 단계에서 범위 확정 예정)
1. **[높음] 자체 구현 암호화** (`crypto.py`): SHA-256 CTR-XOR 스트림 암호, 인증 태그 없음(변조 탐지 불가). CLAUDE.md §2 "never roll your own crypto" 위반 → AES-256-GCM(`cryptography` 라이브러리)로 교체 후보.
2. **[높음] 가명화 비밀키 하드코딩**: `deidentification.py` 기본값 `b"audit-engine"`, 파이프라인 리터럴 `b"lab10-audit-pseudonym"` → 환경변수/시크릿 주입으로 변경 후보.
3. **[중간] Fail-open**: `retention.py`가 타임스탬프 파싱 실패 시 `datetime.now()`로 조용히 대체 → 명시적 실패/이상 플래그로 변경 후보.
4. **[중간] 검증 결과 비추적성**: `verify_chain`이 bool만 반환 → 어느 인덱스에서 깨졌는지 반환(CLAUDE.md §9 "denials debuggable").
5. **[중간] 스키마 검증 부재**: `AuditEvent(**item)` 외 필수값(빈 actor, 타임스탬프 형식) 검증 없음.
6. **[중간] 배치 전용 API**: `build_chain(events)`는 리스트 전체 재계산 → 실시간 요청마다 append하는 증분 체인 API 없음 (Add-on에 필수).
7. **[낮음] Key Vault 동시성**: 파일 read-modify-write, 잠금 없음 → 웹 서버 동시 요청 시 경쟁 조건.
8. **[낮음] 파이프라인이 `lab10_step01_schema_generator.AuditDummyGenerator`(더미 생성기)에 의존해 스키마 검증 → 불필요한 결합.

#### 환경
- PATH Python: 3.14.5 (`C:/Python314`). `cryptography`, `google-generativeai` 없음.
- 프로젝트 venv: `prism/prism/` (Python 3.14.5) — `cryptography 50.0.0`, `fastapi`, `flask`, `google-generativeai 0.8.6`, `google-genai`, `requests`, `python-dotenv` 설치됨. **`pytest` 미설치** (양쪽 모두).
- `prism/` 상위는 git 저장소가 아님. `3_xx`만 독립 git 저장소.

### [03] 다음 단계
- 사용자에게 확인할 항목(한 번에 하나씩): ① rag-agent가 A/B 중 어느 것인지 ② "Add-on"의 의미(실시간 감사 미들웨어 vs 배치 검증 vs 둘 다) ③ 감사 엔진 개선 범위 ④ 원본 폴더 불변 / 복사 방식 확인.

### [04] 결정 — rag-agent 소스
- 질문: rag-agent 소스가 `ch1/1_xx`(RAG Agent Demo API)인지 `ch1/1_5`(취약 RAG 챗봇)인지?
- 사용자 답: **"그냥 새로 구현하자. 없는 거 같아."**
- 결정: `3_xx/rag-agent/`는 기존 코드를 복사하지 않고 **신규 구현**한다. `ch1/1_5`, `ch1/1_xx`는 참고 자료로만 사용(패턴: OpenRouter+Mock 폴백, 도구 라우팅 에이전트, FastAPI 엔드포인트).
- 영향: 프로젝트 범위가 "포팅 + 결합"에서 "신규 RAG 에이전트 + 감사 엔진 개선 포팅 + 결합"으로 확장됨. 설계 질문 계속 진행.

### [05] 결정 — LLM 연결: WSL 로컬 모델 (llama.cpp 서버)
- 질문: 신규 rag-agent의 LLM 제공자? (OpenRouter+Mock / Gemini / Claude / Mock 전용)
- 사용자 답: **"WSL에 모델 하나 올려뒀는데 거기서 API 받아서 쓰면 안 돼?"** → 가능. 로컬 모델 사용으로 결정.
- WSL 조사 결과 (Ubuntu-24.04, 사용자 `server`):
  - 런타임: `~/.llama-app/llama` = **llama.cpp `llama-server` 배포판(llama.app)**, version 0.2.0-dev build 10612. PATH 미등록(절대경로로 실행).
  - 모델 캐시: `huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF:Q4_K_XL` (약 18 GB). 별도로 transformers용 safetensors 30 GB + `~/qwen/run_model.py`(bitsandbytes 4bit 대화 REPL, 서버 아님).
  - GPU: NVIDIA RTX 5090 Laptop 24 GB → Q4_K_XL 18 GB 적재 가능.
  - 이전 실행 이력: `llama serve -hf huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF:UD-Q4_K_XL`
  - 서버 기본값: `--host 127.0.0.1`, `--port 8080`, OpenAI 호환 `/v1/chat/completions`, `/v1/models`, `/health`. `--api-key` 옵션 지원. `--embedding`은 전용 임베딩 모델 전용 모드(채팅 모델과 동시 사용 불가).
  - **현재 서버는 꺼져 있음** (WSL 리스닝 포트: DNS 53뿐). 사용 시 수동 기동 필요.
- 설계 반영:
  - LLM 클라이언트 = **OpenAI 호환 HTTP 클라이언트**(`requests`) — `LLM_BASE_URL`(기본 `http://localhost:8080/v1`), `LLM_MODEL`, `LLM_API_KEY`(선택). 같은 클라이언트로 OpenRouter 등 다른 OpenAI 호환 서버도 전환 가능.
  - 테스트용 **결정적 Mock 제공자**(`LLM_PROVIDER=mock`) 별도 유지 → 네트워크/GPU 없이 테스트.
  - 임베딩 API가 없으므로 **검색은 로컬 결정적 방식(TF-IDF/BM25 코사인, 순수 파이썬)** 채택 예정 — 두 번째 모델 서버 불필요, 테스트 결정적.
  - 서버 기동 명령(문서화 예정): `wsl.exe -- ~/.llama-app/llama serve -hf huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF:Q4_K_XL --port 8080` (Windows→WSL2 localhost 포워딩으로 접근; 안 되면 `--host 0.0.0.0` 또는 WSL IP 사용).
  - 보안 메모: abliterated(안전 튜닝 제거) 모델은 주입된 지시에 더 잘 따름 → 모델 출력 비신뢰 원칙(CLAUDE.md §7)과 감사 추적의 필요성이 더 커짐. 모델 선택 자체는 사용자 결정.

### [06] 결정 — Add-on 형태
- 질문: Add-on = ① 실시간 감사 미들웨어 + 검증 CLI / ② 배치 사후 검증만 / ③ 에이전트 도구로 노출?
- 사용자 답: **① 실시간 감사 미들웨어 + 검증 CLI** 선택.
- 의미: rag-agent의 매 요청(질문·가드 판정·도구 선택·검색 문서·LLM 응답)을 5W1H `AuditEvent`로 만들어 요청 처리 중 해시체인에 **즉시 append**(PII 마스킹·가명화·암호화 포함). 별도 CLI(`python -m audit_engine verify|report`)로 체인 무결성/보존/키파기 보고서 생성.
- 구조적 필수 요건 도출: (a) 증분 append 체인 API + 마지막 해시 영속화(JSONL), (b) 동시 요청 대비 파일 쓰기 잠금/원자적 쓰기, (c) 감사 실패 시 요청 처리 정책(fail-closed 여부) 결정 필요.

### [07] 결정 — 감사 엔진 개선 범위
- 사용자 선택(3개 모두): ① **암호화 교체 → AES-256-GCM**(`cryptography`, venv 기설치; Crypto-Shredding 의미론 유지) ② **가명화 비밀키 환경변수 주입**(`AUDIT_PSEUDONYM_SECRET` 필수, 없으면 기동 거부) ③ **Fail-closed 검증 + 디버깅 가능한 검증 결과**(AuditEvent 필수값/ISO-8601 UTC 검증, retention fail-open 제거, `verify_chain` 실패 위치·사유 반환).
- 항상 포함(구조상 필수): 증분 append 체인 + 마지막 해시 영속화, 파일 쓰기 잠금/원자적 쓰기, `AuditDummyGenerator` 의존 제거.
- 원본 `ch3/3_5/`는 수정하지 않음.

### [08] 결정 — 행위자(Who) 식별
- 사용자 선택: **Bearer 토큰 정적 허용목록 → principal**. `RAG_API_KEYS="tok:actor:role,..."` 환경변수. 토큰 없음/불일치 → 401 + `auth_denied` 감사 이벤트(actor는 `"<unauthenticated>"`가 아닌 별도 표기 규칙 필요 — 설계에서 확정). 신뢰 경계: 토큰은 서버 측 비밀, 클라이언트 주장 신원 아님.

### [09] 결정 — 구조 접근법
- 후보: ① 독립 패키지 2개 + 훅 인터페이스 / ② 단일 패키지(서브패키지) / ③ 사이드카 HTTP 서비스
- 사용자 선택: **① 독립 패키지 2개 + 훅 인터페이스**. `audit-engine/`(패키지 `audit_engine`, RAG 무관, `AuditRecorder` + CLI)와 `rag-agent/`(패키지 `rag_agent`, `audit_engine`에 의존, `audit_hook.py`에서만 recorder 호출). 각각 `pyproject.toml` + editable install.
- 다음: 상세 설계를 섹션별로 제시하고 승인받은 뒤 스펙 문서 작성 → writing-plans.

### [10] 설계 A 승인 — 저장소 구조 + audit-engine
- 사용자 승인. 확정 사항: `AuditEvent` = 3_5의 10필드 + `details: dict[str,str]`; `validate()` fail-closed; 체인은 append-only JSONL(`seq/record/sealed/retention/previous_hash/entry_hash`), 해시가 암호문까지 보호; AES-256-GCM(AAD=record_id) + KEK(`AUDIT_KEK_B64`)로 DEK 래핑한 KeyVault; 가명화 secret env 필수; retention fail-open 제거; `AuditRecorder.record(event, sensitive)` 단일 진입점, 예외 전파; CLI `verify|report|shred|unseal|keygen`, shred/unseal도 체인에 감사 기록.

### [11] 확인 — 사용 venv
- 사용자: **"../../prism이 venv야"** → `3_xx` 기준 `../../prism` = `C:\Users\shapd\Documents\prism\prism` (앞서 [02]에서 확인한 venv와 동일: Python 3.14.5, cryptography 50.0.0, fastapi, requests, python-dotenv 설치됨, pytest 미설치).
- 반영: 설치/실행 명령은 모두 이 venv 인터프리터(`..\..\prism\Scripts\python.exe`)로 수행. README/스펙에 명시.

### [12] 설계 B 승인 — rag-agent + 결합 + 검증
- 사용자 승인. 확정: 요청당 감사 이벤트 1건(`record_id`=request UUID) + `details`/`sealed`로 상세 보관; recorder 실패 시 503 + 답변 폐기(fail-closed); LLM 오류 시 Mock 폴백 없이 502; Bearer 허용목록 인증; SR-01/02/03 가드 + 출력 필터(lab03 패턴 이식); 로컬 TF-IDF 검색; OpenAI 호환 클라이언트(WSL llama-server) + MockLLM; 규칙 기반 도구 라우팅(허용목록 3종); pytest를 dev 의존성으로 venv에 설치.
- 다음: 스펙 문서 작성(`docs/superpowers/specs/2026-09-01-rag-audit-addon-design.md`) → 셀프 리뷰 → 커밋 → 사용자 검토 → writing-plans.

### [13] 스펙 문서 작성 + 브랜치 생성
- 브랜치: `feat/rag-audit-addon` 생성 (main 직접 수정 회피).
- 스펙: `docs/superpowers/specs/2026-09-01-rag-audit-addon-design.md` 작성 (설계 A+B 전체, 위협 스케치, 테스트 목록, 실행 절차, 결정 기록).
- 셀프 리뷰: placeholder 없음; recorder 순서·CLI·훅 매핑 상호 일치 확인; 누락됐던 문서 코퍼스(§5.9)와 `.env.example` 규칙 추가.
- 도구 메모: 약 20KB heredoc을 Bash로 쓰면 명령이 잘려 실패함 → 큰 파일은 Write 도구 사용.
- 다음: 스펙 커밋 → 사용자 검토 → `superpowers:writing-plans`.

### [14] 스펙 승인
- 커밋 `3b86ec7` (feat/rag-audit-addon): 스펙 + PROCESS.md.
- 사용자: 스펙 검토 후 **승인 — 구현 계획 작성**. brainstorming 종료.
- 다음: `superpowers:writing-plans`로 단계별 구현 계획 작성 (TDD 순서로).

### [15] 구현 계획 작성 (writing-plans)
- 스펙이 독립 서브시스템 2개를 다루므로 계획을 2개로 분리:
  - `docs/superpowers/plans/2026-09-01-audit-engine.md` — 9개 태스크 (스캐폴딩 → schema → chain → crypto → masking/deidentification → retention → config → recorder → cli), 예상 85 tests.
  - `docs/superpowers/plans/2026-09-01-rag-agent.md` — 10개 태스크 (스캐폴딩/코퍼스 → auth → guard → retriever → llm → config → agent → audit_hook → api → README/.env.example/스모크), 예상 99 tests.
- 각 태스크: 실패 테스트 → 확인 → 구현 → 통과 → PROCESS.md 기록 + 커밋 (TDD). 전체 코드가 계획에 포함됨.
- 셀프 리뷰: 스펙 §4~§8 전 항목 태스크 매핑 확인; 누적 테스트 수 오기 수정; `test_api.py`의 conftest 모듈 import(importlib 모드 불가) 제거; 스펙 대비 의도된 차이 3건(`errors.py`/`AuditStorageError`, 코퍼스 패키지 내 배치, `--factory` 실행, `AgentTrace.question`)을 각 계획 Global Constraints에 명시.
- 다음: 사용자에게 실행 방식(subagent-driven vs inline) 확인 후 Plan 1부터 실행.

### [16] 실행 준비 — 커밋 저자 정책, 계획 결함 수정, SDD 시작
- 사용자 지시: "1번(subagent-driven)으로 중단 없이 끝까지 구현, 커밋은 나만 contributor로". → 모든 커밋에서 `Co-Authored-By` 제거. 이미 만든 로컬 커밋 2개(미푸시)를 `git commit-tree`로 동일 트리·새 메시지로 재작성(`3cfe2a4` 스펙, `71d62de` 계획). 두 계획의 Global Constraints도 동일하게 수정.
- 사전 충돌 점검에서 계획 결함 1건 발견·수정: recorder가 record 전체에 `mask_record`를 적용하면 카드번호 정규식이 UUID `record_id`/hex 해시의 숫자 연속을 오탐할 수 있음(예: `11111111-2222-3333-4444-…` → `[CARD_MASKED]`, AAD/볼트 조회 파괴). → 마스킹을 `purpose`/`details`(자유 텍스트)로 한정하는 `protect_record`, 잔여 PII 검사 `residual_pii_count` 추가. 테스트도 체인 파일 전체 스캔 대신 record 자유 텍스트 필드 검사로 변경(hex 해시 오탐으로 인한 간헐 실패 방지). 스펙 §4.8의 "mask_record(event.to_dict())" 문구와의 차이는 의도된 것.
- SDD 워크스페이스: `.superpowers/sdd/2026-09-01-audit-engine/` (git-ignored). 원장 `progress.md`에 사전 점검표·판정 기록.
- 모델 선택: 구현자 haiku(계획에 전체 코드 포함 → 전사+테스트), 리뷰어 sonnet, 최종 전체 리뷰 fable.

### [P1-T1] audit-engine 스캐폴딩
- `pytest.ini`(importlib 모드), `.gitignore`, `audit-engine/pyproject.toml`, `errors.py`(예외 7종), `__init__.py` 작성. venv에 editable 설치 + pytest 설치.
- 테스트: `test_errors.py` 3 passed.

### [P1-T2] schema.py
- `AuditEvent`(10필드 + `details`), `validate()`(필수값·UTC Z 타임스탬프·details 문자열 맵), `utc_now`, `parse_timestamp`.
- 테스트: `test_schema.py` 13 passed.

### [P1-T3] chain.py
- 증분 JSONL 해시체인: `append`(lock+fsync), `verify`(실패 seq/사유: previous_hash_mismatch·entry_hash_mismatch·seq_gap·malformed_line), `open`(손상 시 ChainCorruptError), OSError→AuditStorageError.
- 테스트: `test_chain.py` 11 passed (변조 4종 포함).

### [P1-T4] crypto.py
- 3_5의 SHA-256 XOR 스트림 암호를 폐기하고 `cryptography` AESGCM으로 교체: `seal/unseal`(AAD=record_id), `KeyVault`(DEK를 KEK로 래핑, 원자적 쓰기, `shred`), `vault_record_ids`.
- 테스트: `test_crypto.py` 11 passed (AAD 불일치·키 오류·변조·잘못된 KEK 모두 실패 확인).
- 리뷰 수정: _save 실패 시 임시 파일 정리(try/finally) + 회귀 테스트.

### [P1-T5] masking.py / deidentification.py 이식
- `masking.py`는 3_5 원본 그대로. `deidentification.py`는 하드코딩 secret `b"audit-engine"` 제거, `secret` 필수(키워드 전용).
- 테스트: 10 passed (마스킹 후 재스캔 0, secret 의존성·필수성).

### [P1-T6] retention.py + 정책 JSON
- 3_5 정책 유지 + `agent_query`(1년)/`agent_query_blocked`·`auth_denied`(3년)/`audit_shred`·`audit_unseal`(5년) 추가. 타임스탐프 오류 시 `now()` 대체 제거 → 예외.
- 테스트: `test_retention.py` 8 passed.

### [P1-T7] config.py
- `AuditConfig.from_env`: `AUDIT_PSEUDONYM_SECRET`(≥16자)·`AUDIT_KEK_B64`(32B) 필수, 알고리즘 허용목록, 정책 파일 존재 검사. `repr`에 비밀값 미노출.
- 테스트: `test_config.py` 10 passed.

### [P1-T8] recorder.py + 공개 API
- `AuditRecorder.record`: validate → `protect_record`(actor 가명화 + purpose/details만 마스킹; 식별자·타임스탬프는 보존) → sensitive 봉인(중복 record_id 거부) → 보존 → chain.append. `unseal`로 조사용 복호화. `residual_pii_count`로 자유 텍스트 잔여 PII 0 확인.
- `__init__.py` 공개 API 정리.
- 테스트: audit-engine 전체 78 passed.

### [P1-T9] cli.py
- `verify`(실패 seq/사유 JSON), `report`(집계·만료·봉인/파기·잔여 PII 재스캔·이상 목록, `--out`), `shred --record-id|--expired --actor`, `unseal --record-id --actor`, `keygen`. shred/unseal은 `audit_shred`/`audit_unseal` 이벤트로 체인에 기록됨(파기 후 기록 순서 — 기록 실패 시 stderr에 error, exit 1).
- 테스트: audit-engine 전체 87 passed. audit-engine 계획 완료.
- 리뷰 수정: shred는 감사 이벤트를 먼저 기록(write-ahead, result shred_requested:<n>)한 뒤 키를 파기; report --out 쓰기 실패는 AuditStorageError로 정리 종료. 회귀 테스트 2건 추가.

### [P1 완료] audit-engine 계획 종료 (컨트롤러 기록)
- Task 1~9 모두 구현·리뷰 통과. 수정 라운드 2회: T4(볼트 임시 파일 정리), T9(shred 감사 이벤트 write-ahead + `--out` 실패 정리 종료). 최종 테스트 89 passed.
- 스펙 대비 의도된 변경(원장 판정): ① recorder 마스킹을 purpose/details로 한정 ② `shred`는 키 파기 **전에** `audit_shred`(result `shred_requested:<n>`) 기록 — 스펙 §4.9의 "파기 후 기록"보다 감사 가능성이 우선 ③ 예외 계층을 `errors.py`로 분리, `AuditStorageError` 추가.
- 리뷰에서 보류(Minor)된 항목은 `.superpowers/sdd/2026-09-01-audit-engine/progress.md` 원장에 기록, 최종 전체 리뷰에서 재판정.

### [P2-T1] rag-agent 스캐폴딩 + 코퍼스
- `rag-agent/pyproject.toml`(deps: fastapi, uvicorn, requests, python-dotenv, audit-engine), 합성 코퍼스 4건(weather/policy/api_guide(가짜 키)/poisoned(간접 인젝션)), `documents.py`(검증 로더). editable 설치.
- 테스트: `test_documents.py` 6 passed.
