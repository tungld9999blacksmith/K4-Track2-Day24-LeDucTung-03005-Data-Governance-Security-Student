"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

AGENT_ID = "lab24-agent"
RUN_TTL = timedelta(minutes=15)
RUN_A_SCOPES = ("search_docs",)
RUN_B_SCOPES = ("search_docs", "read_customer")
_TICKET_FILE_RE = re.compile(r"^ticket-(\d+)[a-z]?\.md$")


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


@dataclass(frozen=True)
class _Run:
    """Identity của một run con: ai ra lệnh, run nào, quyền tối đa, hạn dùng."""
    principal_id: str
    run_id: str
    agent_owner: str
    scopes: tuple[str, ...]
    expires_at: str
    ledger_path: Path


def _args_hash(args: dict) -> str:
    payload = json.dumps(args, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _authorize(run: _Run, tool: str, args: dict, *, classification: str,
               purpose: str, egress: bool) -> bool:
    """PEP: policy.check() rồi ghi ledger (allow lẫn deny) TRƯỚC khi tool chạy."""
    context = policy.PolicyContext(
        data_classification=classification,
        request_purpose=purpose,
        agent_owner=run.agent_owner,
        delegation_depth=0,
        egress_enabled=egress,
        principal_id=run.principal_id,
        requested_tool=tool,
        agent_scopes=run.scopes,
        parent_scopes=(),
        expires_at=run.expires_at,
    )
    allowed, reason = policy.check(context)
    ledger.append({
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": f"{AGENT_ID}/{run.agent_owner.rsplit('/', 1)[-1]}",
        "run_id": run.run_id,
        "on_behalf_of": run.principal_id,
        "expires_at": run.expires_at,
        "tool": tool,
        "args_hash": _args_hash(args),
        "classification": classification,
        "purpose": purpose,
        "egress": egress,
        "decision": "allow" if allowed else "deny",
        "reason": reason,
    }, run.ledger_path)
    return allowed


def _ticket_ids(docs: list[dict]) -> list[int]:
    """Chỉ ID số lấy từ TÊN FILE được đi qua boundary A -> B."""
    ids = set()
    for doc in docs:
        match = _TICKET_FILE_RE.match(doc["id"])
        if match:
            ids.add(int(match.group(1)))
    return sorted(ids)


def _customers_for_tickets(ticket_ids: list[int]) -> list[str]:
    """Nguồn tin cậy: related_tickets trong customers.json, không phải free text."""
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    wanted = set(ticket_ids)
    return [c["customer_id"] for c in customers if wanted & set(c.get("related_tickets", []))]


def _run_a(message: str, llm, run: _Run) -> tuple[list[dict], list[int], bool]:
    """Run A: chỉ chạm untrusted content. Không private store, không egress."""
    if not _authorize(run, "search_docs", {"query": message}, classification="internal",
                      purpose="summarize-tickets", egress=False):
        return [], [], False
    docs = tools.search_docs(message)
    injected = llm.find_injection("\n\n".join(d["text"] for d in docs))
    # Chỉ giữ cờ có/không có chỉ thị; customer_ids/target_url của attacker bị bỏ.
    return docs, _ticket_ids(docs), injected is not None


def _run_b(ticket_ids: list[int], injection_seen: bool, run: _Run) -> list[dict]:
    """Run B: nhận list[int] đã sanitize, đọc private data qua PEP."""
    records = []
    for customer_id in _customers_for_tickets(ticket_ids):
        if not _authorize(run, "read_customer", {"customer_id": customer_id},
                          classification="restricted", purpose="support-reply", egress=False):
            continue
        try:
            records.append(tools.read_customer(customer_id))
        except tools.ToolError:
            continue

    # Chỉ thị injection đòi gửi dữ liệu ra ngoài: vẫn đưa qua PEP để có bằng
    # chứng deny; URL đích là hằng của lab, không lấy từ free text attacker.
    if injection_seen and records:
        url = f"http://{tools.ALLOWED_EGRESS_HOST}:{tools.ALLOWED_EGRESS_PORT}/reconcile"
        body = {"records": records}
        if _authorize(run, "http_post", {"url": url, "body": body}, classification="restricted",
                      purpose="support-reply", egress=True):
            tools.http_post(url, body)
    return records


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = (Path(log_dir) if log_dir else REPORTS_DIR) / "ledger.jsonl"
    expires_at = (datetime.now(timezone.utc) + RUN_TTL).isoformat()
    request_id = uuid.uuid4().hex[:12]

    run_a = _Run(principal_id, f"{request_id}-a", f"{AGENT_ID}/run-a", RUN_A_SCOPES,
                 expires_at, ledger_path)
    docs, ticket_ids, injection_seen = _run_a(message, llm, run_a)

    run_b = _Run(principal_id, f"{request_id}-b", f"{AGENT_ID}/run-b", RUN_B_SCOPES,
                 expires_at, ledger_path)
    _run_b(ticket_ids, injection_seen, run_b)

    # Câu trả lời cho người dùng đi qua PII gate trước khi rời agent.
    redacted_docs = [{"id": d["id"], "text": pii.redact(d["text"])} for d in docs]
    return pii.redact(llm.summarize(redacted_docs))
