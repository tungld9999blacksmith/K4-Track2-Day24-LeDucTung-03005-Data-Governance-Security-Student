"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def load_principals(path: Path | None = None) -> dict[str, dict]:
    """Nguồn tin cậy mô phỏng cho OBO — không đọc principal từ nơi nào khác."""
    return json.loads((path or PRINCIPALS_FILE).read_text(encoding="utf-8"))


def _parse_expiry(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def check(context: PolicyContext) -> tuple[bool, str]:
    # Rule tối thiểu đứng đầu: không quyền OBO nào mở được restricted + egress.
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, (f"deny: restricted data with egress enabled "
                       f"(tool={context.requested_tool or 'unknown'}, owner={context.agent_owner})")

    principal = load_principals().get(context.principal_id)
    if principal is None:
        return False, f"deny: unknown principal {context.principal_id!r}"

    expires_at = _parse_expiry(context.expires_at)
    if expires_at is None:
        return False, f"deny: missing or invalid expires_at {context.expires_at!r}"
    if expires_at <= datetime.now(timezone.utc):
        return False, f"deny: delegation expired at {context.expires_at}"

    if context.request_purpose not in principal["purposes"]:
        return False, (f"deny: purpose {context.request_purpose!r} not allowed "
                       f"for principal {context.principal_id}")

    effective = set(principal["allowed_tools"]) & set(context.agent_scopes)
    if context.delegation_depth > 0:
        effective &= set(context.parent_scopes)
    if context.requested_tool not in effective:
        return False, (f"deny: tool {context.requested_tool!r} outside effective scope "
                       f"{sorted(effective)} for principal {context.principal_id} "
                       f"(depth={context.delegation_depth})")

    return True, (f"allow: {context.requested_tool} for {context.principal_id} "
                  f"purpose={context.request_purpose} class={context.data_classification} "
                  f"egress={context.egress_enabled}")
