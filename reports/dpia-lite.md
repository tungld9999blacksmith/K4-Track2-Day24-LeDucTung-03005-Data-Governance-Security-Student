# DPIA-lite — checkpoint 5

Phạm vi: agent hỗ trợ khách hàng trong lab Day 24, chạy `--mock` trên dữ liệu **synthetic**. Đây là đánh giá tác động rút gọn cho bài lab, không phải DPIA cho hệ thống production.

1. **Loại dữ liệu và phân loại:**
   - `data/customers.json`: họ tên, CCCD (12 số), SĐT, số tài khoản ngân hàng, email, `related_tickets` → **restricted** (dữ liệu định danh + tài chính).
   - `corpus/*.md`: nội dung ticket, có thể chứa SĐT/STK do khách tự ghi, và có thể chứa chỉ thị độc hại (ticket 901–904b) → **internal, untrusted**.
   - `data/principals.json`: vai trò và quyền mô phỏng → cấu hình tin cậy.
   - `reports/ledger.jsonl`: metadata quyết định, chỉ `args_hash`, không chứa PII thô.
2. **Mục đích xử lý và principal:**
   - `summarize-tickets`: tổng hợp ticket — mọi principal (`support_l1`, `billing`, `dpo`) được `search_docs`.
   - `support-reply`: đọc hồ sơ khách gắn với ticket — chỉ principal có `read_customer` (`dpo`; `billing` có tool nhưng purpose không gồm `support-reply` nên bị deny). `support_l1` không bao giờ đọc record restricted.
   - Không có mục đích nào cho phép gửi dữ liệu restricted ra ngoài.
3. **Dữ liệu đi qua những run/tool nào, endpoint nào:**
   - **Run A** (`lab24-agent/run-a`, scope `search_docs`): đọc `corpus/`; chỉ xuất `list[int]` ticket ID từ tên file và cờ "có chỉ thị đáng ngờ". Không chạm private store, không egress.
   - **Run B** (`lab24-agent/run-b`, scope `search_docs, read_customer`): ticket ID → customer qua `related_tickets` → `read_customer` sau khi PEP allow. Không nhận free text của attacker.
   - **Egress:** `http_post` chỉ tới được `http://127.0.0.1:10024` (allowlist cứng ở `agent/tools.py`); với dữ liệu restricted, PEP luôn deny nên không có request nào tới sink.
   - **Output cho người dùng:** tóm tắt đi qua `pii.redact()`.
   - Không có endpoint ngoài localhost; không gọi model thật.
4. **Bằng chứng deny/allow và giới hạn của mock:**
   - `reports/attack-before.log`: baseline gửi record `KH-000999` ra sink. `reports/attack-after.log`: rỗng sau containment, cùng query, chạy `--as dpo`.
   - `reports/ledger.jsonl`: dòng 2–22 `read_customer` deny cho `support_l1`; dòng 24–44 allow cho `dpo` (khách gắn ticket hợp lệ); dòng 45 `http_post` **deny**, reason `deny: restricted data with egress enabled`, `on_behalf_of: dpo`. `verify()` = True.
   - `tests/test_split.py`: `KH-000777` (chỉ nêu trong free text) không bao giờ bị đọc.
   - **Giới hạn:** `--as` chỉ chọn principal giả lập, không phải xác thực; mock LLM deterministic chỉ mô phỏng hành vi tuân theo chỉ thị; dữ liệu synthetic; regex PII không phát hiện tên/địa chỉ; `dpo` vẫn đọc hợp lệ hồ sơ `KH-000999` vì ticket 901–905 được gắn vào hồ sơ đó (split không chặn được, chỉ PEP chặn egress); ledger hash chain không phát hiện xoá dòng cuối hoặc viết lại toàn bộ file khi không có mốc tin cậy bên ngoài; TTL 15 phút được runner tự cấp, chưa có cơ quan cấp phát token thật.
