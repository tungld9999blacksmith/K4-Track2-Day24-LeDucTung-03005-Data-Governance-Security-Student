# Verification — trước khi nộp

- **OS / Python / Gitleaks version:** Windows 11 Home 10.0.26300 (native, chạy qua Git Bash — lưu ý README nói Windows native chưa được pilot); Python 3.12.5 trong `.venv` tạo bằng `uv 0.12.19`; Gitleaks **8.30.1** (`gitleaks version`); pre-commit 4.6.2. Cần đặt `PYTHONUTF8=1` để console Windows in được tiếng Việt.
- **Môi trường bằng uv (thay cho pip trong README):**
  ```
  uv venv .venv --python 3.12
  uv pip install -r requirements.txt pre-commit pip-tools
  uv pip compile --universal --generate-hashes -o requirements.lock requirements.txt
  uv pip install --require-hashes -r requirements.lock      # -> Checked 11 packages
  ```
  `requirements.lock`: 11 package, mọi package có `--hash=sha256:` (`--universal` để lock dùng được cả trên Linux/WSL của grader; `colorama` có marker `sys_platform == 'win32'`). `.venv` do uv tạo không có `pip`, nên `python -m pip install --require-hashes` được thay bằng lệnh `uv pip install --require-hashes` tương đương.
- **`python -m pytest tests/ -q`:** `33 passed`.
  - `tests/test_pii.py -s`: `gold=118 pred=118 tp=118`, **precision=1.000 recall=1.000**.
  - `test_injection.py`: 8/8 (4 biến thể × `support_l1`, `dpo`); `test_split.py`, `test_obo.py` (5), `test_policy.py` (4), `test_ledger.py` (3), `test_supply_chain.py` (3) pass.
- **`pre-commit run --all-files`:** `Detect hardcoded secrets....Passed` (hook `gitleaks-system`, `rev: v8.30.1`, `pass_filenames: false`).
- **Gitleaks:** `gitleaks git --config .gitleaks.toml --redact --verbose .` -> 1 finding `lab24-synthetic-token` ở commit `1bdd849`, exit 1 (dự kiến, token giả). `gitleaks dir --config .gitleaks.toml .` -> no leaks found, exit 0. Chi tiết: `reports/secrets-incident.md`.
- **Ledger verify:** `verify(Path('reports/ledger.jsonl'))` -> `True` (45 dòng, mọi dòng có `reason`, `on_behalf_of`, `run_id`, `expires_at`). Tamper demo trên **bản sao** của ledger: sửa dòng 11 `decision` deny -> allow mà không tính lại hash -> `verify()` = `False`.
- **Before/after:** `reports/attack-before.log` 299 byte, chứa record synthetic `KH-000999` (POST `/reconcile`, chạy khi runner còn là stub). `reports/attack-after.log` 0 byte: sau `pytest`, reset sink, chạy `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"`. Ledger dòng 45: `http_post` deny, `on_behalf_of: dpo`, reason `deny: restricted data with egress enabled`.
- **Các lỗi còn lại / ghi chú:**
  - Không có test fail. Lần đầu chạy agent preflight báo "Sink chưa chạy" — lỗi setup dự kiến, hết khi chạy `python sink/sink.py`.
  - Ledger hash chain không phát hiện xoá dòng cuối hoặc viết lại toàn bộ chuỗi (không có mốc tin cậy ngoài) — giới hạn đã nêu trong đề.
  - `--as` chỉ là principal mô phỏng; không có authentication thật.
  - Bonus (OPA/Cedar, GLiNER, MCP rug pull, delete cascade): không làm.
