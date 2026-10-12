# Secret giả trong lịch sử Git — checkpoint 4

- **Scanner và phiên bản:** Gitleaks v8.30.1 (`gitleaks version` -> `8.30.1`, binary Windows x64 từ release chính thức, SHA-256 `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e` khớp file checksums của release), config `.gitleaks.toml` (default rules + rule `lab24-synthetic-token`).
- **Commit chứa token giả:** `1bdd849922156c868a5ee9293d68f5b72e242d2c` ("chore: seed student lab with synthetic secret exercise"). File bị xoá ở commit sau `ece6ca4`.
- **File, rule và kết quả quét lịch sử:** `gitleaks git --config .gitleaks.toml --redact --verbose .` -> 4 commits scanned, **leaks found: 1**, exit code 1 (dự kiến):
  ```
  RuleID:      lab24-synthetic-token
  File:        lab-fake-secret.txt
  Line:        1
  Commit:      1bdd849922156c868a5ee9293d68f5b72e242d2c
  Fingerprint: 1bdd849922156c868a5ee9293d68f5b72e242d2c:lab-fake-secret.txt:lab24-synthetic-token:1
  Secret:      REDACTED
  ```
  Đây là token giả, vô hiệu dạng `LAB24-DEMO`, được cài sẵn làm bài tập — không phải sự cố bảo mật thật.
- **Kết quả quét file hiện tại:** `gitleaks dir --config .gitleaks.toml .` -> `no leaks found`, exit code 0. `pre-commit run --all-files` (hook `gitleaks-system`, `rev: v8.30.1`, `pass_filenames: false`) -> `Detect hardcoded secrets ... Passed`.
- **Nếu đây là credential thật, cần xử lý thế nào:**
  1. Thu hồi / rotate credential ngay tại hệ thống phát hành (revoke token, cấp token mới, cập nhật nơi dùng hợp lệ qua secret manager).
  2. Kiểm log truy cập của credential từ thời điểm commit `1bdd849` để xác định có bị lạm dụng không; xử lý theo quy trình sự cố (thông báo owner/DPO nếu liên quan dữ liệu cá nhân).
  3. Sau khi đã rotate, mới cân nhắc rewrite lịch sử (`git filter-repo`) và yêu cầu các bản fork/clone đồng bộ lại — đây là dọn dẹp, không phải biện pháp khắc phục.
  4. Thêm fingerprint vào `.gitleaksignore` chỉ khi credential đã bị vô hiệu, để scanner không báo lại.
- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:** Xoá file ở `ece6ca4` không xoá blob khỏi lịch sử: ai có clone/fork, CI cache hay mirror vẫn đọc được token ở `1bdd849`. Credential chỉ hết nguy hiểm khi bị **thu hồi/rotate** ở phía hệ thống cấp. Pin dependency bằng `requirements.lock` (`--generate-hashes`, cài bằng `--require-hashes`) chống package bị thay thế/typosquat, và hook pre-commit Gitleaks chặn secret **mới** trước khi commit — cả hai đều là biện pháp phòng ngừa cho tương lai, không vô hiệu hoá được một secret đã lộ.
