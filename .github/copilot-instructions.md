## Repo snapshot

This repository implements a minimal HTTP/1.0 client for a teaching assignment (CSCI4406 HW2).
Key files and entry points:
- `Makefile` — build rules (target `make` produces `./http_client`).
- `src/http_client.c` — single-file C implementation of the client (TCP-only, HTTP/1.0).
- `scripts/test_cases.sh` — helper that fetches reference files with `curl`, builds the client, runs fetches and diffs outputs.
- `INSTALL.md` — platform notes for installing OpenSSL dev libraries (for the follow-up HTTPS task).

## Big-picture architecture

- Single-process CLI tool implemented in one C source file. There is no server or multiple components.
- Data flow: CLI parses `-u <url>` and `-o <output>` → `parse_url()` splits scheme/host/port/path → `connect_tcp()` opens TCP socket → send minimal HTTP/1.0 GET → receive bytes, detect header/body boundary (CRLFCRLF) and write body to disk.
- Design decisions visible in code:
  - Explicitly implements HTTP/1.0 semantics (Connection: close). No header parsing beyond boundary detection (":\r\n\r\n").
  - HTTPS is intentionally unimplemented; code exits early on `https` scheme and README/INSTALL document this as a teaching extension.

## Developer workflows (how to build, run, test)

- Build (Linux/macOS/WSL):
  - Ensure development OpenSSL packages if you plan to implement TLS (`INSTALL.md`). Current code doesn't require OpenSSL to build.
  - Run from repo root:
    ```
    make
    ```

- Run the client (example):
  - Fetch an http resource and save to file:
    ```
    ./http_client -u http://example.com/index.html -o index.html
    ```

- Test helper (uses `curl` to create references; HTTP-only client will fail for HTTPS until TLS added):
  - Ensure `curl` is installed then:
    ```
    sh scripts/test_cases.sh
    ```
  - `scripts/test_cases.sh` builds with `make` and writes outputs to `test_outputs/` and references to `test_refs/`.

## Project-specific patterns and conventions

- Single-file service: most logic lives in `src/http_client.c`. When modifying behavior (e.g., add TLS, header parsing), place new helper functions in this file or add small new sources and update `Makefile`'s `SRCS`/`OBJS`.
- Use of simple CLI flags via `getopt(argc, argv, "u:o:")` — follow this pattern when adding flags (`-v`, `-H`, `-A`) and keep usage printed by `print_usage()`.
- Networking: DNS + connect loop uses `getaddrinfo()` and attempts each addrinfo; maintain that pattern for portability (IPv4/IPv6).
- I/O: the code uses `recv()` and `fwrite()` with a sliding 4-byte window to detect CRLFCRLF. When extending header handling, search for the sliding-window logic and either replace or centralize into a header parser function.

## Integration points & extension hooks

- HTTPS/TLS: `parse_url()` sets `scheme` and `port`. Current code early-returns on `https`. To add TLS, integrate OpenSSL at the `connect_tcp()`/send/recv boundary: wrap the connected socket with an SSL/TLS object and use `SSL_read`/`SSL_write` instead of `recv`/`write`. Update `Makefile` LDFLAGS to include `$(shell pkg-config --libs openssl)` or add `-lssl -lcrypto` when required (see `INSTALL.md`).
- Header/response parsing: the boundary detection is in `src/http_client.c` — replace the in-place sliding-window with a small stateful parser that yields `headers` and then streams body to disk. Keep binary-safe writes.
- CLI flags: add flags by expanding `getopt` string and echoing usage via `print_usage()`; keep backwards compatibility with required `-u` and `-o`.

## Useful examples to copy/paste

- Build and run single HTTP fetch in CI-like script:
  ```sh
  make && ./http_client -u http://zechuncao.com/teaching/CSCI4406/test1.txt -o /tmp/test1.txt
  ```

- When adding TLS support, small checklist:
  - Add `#include <openssl/ssl.h>` and init SSL library once (e.g., `SSL_library_init()` on older APIs) or `OPENSSL_init_ssl()` newer APIs.
  - After `connect_tcp()` succeed, create an `SSL*` and `SSL_CTX*`, call `SSL_set_fd(ssl, sockfd)` and `SSL_connect(ssl)`.
  - Replace `write_all()`/`recv()` calls with `SSL_write()`/`SSL_read()` and handle SSL-specific error codes.
  - Update `Makefile` LDFLAGS to link against OpenSSL (see `INSTALL.md`).

## What not to change without CI or a dev machine

- Do not change the minimal header/body detection without ensuring the test script `scripts/test_cases.sh` still behaves—many test references are binary (PNG, object files). Always perform binary-safe writes and `cmp` against references.

## Where to look for quick context

- `src/http_client.c` — single source of truth for behavior. Read top-to-bottom; comments list
remaining TODOs and extension suggestions.

## Quick guidance for AI code agents

- Prefer small, well-tested changes: add a single CLI flag or a small helper function and run `make` and `sh scripts/test_cases.sh` locally (or CI) to validate regressions.
- When touching networking code, preserve binary-safe behavior: use `fwrite(..., "wb")` and `cmp` remains the canonical verification in `scripts/test_cases.sh`.
- Keep error codes stable: main returns small integer codes (1..10) for different failures; follow this convention when adding new error states.

Please review and tell me if any areas need more detail (e.g., expanded examples for TLS, Makefile edits, or a suggested CI job).  