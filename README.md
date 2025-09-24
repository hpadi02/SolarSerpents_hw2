# SolarSerpents_hw2 — Homework 2: HTTP Client

Build
Run `make` to build the `http_client` binary. The project expects a POSIX-like environment
for building (Linux or WSL on Windows). OpenSSL development libraries are required for
HTTPS support. See `INSTALL.md` for platform-specific instructions.

Example:

```
./http_client -u http://example.com/index.html -o index.html
```

Status
------

Completed
- TLS (HTTPS) support (OpenSSL)
- `-A` User-Agent flag
- Safer header detection and robust SSL I/O
- `Makefile` updated for OpenSSL
- `-v` verbose and `-H` custom headers

To do
- Run smoke tests (`make` + `sh scripts/test_cases.sh`) in WSL/Linux
- (Optional) Add full HTTP/1.1 features (chunked decoding, stronger body parsing)
- (Optional) Native Windows port (Winsock)
make
```

Run
---
```
./http_client -u http://example.com/index.html -o index.html
```

Testing helper
--------------
```
sh scripts/test_cases.sh
```

Notes
-----
- Current client supports HTTP over TCP (no TLS). HTTPS is a follow-up task.
- See `README.txt` for assignment Q&A and division of work for teammates.
