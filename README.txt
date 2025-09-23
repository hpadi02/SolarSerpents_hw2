CSCI 4406 — Homework 2: HTTP Client

How to build and run
--------------------
1) Build on Linux/macOS with make:
   $ make

2) Run:
   $ ./http_client -u http://example.com/index.html -o index.html

3) Provided helper script to fetch test cases and compare (uses curl for refs):
   $ sh scripts/test_cases.sh
   Note: Current client only supports http://. HTTPS is still needed to implement

Files
-----
- src/http_client.c         Basic HTTP/1.0 client (no TLS)
- Makefile                  Build rules
- scripts/test_cases.sh     Fetch instructor URLs and diff results
- README.txt                This file

Implementation notes
--------------------
- Opens TCP socket, sends minimal HTTP/1.0 GET with Host and Connection: close.
- Parses response stream to find CRLFCRLF, then writes the remaining bytes to output.
- Binary-safe writing; suitable for text and binary objects when served over HTTP.
- HTTPS intentionally unimplemented so teammates can extend with TLS.

Limitations 
-----------------------------------------------
- No HTTPS/TLS.
- Does not parse headers beyond boundary detection.
- Does not follow redirects.
- Requires -u and -o; no default filename inference.
- No verbose mode to print headers.

Division of work 
----------------------------
Completed in this commit
- Baseline HTTP client over TCP, header/body split, file saving.
- Makefile and smoke-test script.
- Initial README scaffolding and partial Q&A below.

--todo
- Add HTTPS using OpenSSL (detect https, perform TLS handshake, send request).
- Add -A/--user-agent to customize UA string (see Questions #2/#3).
- Update Makefile to link with -lssl -lcrypto.

--todo
- Parse status line and headers; on 3xx with Location, follow up to 5 hops.
- Add -v to print request/response headers to stderr.
- If -o omitted, derive filename from URL path or use index.html.

Answers to Questions
--------------------
1) Difference between http_client, curl, wget:
   - http_client: minimal learning tool written for this assignment; only HTTP/1.0 GET over TCP, no TLS yet.
   - curl: general-purpose URL tool; supports many protocols (HTTP(S), FTP, etc.), advanced features (auth, cookies, redirects, proxies, TLS, HTTP/2/3).
   - wget: focused on retrieval; supports recursive downloads, mirroring, retries, and background mode; strong integration for non-interactive use.

2) Some sites restrict to certain browsers. How to make http_client download content?
   - Many servers check the User-Agent header. By allowing a flag to set User-Agent (e.g., "-A 'Mozilla/5.0 ...'"), we can imitate a known browser.
   - Other headers (Accept, Accept-Language) may matter, but UA is the simplest starting point. Implementing this is left to Member 2.

3) If a site blocks http_client, how to bypass while running such checks?
   - Send a browser-like User-Agent and possibly other common headers (Accept, Accept-Encoding, Referer). Handle redirects and HTTPS correctly.
   - Our client should avoid being identified by its distinct UA; allowing custom UA solves the basic case. Implementation is left to Member 2/3.

Testing
-------
- Use scripts/test_cases.sh to fetch instructor test files, then compare using cmp.
- On HTTPS URLs, the current client will fail until TLS is implemented.

Submission packaging
--------------------
- Zip the folder named teamname_hw2 containing source, Makefile, README.txt.
- Ensure program builds and runs on a Linux machine.
