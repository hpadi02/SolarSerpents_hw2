#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
// OpenSSL
#include <openssl/ssl.h>
#include <openssl/err.h>

/*
 * find_sequence
 * ----------------
 * Search for a contiguous byte sequence `needle` of length `nlen` inside
 * a buffer `hay` with length `hlen`.
 *
 * Returns:
 *  - index (>=0) of first occurrence
 *  - -1 if needle not found or inputs invalid
 *
 * Rationale: memmem() is not portable everywhere; this small helper is
 * straightforward and easy to reason about when dealing with header
 * boundary detection in the client.
 */
static ssize_t find_sequence(const unsigned char *hay, size_t hlen,
                             const unsigned char *needle, size_t nlen) {
    if (nlen == 0 || hlen < nlen) return -1;
    for (size_t i = 0; i <= hlen - nlen; ++i) {
        if (memcmp(hay + i, needle, nlen) == 0) return (ssize_t)i;
    }
    return -1;
}

/* url_parts_t
 * -------------
 * Simple container produced by `parse_url()` describing the parts of a
 * URL we need for connecting and constructing the request. All members
 * are heap-allocated strings that must be freed by `free_url_parts()`.
 */
typedef struct {
    char *scheme;    /* "http" or "https" */
    char *host;      /* hostname (no brackets) */
    char *port;      /* string port, default "80" for http */
    char *path;      /* path starting with '/' */
} url_parts_t;

/* Print a short usage help message. */
/* print_usage
 * ------------
 * Print a short usage message to stderr describing required and
 * optional flags. Keep the message minimal but informative.
 */
static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s -u <url> -o <output_file> [-A <user-agent>] [-k]\n", prog);
    fprintf(stderr, "  -A <user-agent>   Set custom User-Agent header (default preserved)\n");
    fprintf(stderr, "  -k                Skip TLS certificate verification (insecure)\n");
}

/* Duplicate a slice of memory into a NUL-terminated string. Caller frees. */
/* strdup_slice
 * -------------
 * Allocate a new, NUL-terminated string copying `len` bytes from `start`.
 * Returns NULL on allocation failure. Caller owns the returned pointer.
 */
static char *strdup_slice(const char *start, size_t len) {
    char *s = (char *)malloc(len + 1);
    if (!s) return NULL;
    memcpy(s, start, len);
    s[len] = '\0';
    return s;
}

static bool parse_url(const char *url, url_parts_t *out, char **err_msg) {
    // Initialize
    memset(out, 0, sizeof(*out));
    const char *p = strstr(url, "://");
    if (!p) {
        *err_msg = strdup("URL must include scheme, e.g., http://example.com/");
        return false;
    }
    out->scheme = strdup_slice(url, (size_t)(p - url));
    const char *rest = p + 3; // skip ://

    /* Extract host[:port] and path
     * -------------------------------
     * We look for the first '/' after the scheme (rest). If no '/', the
     * URL contained only host[:port] and we'll set path = "/". If a
     * colon appears between the start and the '/', it denotes a port.
     */
    const char *path_start = strchr(rest, '/');
    if (!path_start) {
        // No path specified, assume root
        path_start = rest + strlen(rest);
        out->path = strdup("/");
    } else {
        out->path = strdup(path_start);
    }

    const char *host_end = path_start; // points to '/' or to string end
    const char *colon = memchr(rest, ':', (size_t)(host_end - rest));
    if (colon) {
        out->host = strdup_slice(rest, (size_t)(colon - rest));
        out->port = strdup_slice(colon + 1, (size_t)(host_end - colon - 1));
    } else {
        out->host = strdup_slice(rest, (size_t)(host_end - rest));
        out->port = NULL; // will be filled by default below
    }

    if (!out->scheme || !out->host || !out->path) {
        *err_msg = strdup("Out of memory while parsing URL");
        return false;
    }

    /* Defaults: if no port provided, set default ports for http/https */
    if (!out->port) {
        if (strcmp(out->scheme, "http") == 0) {
            out->port = strdup("80");
        } else if (strcmp(out->scheme, "https") == 0) {
            out->port = strdup("443");
        } else {
            *err_msg = strdup("Unsupported URL scheme. Use http:// or https://");
            return false;
        }
    }
    return true;
}

static void free_url_parts(url_parts_t *u) {
    if (!u) return;
    free(u->scheme);
    free(u->host);
    free(u->port);
    free(u->path);
}

static int connect_tcp(const char *host, const char *port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
        return -1;
    }

    /* Iterate through returned addrinfo results and try to connect. This
     * approach provides IPv4/IPv6 portability: we attempt each address
     * until one succeeds. On failure we return -1. The caller must close
     * the socket when done on success. */
    int sockfd = -1;
    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) continue;
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break; /* success */
        }
        close(sockfd);
        sockfd = -1;
    }
    freeaddrinfo(res);
    return sockfd; // -1 if failed
}

/*
 * Send all bytes from `buf` of length `len` over either the plain socket
 * `fd` or the OpenSSL `ssl` object if `ssl` is not NULL. This function
 * retries interrupted system calls and handles SSL WANT_* transient
 * conditions for writes by retrying.
 */
static bool write_all_ssl(int fd, SSL *ssl, const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char *)buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n;
        if (ssl) {
            n = SSL_write(ssl, p, (int)remaining);
            if (n <= 0) {
                int err = SSL_get_error(ssl, (int)n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    /* transient, try again */
                    continue;
                }
                return false; /* fatal SSL write error */
            }
        } else {
            n = write(fd, p, remaining);
            if (n < 0) {
                if (errno == EINTR) continue; /* interrupted, retry */
                return false; /* fatal write error */
            }
        }
        p += (size_t)n;
        remaining -= (size_t)n;
    }
    return true;
}

// recv via fd or SSL when ssl != NULL
/*
 * Receive up to `len` bytes into `buf` from either the plain socket `fd`
 * or the OpenSSL `ssl` object. On success returns number of bytes > 0.
 * Returns 0 on clean EOF. Returns -1 on fatal error. For SSL, this
 * function will retry transient WANT_READ/WANT_WRITE conditions rather
 * than returning 0 so the caller does not mistake WANT_* for EOF.
 */
static ssize_t recv_ssl(int fd, SSL *ssl, void *buf, size_t len) {
    if (ssl) {
        for (;;) {
            int n = SSL_read(ssl, buf, (int)len);
            if (n > 0) return n; /* got data */
            if (n == 0) return 0; /* clean shutdown (EOF) */
            /* n < 0: get the SSL error and decide */
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                /* transient, retry the read */
                continue;
            }
            /* fatal SSL error */
            return -1;
        }
    }
    /* Plain socket: behave like recv(2) */
    return recv(fd, buf, len, 0);
}

int main(int argc, char **argv) {
    /* Command-line state */
    const char *url = NULL;
    const char *out_path = NULL;
    const char *user_agent = NULL;
    bool insecure_skip_verify = false; /* -k flag */
    bool verbose = false; /* -v flag */
    /* Support up to 32 custom headers passed via -H; dynamic list is overkill */
    const int MAX_HEADERS = 32;
    char *custom_headers[MAX_HEADERS];
    int custom_header_count = 0;

    int opt;
    /* Accept -u <url>, -o <output>, -A <user-agent>, -k (skip cert verification) */
    while ((opt = getopt(argc, argv, "u:o:A:kvH:")) != -1) {
        switch (opt) {
            case 'u': url = optarg; break;
            case 'o': out_path = optarg; break;
            case 'A': user_agent = optarg; break;
            case 'k': insecure_skip_verify = true; break;
            case 'v': verbose = true; break;
            case 'H':
                if (custom_header_count < MAX_HEADERS) {
                    custom_headers[custom_header_count++] = strdup(optarg);
                } else {
                    fprintf(stderr, "Too many -H headers (max %d)\n", MAX_HEADERS);
                    return 1;
                }
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (!url || !out_path) {
        print_usage(argv[0]);
        return 1;
    }

    url_parts_t u;
    char *err_msg = NULL;
    if (!parse_url(url, &u, &err_msg)) {
        fprintf(stderr, "URL parse error: %s\n", err_msg ? err_msg : "unknown");
        free(err_msg);
        return 2;
    }

    bool use_tls = (strcmp(u.scheme, "https") == 0);

    /* TLS objects and socket; will be created only if HTTPS requested. */
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int sockfd = -1;

    if (use_tls) {
        /* Initialize OpenSSL library and create a client context. We use
         * TLS_client_method() so OpenSSL negotiates the highest TLS version
         * both client and server support. */
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            fprintf(stderr, "SSL_CTX_new failed\n");
            free_url_parts(&u);
            return 3;
        }

        /* Configure verification behavior. By default we attempt to load
         * the system CA bundle (SSL_CTX_set_default_verify_paths). If the
         * user supplied -k, verification is disabled (insecure). */
        if (!insecure_skip_verify) {
            if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
                /* warn but continue; server cert verification may fail later */
                fprintf(stderr, "Warning: could not load default CA paths for verification\n");
            }
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        } else {
            /* Insecure: do not verify server certificate */
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        }
    }

    /* Make a TCP connection first (works for both HTTP and HTTPS) */
    sockfd = connect_tcp(u.host, u.port);
    if (sockfd < 0) {
        fprintf(stderr, "Failed to connect to %s:%s\n", u.host, u.port);
        if (ctx) SSL_CTX_free(ctx);
        free_url_parts(&u);
        return 4;
    }

    /* If HTTPS requested, create SSL object and perform handshake */
    if (use_tls) {
        ssl = SSL_new(ctx);
        if (!ssl) {
            fprintf(stderr, "SSL_new failed\n");
            close(sockfd);
            SSL_CTX_free(ctx);
            free_url_parts(&u);
            return 5;
        }
        SSL_set_fd(ssl, sockfd);
        if (SSL_connect(ssl) != 1) {
            fprintf(stderr, "SSL_connect failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sockfd);
            free_url_parts(&u);
            return 6;
        }

        /* If verification is enabled, check the result now. */
        if (!insecure_skip_verify) {
            long rv = SSL_get_verify_result(ssl);
            if (rv != X509_V_OK) {
                fprintf(stderr, "Certificate verification failed: %ld\n", rv);
                /* Continue or fail: for safety, fail here so the user can choose -k to override */
                SSL_shutdown(ssl);
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                close(sockfd);
                free_url_parts(&u);
                return 7;
            }
        }
    }

    /* Construct minimal HTTP/1.0 GET request. We keep the request small
     * and compatible with HTTP/1.0 servers. The Connection: close header
     * ensures the server will close the connection when it's done, which
     * simplifies reading the response: we can read until EOF instead of
     * parsing Content-Length or chunked encoding. */
    char request[4096];
    const char *ua_final = user_agent ? user_agent : "http_client/1.0 (CSCI4406)";
    int req_len = snprintf(
        request, sizeof(request),
        "GET %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n",
        u.path, u.host, ua_final);
    /* Append custom headers and Connection: close and final CRLF manually */
    size_t base_len = (size_t)req_len;
    for (int i = 0; i < custom_header_count; ++i) {
        int n = snprintf(request + base_len, sizeof(request) - base_len, "%s\r\n", custom_headers[i]);
        if (n <= 0 || (size_t)n >= sizeof(request) - base_len) { req_len = -1; break; }
        base_len += (size_t)n;
    }
    if (req_len > 0) {
        int n = snprintf(request + base_len, sizeof(request) - base_len, "Connection: close\r\n\r\n");
        if (n <= 0 || (size_t)n >= sizeof(request) - base_len) req_len = -1; else req_len = (int)(base_len + n);
    }
    if (req_len <= 0 || req_len >= (int)sizeof(request)) {
        fprintf(stderr, "Failed to build HTTP request\n");
        close(sockfd);
        free_url_parts(&u);
        return 5;
    }

    if (verbose) {
        /* Print the exact request we will send for debugging */
        fprintf(stderr, "--- Outgoing HTTP request ---\n%.*s\n-----------------------------\n", req_len, request);
    }

    if (!write_all_ssl(sockfd, ssl, request, (size_t)req_len)) {
        fprintf(stderr, "Failed to send HTTP request\n");
        goto cleanup_and_error;
    }

    FILE *out = fopen(out_path, "wb");
    if (!out) {
        fprintf(stderr, "Failed to open output file '%s': %s\n", out_path, strerror(errno));
        close(sockfd);
        free_url_parts(&u);
        return 7;
    }

    // Read response. Separate headers and body by looking for CRLFCRLF
    const size_t buf_size = 8192;
    /* Open output file for binary writing. */
    FILE *out = fopen(out_path, "wb");
    if (!out) {
        fprintf(stderr, "Failed to open output file '%s': %s\n", out_path, strerror(errno));
        goto cleanup_and_error;
    }

    /*
     * Read response from the socket/SSL. We accumulate bytes until we find
     * the header/body separator "\r\n\r\n". After the separator, the
     * remainder of the buffer is the start of the body and is written to
     * disk. Subsequent reads write directly to disk.
     */
    const size_t buf_size = 8192;
    unsigned char buffer[8192];
    unsigned char header_accum[64 * 1024]; /* allow up to 64KB of headers */
    size_t header_len = 0;
    const unsigned char needle[4] = {'\r', '\n', '\r', '\n'};
    bool headers_parsed = false;

    ssize_t nread;
    while ((nread = recv_ssl(sockfd, ssl, buffer, buf_size)) > 0) {
        size_t off = 0;
        if (!headers_parsed) {
            /* Append to header_accum, but protect against overflow */
            size_t to_copy = (size_t)nread;
            if (header_len + to_copy > sizeof(header_accum)) {
                /* headers too large */
                fprintf(stderr, "Headers too large\n");
                goto cleanup_and_error_with_file;
            }
            memcpy(header_accum + header_len, buffer, to_copy);
            header_len += to_copy;

                    /* Search for CRLFCRLF in accumulated headers */
                    ssize_t idx = find_sequence(header_accum, header_len, needle, sizeof(needle));
            if (idx >= 0) {
                /* Found end of headers; body starts after idx+4 */
                size_t body_start = (size_t)idx + sizeof(needle);
                size_t body_len = header_len - body_start;
                if (body_len > 0) {
                    if (fwrite(header_accum + body_start, 1, body_len, out) != body_len) {
                        fprintf(stderr, "Write error\n");
                        goto cleanup_and_error_with_file;
                    }
                }
                headers_parsed = true;
                        /*
                         * Parse and optionally print response status line and headers
                         * for the caller. We keep parsing simple: split lines at CRLF
                         * and print them. This is intended for debugging / grading.
                         */
                        if (verbose) {
                            /* Find end of status line */
                            ssize_t eol = find_sequence(header_accum, header_len, (unsigned char *)"\r\n", 2);
                            if (eol >= 0) {
                                fprintf(stderr, "--- Response status line ---\n%.*s\n", (int)eol, header_accum);
                            }
                            fprintf(stderr, "--- Response headers ---\n");
                            /* Print each header line */
                            size_t pos = 0;
                            while (pos + 1 < (size_t)idx) {
                                /* find next CRLF */
                                ssize_t nl = find_sequence(header_accum + pos, (size_t)idx - pos, (unsigned char *)"\r\n", 2);
                                if (nl < 0) break;
                                if (nl == 0) break; /* empty line */
                                fprintf(stderr, "%.*s\n", (int)nl, (char *)(header_accum + pos));
                                pos += (size_t)nl + 2;
                            }
                            fprintf(stderr, "-------------------------\n");
                        }
            }
            /* continue reading; any extra data beyond header accumulation was handled */
        } else {
            /* headers already parsed: write body bytes directly to file */
            if (fwrite(buffer, 1, (size_t)nread, out) != (size_t)nread) {
                fprintf(stderr, "Write error\n");
                goto cleanup_and_error_with_file;
            }
        }
    }

    if (nread < 0) {
        fprintf(stderr, "recv error\n");
        goto cleanup_and_error_with_file;
    }

    /* Clean shutdown and normal exit */
    fclose(out);
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
    close(sockfd);
    free_url_parts(&u);
    return 0;

cleanup_and_error_with_file:
    fclose(out);
cleanup_and_error:
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx) SSL_CTX_free(ctx);
    if (sockfd >= 0) close(sockfd);
    free_url_parts(&u);
    return 1;


