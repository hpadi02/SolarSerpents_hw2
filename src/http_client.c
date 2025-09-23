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

typedef struct {
    char *scheme;    // "http" or "https"
    char *host;      // hostname (no brackets)
    char *port;      // string port, default "80" for http
    char *path;      // path starting with '/'
} url_parts_t;

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s -u <url> -o <output_file>\n", prog);
}

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

    // Extract host[:port]
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

    // Defaults
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

    int sockfd = -1;
    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) continue;
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break; // success
        }
        close(sockfd);
        sockfd = -1;
    }
    freeaddrinfo(res);
    return sockfd; // -1 if failed
}

static bool write_all(int fd, const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char *)buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        p += (size_t)n;
        remaining -= (size_t)n;
    }
    return true;
}

int main(int argc, char **argv) {
    const char *url = NULL;
    const char *out_path = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "u:o:")) != -1) {
        switch (opt) {
            case 'u': url = optarg; break;
            case 'o': out_path = optarg; break;
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

    if (strcmp(u.scheme, "https") == 0) {
        fprintf(stderr, "Note: HTTPS is not yet implemented. Please use http:// or extend with TLS.\n");
        free_url_parts(&u);
        return 3;
    }

    int sockfd = connect_tcp(u.host, u.port);
    if (sockfd < 0) {
        fprintf(stderr, "Failed to connect to %s:%s\n", u.host, u.port);
        free_url_parts(&u);
        return 4;
    }

    // Construct minimal HTTP/1.0 request
    char request[4096];
    int req_len = snprintf(
        request, sizeof(request),
        "GET %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "User-Agent: http_client/1.0 (CSCI4406)\r\n"
        "Connection: close\r\n"
        "\r\n",
        u.path, u.host);
    if (req_len <= 0 || req_len >= (int)sizeof(request)) {
        fprintf(stderr, "Failed to build HTTP request\n");
        close(sockfd);
        free_url_parts(&u);
        return 5;
    }

    if (!write_all(sockfd, request, (size_t)req_len)) {
        fprintf(stderr, "Failed to send HTTP request\n");
        close(sockfd);
        free_url_parts(&u);
        return 6;
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
    unsigned char buffer[8192];
    bool header_done = false;
    // Small header stash to detect boundary across reads
    unsigned char header_window[4] = {0};
    size_t window_filled = 0;

    // We will store headers in-memory for debugging (optional)
    // To keep implementation simple, we don't parse Content-Length or chunked here.

    ssize_t n;
    while ((n = recv(sockfd, buffer, buf_size, 0)) > 0) {
        if (!header_done) {
            // Scan for "\r\n\r\n" across boundary using a sliding window
            size_t i = 0;
            for (; i < (size_t)n; i++) {
                // shift
                if (window_filled < 4) {
                    header_window[window_filled++] = buffer[i];
                } else {
                    header_window[0] = header_window[1];
                    header_window[1] = header_window[2];
                    header_window[2] = header_window[3];
                    header_window[3] = buffer[i];
                }

                if (window_filled == 4 &&
                    header_window[0] == '\r' && header_window[1] == '\n' &&
                    header_window[2] == '\r' && header_window[3] == '\n') {
                    // Write the remainder after headers
                    size_t body_start_index = i + 1; // index after the last '\n'
                    if (body_start_index < (size_t)n) {
                        size_t body_len = (size_t)n - body_start_index;
                        if (fwrite(buffer + body_start_index, 1, body_len, out) != body_len) {
                            fprintf(stderr, "Write error\n");
                            fclose(out);
                            close(sockfd);
                            free_url_parts(&u);
                            return 8;
                        }
                    }
                    header_done = true;
                    break;
                }
            }
            if (!header_done) {
                // Haven't reached body yet, continue reading
                continue;
            }
            // If we broke because header finished, continue reading rest of body in next iterations
        } else {
            if (fwrite(buffer, 1, (size_t)n, out) != (size_t)n) {
                fprintf(stderr, "Write error\n");
                fclose(out);
                close(sockfd);
                free_url_parts(&u);
                return 9;
            }
        }
    }

    if (n < 0) {
        fprintf(stderr, "recv error: %s\n", strerror(errno));
        fclose(out);
        close(sockfd);
        free_url_parts(&u);
        return 10;
    }

    fclose(out);
    close(sockfd);
    free_url_parts(&u);

    // Success
    return 0;
}

/*
Remaining work for teammates (clearly labeled):
1) Implement HTTPS using OpenSSL (detect scheme https and establish TLS). Update Makefile libs.
2) Parse response headers fully: status code, Content-Length, handle chunked (HTTP/1.1). Save headers to a file if -H is given.
3) Improve CLI: default output filename from URL when -o omitted; add -v verbose to print request/response headers to stderr.
4) Handle redirects (3xx) by following Location header up to a small max.
5) Add User-Agent spoofing option to answer assignment Q2/Q3 and bypass simple UA checks.
*/


