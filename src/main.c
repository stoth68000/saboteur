#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <libavformat/avio.h>
#include <libavformat/avformat.h>
#include <libavutil/error.h>

#define TS_PACKET_SIZE 188
#define IO_BUFFER_SIZE (TS_PACKET_SIZE * 7)
#define HTTP_BUFFER_SIZE 4096
#define WEBROOT_DIR "webroot"

typedef struct {
    uint64_t packets_in;
    uint64_t packets_out;
    uint64_t packets_dropped;
    uint64_t pid0_packets_dropped;
    uint64_t pid_packets_dropped;
    uint64_t tei_packets_flipped;
    uint64_t sync_bytes_replaced;
    uint64_t adaptation_lengths_faulted;
    uint64_t chunks_in;
    uint64_t chunks_out;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t bytes_corrupted;
    uint64_t read_errors;
    uint64_t write_errors;

    uint64_t drop_next_packets;
    int64_t drop_until_ms;
    int64_t drop_pid0_until_ms;
    int64_t drop_pid_until_ms;
    uint16_t drop_pid;
    uint32_t drop_every_n;
    uint32_t jitter_ms;
    uint32_t jitter_remaining;
    uint32_t corrupt_next_bytes;
    uint64_t flip_tei_next_packets;
    int64_t replace_sync_until_ms;
    uint64_t adaptation_length_next_packets;
    uint16_t adaptation_length_pid;
} State;

typedef struct {
    const char *input_url;
    const char *output_url;
    int http_port;
} Config;

static State g_state;
static pthread_mutex_t g_state_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t g_stop = 0;

static int64_t now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((int64_t)tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

static void sleep_ms(uint32_t ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static void fferr(char *dst, size_t dst_len, int errnum) {
    av_strerror(errnum, dst, dst_len);
}

static long query_long(const char *path, const char *key, long fallback) {
    const char *query = strchr(path, '?');
    size_t key_len = strlen(key);

    if (!query) {
        return fallback;
    }
    query++;

    while (*query) {
        const char *next = strchr(query, '&');
        size_t len = next ? (size_t)(next - query) : strlen(query);

        if (len > key_len && strncmp(query, key, key_len) == 0 && query[key_len] == '=') {
            char tmp[64];
            size_t value_len = len - key_len - 1;
            if (value_len >= sizeof(tmp)) {
                value_len = sizeof(tmp) - 1;
            }
            memcpy(tmp, query + key_len + 1, value_len);
            tmp[value_len] = '\0';
            return strtol(tmp, NULL, 10);
        }

        if (!next) {
            break;
        }
        query = next + 1;
    }

    return fallback;
}

static uint16_t ts_pid(const uint8_t *packet) {
    if (packet[0] != 0x47) {
        return 0x1fff;
    }
    return (uint16_t)(((packet[1] & 0x1f) << 8) | packet[2]);
}

static size_t find_ts_sync(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != 0x47) {
            continue;
        }
        if (i + TS_PACKET_SIZE >= len || buf[i + TS_PACKET_SIZE] == 0x47) {
            return i;
        }
    }
    return len;
}

static bool should_drop_packet(const uint8_t *packet, uint64_t packet_index) {
    bool drop = false;
    bool pid0_drop = false;
    bool pid_drop = false;
    int64_t now = now_ms();
    uint16_t pid = ts_pid(packet);

    pthread_mutex_lock(&g_state_lock);
    if (pid == 0 && g_state.drop_pid0_until_ms > now) {
        drop = true;
        pid0_drop = true;
    }
    if (pid == g_state.drop_pid && g_state.drop_pid_until_ms > now) {
        drop = true;
        pid_drop = true;
    }
    if (g_state.drop_next_packets > 0) {
        g_state.drop_next_packets--;
        drop = true;
    }
    if (g_state.drop_until_ms > now) {
        drop = true;
    }
    if (g_state.drop_every_n > 0 && packet_index % g_state.drop_every_n == 0) {
        drop = true;
    }
    if (drop) {
        g_state.packets_dropped++;
    }
    if (pid0_drop) {
        g_state.pid0_packets_dropped++;
    }
    if (pid_drop) {
        g_state.pid_packets_dropped++;
    }
    pthread_mutex_unlock(&g_state_lock);

    return drop;
}

static void maybe_jitter(void) {
    uint32_t delay = 0;

    pthread_mutex_lock(&g_state_lock);
    if (g_state.jitter_ms > 0 && g_state.jitter_remaining > 0) {
        delay = g_state.jitter_ms;
        g_state.jitter_remaining--;
    }
    pthread_mutex_unlock(&g_state_lock);

    if (delay > 0) {
        sleep_ms(delay);
    }
}

static void maybe_corrupt(uint8_t *buf, int len) {
    uint32_t to_corrupt = 0;

    pthread_mutex_lock(&g_state_lock);
    if (g_state.corrupt_next_bytes > 0) {
        to_corrupt = g_state.corrupt_next_bytes;
        if (to_corrupt > (uint32_t)len) {
            to_corrupt = (uint32_t)len;
        }
        g_state.corrupt_next_bytes -= to_corrupt;
        g_state.bytes_corrupted += to_corrupt;
    }
    pthread_mutex_unlock(&g_state_lock);

    for (uint32_t i = 0; i < to_corrupt; i++) {
        buf[i] ^= 0xff;
    }
}

static void maybe_flip_tei(uint8_t *packet) {
    bool flip = false;

    pthread_mutex_lock(&g_state_lock);
    if (g_state.flip_tei_next_packets > 0) {
        g_state.flip_tei_next_packets--;
        g_state.tei_packets_flipped++;
        flip = true;
    }
    pthread_mutex_unlock(&g_state_lock);

    if (flip) {
        packet[1] ^= 0x80;
    }
}

static void maybe_replace_sync_byte(uint8_t *packet) {
    bool replace = false;
    int64_t now = now_ms();

    pthread_mutex_lock(&g_state_lock);
    if (g_state.replace_sync_until_ms > now) {
        g_state.sync_bytes_replaced++;
        replace = true;
    }
    pthread_mutex_unlock(&g_state_lock);

    if (replace) {
        packet[0] = 0x74;
    }
}

static void maybe_fault_adaptation_length(uint8_t *packet) {
    bool fault = false;
    uint16_t pid = ts_pid(packet);

    pthread_mutex_lock(&g_state_lock);
    if (g_state.adaptation_length_next_packets > 0 && pid == g_state.adaptation_length_pid) {
        g_state.adaptation_length_next_packets--;
        g_state.adaptation_lengths_faulted++;
        fault = true;
    }
    pthread_mutex_unlock(&g_state_lock);

    if (fault) {
        packet[3] = (uint8_t)((packet[3] & 0xcf) | 0x30);
        packet[4] = 191;
    }
}

static void write_packet(AVIOContext *out, const uint8_t *packet) {
    avio_write(out, packet, TS_PACKET_SIZE);
    avio_flush(out);

    pthread_mutex_lock(&g_state_lock);
    g_state.packets_out++;
    g_state.bytes_out += TS_PACKET_SIZE;
    pthread_mutex_unlock(&g_state_lock);
}

static void *stream_thread(void *arg) {
    const Config *cfg = arg;
    AVIOContext *in = NULL;
    AVIOContext *out = NULL;
    uint8_t buf[IO_BUFFER_SIZE];
    uint8_t packet_buf[IO_BUFFER_SIZE + TS_PACKET_SIZE];
    size_t packet_buf_len = 0;
    char errbuf[AV_ERROR_MAX_STRING_SIZE];

    int ret = avio_open2(&in, cfg->input_url, AVIO_FLAG_READ, NULL, NULL);
    if (ret < 0) {
        fferr(errbuf, sizeof(errbuf), ret);
        fprintf(stderr, "failed to open input %s: %s\n", cfg->input_url, errbuf);
        g_stop = 1;
        return NULL;
    }

    ret = avio_open2(&out, cfg->output_url, AVIO_FLAG_WRITE, NULL, NULL);
    if (ret < 0) {
        fferr(errbuf, sizeof(errbuf), ret);
        fprintf(stderr, "failed to open output %s: %s\n", cfg->output_url, errbuf);
        avio_closep(&in);
        g_stop = 1;
        return NULL;
    }

    fprintf(stderr, "forwarding %s -> %s\n", cfg->input_url, cfg->output_url);

    while (!g_stop) {
        ret = avio_read(in, buf, sizeof(buf));
        if (ret == AVERROR_EOF) {
            break;
        }
        if (ret < 0) {
            pthread_mutex_lock(&g_state_lock);
            g_state.read_errors++;
            pthread_mutex_unlock(&g_state_lock);
            sleep_ms(25);
            continue;
        }

        pthread_mutex_lock(&g_state_lock);
        g_state.chunks_in++;
        g_state.bytes_in += (uint64_t)ret;
        pthread_mutex_unlock(&g_state_lock);

        if (packet_buf_len + (size_t)ret > sizeof(packet_buf)) {
            packet_buf_len = 0;
            pthread_mutex_lock(&g_state_lock);
            g_state.read_errors++;
            pthread_mutex_unlock(&g_state_lock);
        }

        memcpy(packet_buf + packet_buf_len, buf, (size_t)ret);
        packet_buf_len += (size_t)ret;

        while (packet_buf_len >= TS_PACKET_SIZE && !g_stop) {
            if (packet_buf[0] != 0x47) {
                size_t sync = find_ts_sync(packet_buf, packet_buf_len);
                memmove(packet_buf, packet_buf + sync, packet_buf_len - sync);
                packet_buf_len -= sync;
                pthread_mutex_lock(&g_state_lock);
                g_state.read_errors++;
                pthread_mutex_unlock(&g_state_lock);
                continue;
            }

            pthread_mutex_lock(&g_state_lock);
            g_state.packets_in++;
            uint64_t packet_index = g_state.packets_in;
            pthread_mutex_unlock(&g_state_lock);

            if (!should_drop_packet(packet_buf, packet_index)) {
                maybe_flip_tei(packet_buf);
                maybe_fault_adaptation_length(packet_buf);
                maybe_corrupt(packet_buf, TS_PACKET_SIZE);
                maybe_replace_sync_byte(packet_buf);
                maybe_jitter();
                write_packet(out, packet_buf);
            }

            memmove(packet_buf, packet_buf + TS_PACKET_SIZE, packet_buf_len - TS_PACKET_SIZE);
            packet_buf_len -= TS_PACKET_SIZE;

            if (packet_buf_len < TS_PACKET_SIZE) {
                continue;
            }
        }

        pthread_mutex_lock(&g_state_lock);
        g_state.chunks_out++;
        pthread_mutex_unlock(&g_state_lock);
    }

    avio_flush(out);
    avio_closep(&out);
    avio_closep(&in);
    g_stop = 1;
    return NULL;
}

static void send_response(int fd, const char *status, const char *type, const char *body) {
    dprintf(fd,
            "HTTP/1.1 %s\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Cache-Control: no-store\r\n"
            "\r\n"
            "%s",
            status, type, strlen(body), body);
}

static void send_bytes(int fd, const char *status, const char *type, const uint8_t *body, size_t body_len) {
    dprintf(fd,
            "HTTP/1.1 %s\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Cache-Control: no-store\r\n"
            "\r\n",
            status, type, body_len);

    if (body_len > 0) {
        ssize_t written = write(fd, body, body_len);
        (void)written;
    }
}

static const char *content_type_for(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) {
        return "application/octet-stream";
    }
    if (strcmp(ext, ".html") == 0) {
        return "text/html; charset=utf-8";
    }
    if (strcmp(ext, ".css") == 0) {
        return "text/css; charset=utf-8";
    }
    if (strcmp(ext, ".js") == 0) {
        return "application/javascript; charset=utf-8";
    }
    if (strcmp(ext, ".json") == 0) {
        return "application/json";
    }
    if (strcmp(ext, ".svg") == 0) {
        return "image/svg+xml";
    }
    return "application/octet-stream";
}

static bool clean_static_path(const char *request_path, char *dst, size_t dst_len) {
    char path[1024];
    size_t path_len = 0;
    const char *query = strchr(request_path, '?');

    if (!request_path || request_path[0] != '/') {
        return false;
    }

    path_len = query ? (size_t)(query - request_path) : strlen(request_path);
    if (path_len == 0 || path_len >= sizeof(path)) {
        return false;
    }

    memcpy(path, request_path, path_len);
    path[path_len] = '\0';

    if (strstr(path, "..") || strchr(path, '\\')) {
        return false;
    }

    if (strcmp(path, "/") == 0) {
        path_len = strlen("/index.html");
        memcpy(path, "/index.html", path_len + 1);
    }

    int n = snprintf(dst, dst_len, "%s%s", WEBROOT_DIR, path);
    return n > 0 && (size_t)n < dst_len;
}

static bool serve_static_file(int fd, const char *request_path) {
    char fs_path[1200];
    if (!clean_static_path(request_path, fs_path, sizeof(fs_path))) {
        send_response(fd, "400 Bad Request", "text/plain", "bad request\n");
        return true;
    }

    struct stat st;
    if (stat(fs_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        return false;
    }

    FILE *f = fopen(fs_path, "rb");
    if (!f) {
        send_response(fd, "403 Forbidden", "text/plain", "forbidden\n");
        return true;
    }

    uint8_t *body = malloc((size_t)st.st_size);
    if (!body && st.st_size > 0) {
        fclose(f);
        send_response(fd, "500 Internal Server Error", "text/plain", "out of memory\n");
        return true;
    }

    size_t nread = fread(body, 1, (size_t)st.st_size, f);
    fclose(f);
    if (nread != (size_t)st.st_size) {
        free(body);
        send_response(fd, "500 Internal Server Error", "text/plain", "read failed\n");
        return true;
    }

    send_bytes(fd, "200 OK", content_type_for(fs_path), body, nread);
    free(body);
    return true;
}

static void status_json(char *dst, size_t len) {
    State s;
    pthread_mutex_lock(&g_state_lock);
    s = g_state;
    pthread_mutex_unlock(&g_state_lock);

    snprintf(dst, len,
             "{"
             "\"packets_in\":%" PRIu64 ","
             "\"packets_out\":%" PRIu64 ","
             "\"packets_dropped\":%" PRIu64 ","
             "\"pid0_packets_dropped\":%" PRIu64 ","
             "\"pid_packets_dropped\":%" PRIu64 ","
             "\"tei_packets_flipped\":%" PRIu64 ","
             "\"sync_bytes_replaced\":%" PRIu64 ","
             "\"adaptation_lengths_faulted\":%" PRIu64 ","
             "\"chunks_in\":%" PRIu64 ","
             "\"chunks_out\":%" PRIu64 ","
             "\"bytes_in\":%" PRIu64 ","
             "\"bytes_out\":%" PRIu64 ","
             "\"bytes_corrupted\":%" PRIu64 ","
             "\"read_errors\":%" PRIu64 ","
             "\"write_errors\":%" PRIu64 ","
             "\"drop_next_packets\":%" PRIu64 ","
             "\"drop_ms_remaining\":%" PRId64 ","
             "\"drop_pid0_ms_remaining\":%" PRId64 ","
             "\"drop_pid_ms_remaining\":%" PRId64 ","
             "\"drop_pid\":%u,"
             "\"drop_every_n\":%u,"
             "\"jitter_ms\":%u,"
             "\"jitter_remaining\":%u,"
             "\"corrupt_next_bytes\":%u,"
             "\"flip_tei_next_packets\":%" PRIu64 ","
             "\"replace_sync_ms_remaining\":%" PRId64 ","
             "\"adaptation_length_next_packets\":%" PRIu64 ","
             "\"adaptation_length_pid\":%u"
             "}",
             s.packets_in, s.packets_out, s.packets_dropped, s.pid0_packets_dropped,
             s.pid_packets_dropped,
             s.tei_packets_flipped, s.sync_bytes_replaced, s.adaptation_lengths_faulted,
             s.chunks_in, s.chunks_out,
             s.bytes_in, s.bytes_out, s.bytes_corrupted, s.read_errors, s.write_errors,
             s.drop_next_packets,
             s.drop_until_ms > now_ms() ? s.drop_until_ms - now_ms() : 0,
             s.drop_pid0_until_ms > now_ms() ? s.drop_pid0_until_ms - now_ms() : 0,
             s.drop_pid_until_ms > now_ms() ? s.drop_pid_until_ms - now_ms() : 0,
             s.drop_pid,
             s.drop_every_n, s.jitter_ms, s.jitter_remaining, s.corrupt_next_bytes,
             s.flip_tei_next_packets,
             s.replace_sync_until_ms > now_ms() ? s.replace_sync_until_ms - now_ms() : 0,
             s.adaptation_length_next_packets,
             s.adaptation_length_pid);
}

static void handle_client(int fd) {
    char req[HTTP_BUFFER_SIZE];
    ssize_t n = read(fd, req, sizeof(req) - 1);
    if (n <= 0) {
        return;
    }
    req[n] = '\0';

    char method[16] = {0};
    char path[1024] = {0};
    if (sscanf(req, "%15s %1023s", method, path) != 2) {
        send_response(fd, "400 Bad Request", "text/plain", "bad request\n");
        return;
    }

    if (strcmp(method, "OPTIONS") == 0) {
        send_response(fd, "204 No Content", "text/plain", "");
        return;
    }

    if (strcmp(method, "GET") == 0 && strncmp(path, "/api/status", 11) == 0) {
        char body[2048];
        status_json(body, sizeof(body));
        send_response(fd, "200 OK", "application/json", body);
        return;
    }

    if (strcmp(method, "GET") == 0 && strncmp(path, "/api/", 5) != 0) {
        if (!serve_static_file(fd, path)) {
            send_response(fd, "404 Not Found", "text/plain", "not found\n");
        }
        return;
    }

    if (strcmp(method, "POST") != 0) {
        send_response(fd, "405 Method Not Allowed", "text/plain", "method not allowed\n");
        return;
    }

    pthread_mutex_lock(&g_state_lock);
    if (strncmp(path, "/api/drop?", 10) == 0) {
        long packets = query_long(path, "packets", 1);
        if (packets > 0) {
            g_state.drop_next_packets += (uint64_t)packets;
        }
    } else if (strncmp(path, "/api/drop_for?", 14) == 0) {
        long ms = query_long(path, "ms", 1000);
        if (ms > 0) {
            g_state.drop_until_ms = now_ms() + ms;
        }
    } else if (strncmp(path, "/api/drop_pid0_for?", 19) == 0) {
        long ms = query_long(path, "ms", 1000);
        if (ms > 0) {
            g_state.drop_pid0_until_ms = now_ms() + ms;
        }
    } else if (strncmp(path, "/api/drop_pid_for?", 18) == 0) {
        long ms = query_long(path, "ms", 1000);
        long pid = query_long(path, "pid", 49);
        if (ms > 0 && pid >= 0 && pid <= 8191) {
            g_state.drop_pid_until_ms = now_ms() + ms;
            g_state.drop_pid = (uint16_t)pid;
        }
    } else if (strncmp(path, "/api/drop_every?", 16) == 0) {
        long n_every = query_long(path, "n", 0);
        g_state.drop_every_n = n_every > 0 ? (uint32_t)n_every : 0;
    } else if (strncmp(path, "/api/jitter?", 12) == 0) {
        long ms = query_long(path, "ms", 100);
        long count = query_long(path, "count", 1);
        g_state.jitter_ms = ms > 0 ? (uint32_t)ms : 0;
        g_state.jitter_remaining = count > 0 ? (uint32_t)count : 0;
    } else if (strncmp(path, "/api/corrupt?", 13) == 0) {
        long bytes = query_long(path, "bytes", TS_PACKET_SIZE);
        if (bytes > 0) {
            g_state.corrupt_next_bytes += (uint32_t)bytes;
        }
    } else if (strncmp(path, "/api/flip_tei?", 14) == 0) {
        long packets = query_long(path, "packets", 1);
        if (packets > 0) {
            g_state.flip_tei_next_packets += (uint64_t)packets;
        }
    } else if (strncmp(path, "/api/replace_sync_for?", 22) == 0) {
        long seconds = query_long(path, "seconds", 1);
        if (seconds > 0) {
            g_state.replace_sync_until_ms = now_ms() + (seconds * 1000);
        }
    } else if (strncmp(path, "/api/fault_adaptation_length?", 29) == 0) {
        long packets = query_long(path, "packets", 1);
        long pid = query_long(path, "pid", 49);
        if (packets > 0) {
            g_state.adaptation_length_next_packets += (uint64_t)packets;
            if (pid >= 0 && pid <= 8191) {
                g_state.adaptation_length_pid = (uint16_t)pid;
            }
        }
    } else if (strncmp(path, "/api/reset", 10) == 0) {
        g_state.drop_next_packets = 0;
        g_state.drop_until_ms = 0;
        g_state.drop_pid0_until_ms = 0;
        g_state.drop_pid_until_ms = 0;
        g_state.drop_pid = 49;
        g_state.drop_every_n = 0;
        g_state.jitter_ms = 0;
        g_state.jitter_remaining = 0;
        g_state.corrupt_next_bytes = 0;
        g_state.flip_tei_next_packets = 0;
        g_state.replace_sync_until_ms = 0;
        g_state.adaptation_length_next_packets = 0;
        g_state.adaptation_length_pid = 49;
    } else {
        pthread_mutex_unlock(&g_state_lock);
        send_response(fd, "404 Not Found", "text/plain", "not found\n");
        return;
    }
    pthread_mutex_unlock(&g_state_lock);

    char body[2048];
    status_json(body, sizeof(body));
    send_response(fd, "200 OK", "application/json", body);
}

static void *http_thread(void *arg) {
    const Config *cfg = arg;
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        g_stop = 1;
        return NULL;
    }

    int yes = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)cfg->http_port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        g_stop = 1;
        return NULL;
    }

    if (listen(server_fd, 16) < 0) {
        perror("listen");
        close(server_fd);
        g_stop = 1;
        return NULL;
    }

    fprintf(stderr, "web ui listening on http://127.0.0.1:%d/\n", cfg->http_port);

    while (!g_stop) {
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);

        int ready = select(server_fd + 1, &readfds, NULL, NULL, &timeout);
        if (ready <= 0) {
            continue;
        }

        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno != EINTR) {
                perror("accept");
            }
            continue;
        }
        handle_client(client_fd);
        close(client_fd);
    }

    close(server_fd);
    return NULL;
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "usage: %s --input-url URL --output-url URL [--http-port PORT]\n"
            "\n"
            "example:\n"
            "  %s --input-url 'udp://239.10.10.10:5000?overrun_nonfatal=1' --output-url 'udp://127.0.0.1:6000'\n",
            argv0, argv0);
}

static bool parse_args(int argc, char **argv, Config *cfg) {
    cfg->http_port = 9601;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--input-url") == 0 && i + 1 < argc) {
            cfg->input_url = argv[++i];
        } else if (strcmp(argv[i], "--output-url") == 0 && i + 1 < argc) {
            cfg->output_url = argv[++i];
        } else if (strcmp(argv[i], "--http-port") == 0 && i + 1 < argc) {
            cfg->http_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            exit(0);
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[i]);
            return false;
        }
    }

    return cfg->input_url && cfg->output_url && cfg->http_port > 0 && cfg->http_port < 65536;
}

int main(int argc, char **argv) {
    Config cfg = {0};
    pthread_t stream_tid;
    pthread_t http_tid;

    if (!parse_args(argc, argv, &cfg)) {
        usage(argv[0]);
        return 2;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    avformat_network_init();
    g_state.drop_pid = 49;
    g_state.adaptation_length_pid = 49;

    if (pthread_create(&http_tid, NULL, http_thread, &cfg) != 0) {
        perror("pthread_create http");
        return 1;
    }
    if (pthread_create(&stream_tid, NULL, stream_thread, &cfg) != 0) {
        perror("pthread_create stream");
        g_stop = 1;
        pthread_join(http_tid, NULL);
        return 1;
    }

    pthread_join(stream_tid, NULL);
    pthread_join(http_tid, NULL);
    avformat_network_deinit();
    return 0;
}
