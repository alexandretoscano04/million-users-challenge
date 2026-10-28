#include "app.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "libdeflate.h"

#define BLOCK_BITS 12
#define BLOCK_SIZE (1U << BLOCK_BITS)
#define MAX_BLOCKS 512
#define NONE UINT32_MAX
#define CLIENT_EVENTS (EPOLLIN | EPOLLRDHUP | EPOLLONESHOT)
#define ACTIVE_LIMIT 8192
#define BUFFER_BUDGET (32U * 1024 * 1024)

typedef struct Active Active;
struct Active {
    Buffer input, output;
    size_t sent;
    unsigned header_len, interim_sent;
    uint32_t next_ready;
    bool busy, close, queued, interim;
    char header[256];
};
typedef struct {
    Active *active;
    uint32_t generation, next;
    int fd;
} Client;
typedef struct {
    int epoll_fd, listeners[2];
    Client *blocks[MAX_BLOCKS];
    uint32_t block_count, free_head, ready_head, ready_tail;
    Auth *auth;
    DbPool *db;
    struct libdeflate_compressor *compressor;
    Buffer compressed;
    size_t input_capacity, output_capacity;
    unsigned active_count, gzip_min;
    unsigned char scratch[MAX_REQUEST];
} Worker;

static Worker worker;
static volatile sig_atomic_t stopping;
static uint64_t started_ms;

static uint64_t monotonic_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
uint64_t app_uptime(void) { return (monotonic_ms() - started_ms) / 1000; }
static void stop_signal(int sig) { (void)sig; stopping = 1; }
static Client *client_at(uint32_t slot) {
    if (slot >> BLOCK_BITS >= worker.block_count) return NULL;
    return &worker.blocks[slot >> BLOCK_BITS][slot & (BLOCK_SIZE - 1)];
}
static uint64_t client_key(uint32_t slot, Client *c) {
    return ((uint64_t)c->generation << 32) | slot;
}
static void active_free(Active *a) {
    if (!a) return;
    worker.input_capacity -= a->input.cap;
    worker.output_capacity -= a->output.cap;
    worker.active_count--;
    buffer_free(&a->input);
    buffer_free(&a->output);
    free(a);
}
static void client_close(uint32_t slot) {
    Client *c = client_at(slot);
    if (!c || c->fd < 0) return;
    close(c->fd);
    c->fd = -1;
    if (!c->active || !c->active->queued) {
        active_free(c->active);
        c->active = NULL;
        c->next = worker.free_head;
        worker.free_head = slot;
    }
}
static bool client_arm(uint32_t slot, uint32_t events) {
    Client *c = client_at(slot);
    struct epoll_event e = {.events = events | EPOLLONESHOT | EPOLLRDHUP, .data.u64 = client_key(slot, c)};
    if (epoll_ctl(worker.epoll_fd, EPOLL_CTL_MOD, c->fd, &e) == 0) return true;
    client_close(slot);
    return false;
}
static uint32_t client_allocate(int fd) {
    if (worker.free_head == NONE) {
        if (worker.block_count == MAX_BLOCKS) return NONE;
        Client *block = calloc(BLOCK_SIZE, sizeof(*block));
        if (!block) return NONE;
        uint32_t base = worker.block_count * BLOCK_SIZE;
        worker.blocks[worker.block_count++] = block;
        for (unsigned i = 0; i < BLOCK_SIZE; i++) {
            block[i].fd = -1;
            block[i].next = i + 1 == BLOCK_SIZE ? NONE : base + i + 1;
        }
        worker.free_head = base;
    }
    uint32_t slot = worker.free_head;
    Client *c = client_at(slot);
    worker.free_head = c->next;
    c->generation = (c->generation + 1) & 0x3fffffff;
    if (!c->generation) c->generation = 1;
    c->fd = fd;
    return slot;
}
static void client_schedule(uint32_t slot) {
    Client *c = client_at(slot);
    Active *a = c->active;
    if (a->queued) return;
    a->queued = true;
    a->next_ready = NONE;
    if (worker.ready_tail != NONE) client_at(worker.ready_tail)->active->next_ready = slot;
    else worker.ready_head = slot;
    worker.ready_tail = slot;
}
static void response_finished(uint32_t slot) {
    Client *c = client_at(slot);
    Active *a = c->active;
    worker.output_capacity -= a->output.cap;
    buffer_free(&a->output);
    a->sent = 0;
    a->header_len = 0;
    a->busy = false;
    if (a->close) { client_close(slot); return; }
    if (a->input.len) { client_schedule(slot); return; }
    active_free(a);
    c->active = NULL;
    client_arm(slot, EPOLLIN);
}
static void client_write(uint32_t slot) {
    Client *c = client_at(slot);
    Active *a = c->active;
    if (!a) { client_arm(slot, EPOLLIN); return; }
    if (a->interim) {
        static const char cont[] = "HTTP/1.1 100 Continue\r\n\r\n";
        ssize_t n = send(c->fd, cont + a->interim_sent, sizeof(cont) - 1 - a->interim_sent, MSG_NOSIGNAL);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) { client_arm(slot, EPOLLOUT); return; }
        if (n <= 0) { client_close(slot); return; }
        a->interim_sent += (unsigned)n;
        if (a->interim_sent < sizeof(cont) - 1) { client_arm(slot, EPOLLOUT); return; }
        a->interim = false;
        client_arm(slot, EPOLLIN);
        return;
    }
    if (!a->header_len) return;
    struct iovec v[2];
    unsigned count = 0;
    if (a->sent < a->header_len) {
        v[count++] = (struct iovec){a->header + a->sent, a->header_len - a->sent};
        if (a->output.len) v[count++] = (struct iovec){a->output.data, a->output.len};
    } else {
        size_t offset = a->sent - a->header_len;
        v[count++] = (struct iovec){a->output.data + offset, a->output.len - offset};
    }
    struct msghdr msg = {.msg_iov = v, .msg_iovlen = count};
    ssize_t n = sendmsg(c->fd, &msg, MSG_NOSIGNAL);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) { client_arm(slot, EPOLLOUT); return; }
    if (n <= 0) { client_close(slot); return; }
    a->sent += (size_t)n;
    if (a->sent == a->header_len + a->output.len) response_finished(slot);
    else client_arm(slot, EPOLLOUT);
}
void app_complete(Request *r) {
    Client *c = client_at(r->slot);
    if (!c || c->fd < 0 || c->generation != r->generation || !c->active) { request_destroy(r); return; }
    Active *a = c->active;
    if (r->response.cap > BUFFER_BUDGET - worker.output_capacity) {
        uint32_t slot = r->slot;
        request_destroy(r);
        client_close(slot);
        return;
    }
    bool compressed = false;
    if (r->gzip && r->response.len >= worker.gzip_min) {
        size_t capacity = libdeflate_gzip_compress_bound(worker.compressor, r->response.len);
        if (worker.compressed.cap < capacity) {
            char *p = realloc(worker.compressed.data, capacity);
            if (p) { worker.compressed.data = p; worker.compressed.cap = capacity; }
        }
        if (capacity && worker.compressed.cap >= capacity) {
            size_t n = libdeflate_gzip_compress(worker.compressor, r->response.data, r->response.len,
                                               worker.compressed.data, capacity);
            if (n && n < r->response.len) {
                memcpy(r->response.data, worker.compressed.data, n);
                r->response.len = n;
                compressed = true;
            }
        }
    }
    a->output = r->response;
    worker.output_capacity += a->output.cap;
    r->response = (Buffer){0};
    a->close = r->close;
    const char *reason = r->status == 200 ? "OK" : r->status == 201 ? "Created" : r->status == 400 ? "Bad Request" : r->status == 401 ? "Unauthorized" : r->status == 404 ? "Not Found" : r->status == 503 ? "Service Unavailable" : "Internal Server Error";
    a->header_len = (unsigned)snprintf(a->header, sizeof(a->header), "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: %s\r\nVary: Accept-Encoding\r\n%s\r\n", r->status, reason, a->output.len, r->close ? "close" : "keep-alive", compressed ? "Content-Encoding: gzip\r\n" : "");
    uint32_t slot = r->slot;
    request_destroy(r);
    client_write(slot);
}
static bool slice_equal(const char *s, size_t n, const char *text) { return strlen(text) == n && !memcmp(s, text, n); }
static bool slice_case(const char *s, size_t n, const char *text) { return strlen(text) == n && !strncasecmp(s, text, n); }
static bool number(const char *s, size_t n, int64_t *out) {
    if (!n) return false;
    uint64_t value = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9' || value > ((uint64_t)INT64_MAX - (unsigned)(s[i] - '0')) / 10) return false;
        value = value * 10 + (unsigned)(s[i] - '0');
    }
    *out = (int64_t)value;
    return true;
}
static bool header_token(const char *s, size_t n, const char *token) {
    while (n) {
        const char *end = memchr(s, ',', n);
        size_t len = end ? (size_t)(end - s) : n;
        while (len && (*s == ' ' || *s == '\t')) { s++; len--; n--; }
        while (len && (s[len-1] == ' ' || s[len-1] == '\t')) len--;
        if (slice_case(s, len, token)) return true;
        if (!end) break;
        n -= (size_t)(end + 1 - s); s = end + 1;
    }
    return false;
}
static bool accepts_gzip(const char *s, size_t n) {
    bool wildcard = false;
    while (n) {
        const char *end = memchr(s, ',', n);
        size_t item = end ? (size_t)(end - s) : n;
        const char *p = s, *limit = s + item;
        while (p < limit && isspace((unsigned char)*p)) p++;
        const char *name = p;
        while (p < limit && *p != ';' && !isspace((unsigned char)*p)) p++;
        size_t name_len = (size_t)(p - name);
        double q = 1;
        while (p < limit) {
            if (*p++ != ';') continue;
            while (p < limit && isspace((unsigned char)*p)) p++;
            if (limit - p >= 2 && (p[0] == 'q' || p[0] == 'Q') && p[1] == '=') {
                p += 2; q = 0;
                if (p < limit && *p == '1') q = 1;
                else if (p < limit && *p == '0') {
                    p++;
                    if (p < limit && *p == '.') {
                        for (p++; p < limit && isdigit((unsigned char)*p); p++) if (*p != '0') q = 0.5;
                    }
                }
            }
        }
        if (slice_case(name, name_len, "gzip")) return q > 0;
        if (slice_equal(name, name_len, "*")) wildcard = q > 0;
        if (!end) break;
        n -= item + 1; s = end + 1;
    }
    return wildcard;
}
typedef struct {
    const char *path, *auth, *body;
    size_t path_len, auth_len, body_len, total;
    bool post, get, gzip, close, expect;
} Http;
static int parse_http(const char *data, size_t len, Http *h) {
    const char *end = memmem(data, len, "\r\n\r\n", 4);
    if (!end) return len == MAX_REQUEST ? -1 : 0;
    size_t head_len = (size_t)(end + 4 - data);
    const char *line = memmem(data, head_len, "\r\n", 2);
    const char *space = memchr(data, ' ', (size_t)(line - data));
    if (!space) return -1;
    h->get = slice_equal(data, (size_t)(space-data), "GET");
    h->post = slice_equal(data, (size_t)(space-data), "POST");
    h->path = space + 1;
    space = memchr(h->path, ' ', (size_t)(line - h->path));
    if (!space || *h->path != '/') return -1;
    h->path_len = (size_t)(space - h->path);
    const char *query = memchr(h->path, '?', h->path_len);
    if (query) h->path_len = (size_t)(query - h->path);
    bool v10 = slice_equal(space + 1, (size_t)(line - space - 1), "HTTP/1.0");
    if (!v10 && !slice_equal(space + 1, (size_t)(line-space-1), "HTTP/1.1")) return -1;
    h->close = v10;
    bool has_length = false;
    for (const char *p = line + 2; p < end; ) {
        const char *next = memmem(p, (size_t)(end + 2 - p), "\r\n", 2);
        if (!next) return -1;
        const char *colon = memchr(p, ':', (size_t)(next - p));
        if (!colon || colon == p) return -1;
        for (const char *k = p; k < colon; k++) if (!isalnum((unsigned char)*k) && *k != '-') return -1;
        const char *value = colon + 1;
        while (value < next && (*value == ' ' || *value == '\t')) value++;
        const char *last = next;
        while (last > value && (last[-1] == ' ' || last[-1] == '\t')) last--;
        for (const char *k = value; k < last; k++) if ((unsigned char)*k < 32 && *k != '\t') return -1;
        size_t key_len = (size_t)(colon - p), value_len = (size_t)(last - value);
        if (slice_case(p, key_len, "Content-Length")) {
            int64_t n;
            if (has_length || !number(value, value_len, &n) || n > MAX_REQUEST - (int64_t)head_len) return -1;
            h->body_len = (size_t)n; has_length = true;
        } else if (slice_case(p, key_len, "Transfer-Encoding")) return -1;
        else if (slice_case(p, key_len, "Authorization")) {
            if (h->auth) return -1;
            h->auth = value; h->auth_len = value_len;
        } else if (slice_case(p, key_len, "Accept-Encoding")) h->gzip = accepts_gzip(value, value_len);
        else if (slice_case(p, key_len, "Connection")) {
            if (header_token(value, value_len, "close")) h->close = true;
            else if (v10 && header_token(value, value_len, "keep-alive")) h->close = false;
        } else if (slice_case(p, key_len, "Expect")) h->expect = slice_case(value, value_len, "100-continue");
        p = next + 2;
    }
    h->body = data + head_len;
    h->total = head_len + h->body_len;
    return len >= h->total ? 1 : 0;
}
static void process_input(uint32_t slot) {
    Client *c = client_at(slot);
    Active *a = c->active;
    Http h = {0};
    int parsed = parse_http(a->input.data, a->input.len, &h);
    if (!parsed) {
        if (h.expect && !a->interim_sent) { a->interim = true; client_write(slot); }
        else client_arm(slot, EPOLLIN);
        return;
    }
    Request *r = calloc(1, sizeof(*r));
    if (!r) { client_close(slot); return; }
    r->slot = slot; r->generation = c->generation; r->gzip = h.gzip; r->close = h.close;
    a->busy = true;
    const char *error = NULL;
    int status = 400;
    if (parsed < 0) { error = "malformed HTTP request"; r->close = true; }
    else {
        bool authenticated = false;
        const char *id = NULL; size_t id_len = 0;
        if (h.get && slice_equal(h.path, h.path_len, "/health")) r->route = HEALTH;
        else if (h.get && slice_equal(h.path, h.path_len, "/feed")) r->route = FEED;
        else if (h.post && slice_equal(h.path, h.path_len, "/posts")) { r->route = POST_CREATE; authenticated = true; }
        else if (h.path_len > 7 && !memcmp(h.path, "/posts/", 7)) {
            if (h.post && h.path_len > 12 && !memcmp(h.path + h.path_len - 5, "/like", 5) &&
                !memchr(h.path + 7, '/', h.path_len - 12)) {
                r->route = POST_LIKE; authenticated = true; id = h.path + 7; id_len = h.path_len - 12;
            } else if (h.get && !memchr(h.path + 7, '/', h.path_len - 7)) { r->route = POST_GET; id = h.path + 7; id_len = h.path_len - 7; }
            else { error = "not found"; status = 404; }
        } else { error = "not found"; status = 404; }
        if (!error && authenticated) {
            status = 401;
            if (!h.auth || h.auth_len < 7 || memcmp(h.auth, "Bearer ", 7)) error = "missing bearer token";
            else error = auth_verify(worker.auth, h.auth + 7, h.auth_len - 7, r);
        }
        if (!error && id && (!number(id, id_len, &r->id) || r->id <= 0)) { error = "invalid post id"; status = 400; }
        if (!error && r->route == POST_CREATE) { error = parse_post_body(h.body, h.body_len, r); status = 400; }
        size_t left = a->input.len - h.total;
        if (left) memmove(a->input.data, a->input.data + h.total, left);
        a->input.len = left;
        if (!left) {
            worker.input_capacity -= a->input.cap;
            buffer_free(&a->input);
        }
        a->interim_sent = 0;
    }
    if (error) {
        if (!strcmp(error, "internal server error")) status = 500;
        request_error(r, status, error);
        app_complete(r);
    } else db_submit(worker.db, r);
}
static void client_read(uint32_t slot) {
    Client *c = client_at(slot);
    if (!c->active) {
        if (worker.active_count >= ACTIVE_LIMIT) { client_close(slot); return; }
        c->active = calloc(1, sizeof(*c->active));
        if (!c->active) { client_close(slot); return; }
        worker.active_count++;
    }
    Active *a = c->active;
    size_t room = MAX_REQUEST - a->input.len;
    ssize_t n = recv(c->fd, worker.scratch, room, 0);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
        if (!a->input.len) { active_free(a); c->active = NULL; }
        client_arm(slot, EPOLLIN); return;
    }
    if (n <= 0) { client_close(slot); return; }
    size_t old_capacity = a->input.cap, capacity = old_capacity ? old_capacity : 256;
    while (capacity < a->input.len + (size_t)n + 1) capacity *= 2;
    if (capacity - old_capacity > BUFFER_BUDGET - worker.input_capacity ||
        !buffer_append(&a->input, worker.scratch, (size_t)n)) { client_close(slot); return; }
    worker.input_capacity += a->input.cap - old_capacity;
    process_input(slot);
}
static int listener(const char *host, const char *port) {
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM, .ai_flags = AI_NUMERICSERV | AI_PASSIVE};
    struct addrinfo *addresses = NULL;
    int error = getaddrinfo(host, port, &hints, &addresses);
    if (error) { fprintf(stderr, "listen address: %s\n", gai_strerror(error)); return -1; }
    int fd = -1, yes = 1;
    for (struct addrinfo *a = addresses; a; a = a->ai_next) {
        fd = socket(a->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) continue;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes)) == 0 && bind(fd, a->ai_addr, a->ai_addrlen) == 0 && listen(fd, 65535) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(addresses);
    return fd;
}
static void accept_clients(int listener_fd) {
    for (unsigned batch = 0; batch < 512; batch++) {
        int fd = accept4(listener_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR) continue;
            return;
        }
        int yes = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
        uint32_t slot = client_allocate(fd);
        if (slot == NONE) { close(fd); continue; }
        Client *c = client_at(slot);
        struct epoll_event e = {.events = CLIENT_EVENTS, .data.u64 = client_key(slot, c)};
        if (epoll_ctl(worker.epoll_fd, EPOLL_CTL_ADD, fd, &e)) client_close(slot);
    }
}
static int worker_run(const char *host, const char *ports[2], const char *url, const char *secret, unsigned reads, unsigned writes, unsigned gzip_min) {
    worker.free_head = worker.ready_head = worker.ready_tail = NONE;
    worker.gzip_min = gzip_min;
    worker.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    worker.auth = auth_create(secret);
    worker.compressor = libdeflate_alloc_compressor(1);
    if (worker.epoll_fd < 0 || !worker.auth || !worker.compressor) return 1;
    for (unsigned i = 0; i < 2; i++) {
        worker.listeners[i] = listener(host, ports[i]);
        if (worker.listeners[i] < 0) { perror("listen"); return 1; }
        struct epoll_event e = {.events = EPOLLIN, .data.u64 = LISTEN_EVENT | i};
        if (epoll_ctl(worker.epoll_fd, EPOLL_CTL_ADD, worker.listeners[i], &e)) return 1;
    }
    worker.db = db_create(worker.epoll_fd, url, reads, writes);
    if (!worker.db) return 1;
    fprintf(stderr, "worker=%ld reads=%u writes=%u gzip_min=%u idle_slot=%zu\n", (long)getpid(), reads, writes, gzip_min, sizeof(Client));
    struct epoll_event events[1024];
    while (!stopping) {
        int n = epoll_wait(worker.epoll_fd, events, 1024, worker.ready_head == NONE ? 100 : 0);
        if (n < 0 && errno != EINTR) break;
        for (int i = 0; i < n; i++) {
            uint64_t key = events[i].data.u64;
            if (key & DB_EVENT) db_event(worker.db, (unsigned)(key & ~DB_EVENT), events[i].events);
            else if (key & LISTEN_EVENT) accept_clients(worker.listeners[key & 1]);
            else {
                uint32_t slot = (uint32_t)key;
                Client *c = client_at(slot);
                if (!c || c->fd < 0 || c->generation != key >> 32) continue;
                if (events[i].events & EPOLLERR) client_close(slot);
                else if (events[i].events & EPOLLOUT) client_write(slot);
                else client_read(slot);
            }
        }
        for (unsigned i = 0; i < 1024 && worker.ready_head != NONE; i++) {
            uint32_t slot = worker.ready_head;
            Client *c = client_at(slot);
            worker.ready_head = c->active->next_ready;
            if (worker.ready_head == NONE) worker.ready_tail = NONE;
            c->active->queued = false;
            if (c->fd >= 0) process_input(slot);
            else {
                active_free(c->active); c->active = NULL;
                c->next = worker.free_head; worker.free_head = slot;
            }
        }
        db_tick(worker.db, monotonic_ms());
    }
    db_destroy(worker.db);
    libdeflate_free_compressor(worker.compressor);
    buffer_free(&worker.compressed);
    return stopping ? 0 : 1;
}
static unsigned positive_env(const char *name, unsigned fallback, unsigned max) {
    const char *value = getenv(name);
    if (!value || !*value) return fallback;
    int64_t n;
    if (!number(value, strlen(value), &n) || n < 1 || n > max) { fprintf(stderr, "invalid %s\n", name); exit(1); }
    return (unsigned)n;
}
static unsigned cpu_count(void) {
    cpu_set_t cpus;
    unsigned count = sched_getaffinity(0, sizeof(cpus), &cpus) == 0 ? (unsigned)CPU_COUNT(&cpus) : 1;
    char path[PATH_MAX] = "/sys/fs/cgroup", line[PATH_MAX];
    FILE *groups = fopen("/proc/self/cgroup", "r");
    if (groups) {
        while (fgets(line, sizeof(line), groups)) {
            if (strncmp(line, "0::/", 4)) continue;
            line[strcspn(line, "\r\n")] = 0;
            if (strlen(line + 3) + strlen(path) + 1 < sizeof(path)) strcat(path, line + 3);
            break;
        }
        fclose(groups);
    }
    for (;;) {
        char filename[PATH_MAX + 9];
        snprintf(filename, sizeof(filename), "%s/cpu.max", path);
        FILE *f = fopen(filename, "r");
        if (f) {
            unsigned long long quota, period;
            if (fscanf(f, "%llu %llu", &quota, &period) == 2 && period && quota) {
                unsigned long long limit = quota / period + (quota % period != 0);
                if (limit < count) count = (unsigned)limit;
            }
            fclose(f);
        }
        if (!strcmp(path, "/sys/fs/cgroup")) break;
        char *slash = strrchr(path, '/');
        if (!slash || slash < path + strlen("/sys/fs/cgroup")) break;
        *slash = 0;
    }
    return count > 16 ? 16 : count ? count : 1;
}
int main(void) {
    const char *url = getenv("DATABASE_URL"), *secret = getenv("JWT_SECRET");
    const char *host = getenv("HOST"), *ports[2] = {getenv("PORT"), getenv("EXTRA_PORT")};
    if (!url || !secret) { fprintf(stderr, "DATABASE_URL and JWT_SECRET are required\n"); return 1; }
    if (!host) host = "0.0.0.0";
    if (!ports[0]) ports[0] = "80";
    if (!ports[1]) ports[1] = "81";
    unsigned count = positive_env("WORKERS", cpu_count(), 16);
    unsigned reads = positive_env("DB_READ_CONNECTIONS", count * 4, 496), writes = positive_env("DB_WRITE_CONNECTIONS", 64, 496);
    unsigned gzip_min = positive_env("GZIP_MIN", count == 1 ? 8192 : 512, UINT_MAX);
    if (reads < count || writes < count || reads + writes > 512) { fprintf(stderr, "database pools require at least one connection per worker and at most 512 total\n"); return 1; }
    started_ms = monotonic_ms();
    struct sigaction action = {.sa_handler = stop_signal};
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL); sigaction(SIGINT, &action, NULL);
    signal(SIGPIPE, SIG_IGN);
    if (count == 1) return worker_run(host, ports, url, secret, reads, writes, gzip_min);
    pid_t children[16] = {0};
    int status = 0;
    for (unsigned i = 0; i < count; i++) {
        pid_t child = fork();
        if (!child) {
            prctl(PR_SET_PDEATHSIG, SIGTERM);
            if (getppid() == 1) return 1;
            return worker_run(host, ports, url, secret, reads/count + (i < reads%count), writes/count + (i < writes%count), gzip_min);
        }
        if (child < 0) { stopping = 1; status = 1; break; }
        children[i] = child;
    }
    if (!stopping) {
        pid_t exited;
        do { exited = waitpid(-1, &status, 0); } while (exited < 0 && errno == EINTR && !stopping);
        if (!stopping) { fprintf(stderr, "worker exited unexpectedly\n"); status = 1; }
        else status = 0;
    }
    for (unsigned i = 0; i < count; i++) if (children[i]) kill(children[i], SIGTERM);
    while (waitpid(-1, NULL, 0) > 0 || errno == EINTR) {}
    return status ? 1 : 0;
}
