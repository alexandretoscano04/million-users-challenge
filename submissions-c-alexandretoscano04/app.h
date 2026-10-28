#ifndef COMPACT_APP_H
#define COMPACT_APP_H
#define _GNU_SOURCE
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <libpq-fe.h>

#define DB_EVENT (UINT64_C(1) << 63)
#define LISTEN_EVENT (UINT64_C(1) << 62)
#define MAX_REQUEST 65536

typedef struct { char *data; size_t len, cap; } Buffer;
typedef enum { HEALTH, FEED, POST_GET, POST_CREATE, POST_LIKE } Route;
typedef struct Request Request;
struct Request {
    Request *next;
    uint32_t slot, generation;
    Route route;
    bool gzip, close;
    int status;
    int64_t id, user_id;
    char *body, *username;
    size_t body_len, username_len;
    Buffer response;
};

typedef struct Auth Auth;
bool buffer_append(Buffer *b, const void *data, size_t len);
bool buffer_text(Buffer *b, const char *text);
bool buffer_integer(Buffer *b, int64_t n);
bool buffer_json(Buffer *b, const char *text, size_t len);
void buffer_free(Buffer *b);
bool buffer_timestamp(Buffer *b, const char *data, int len);
bool buffer_post(Buffer *b, PGresult *result, int row);
Auth *auth_create(const char *secret);
void auth_destroy(Auth *auth);
const char *auth_verify(Auth *auth, const char *token, size_t len, Request *request);
const char *parse_post_body(const char *body, size_t len, Request *request);
void request_destroy(Request *request);
void request_error(Request *request, int status, const char *message);
void app_complete(Request *request);
uint64_t app_uptime(void);

typedef struct DbPool DbPool;
DbPool *db_create(int epoll_fd, const char *url, unsigned reads, unsigned writes);
void db_submit(DbPool *pool, Request *request);
void db_event(DbPool *pool, unsigned index, uint32_t events);
void db_tick(DbPool *pool, uint64_t now_ms);
void db_destroy(DbPool *pool);
#endif
