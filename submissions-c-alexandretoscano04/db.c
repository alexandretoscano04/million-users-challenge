#include "app.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>

#define PIPELINE_LIMIT 32
#define WAITING_LIMIT 4096
#define CONNECT_TIMEOUT 5000
#define REQUEST_TIMEOUT 30000

typedef enum { DB_DOWN, DB_CONNECTING, DB_PREPARING, DB_READY } DbState;
typedef struct {
    Request *request;
    uint64_t sent_ms;
    bool result_seen;
} Pending;
typedef struct {
    PGconn *connection;
    DbState state;
    int registered_fd;
    uint32_t interest;
    bool dirty;
    unsigned index, generation, head, count, prepared;
    uint64_t retry_ms, connect_ms;
    Pending pending[PIPELINE_LIMIT];
} DbConnection;
struct DbPool {
    int epoll_fd;
    char *url;
    unsigned reads, writes, total;
    uint64_t now_ms, tick_ms;
    DbConnection *connections;
    Request *waiting_head[2], *waiting_tail[2];
    unsigned waiting_count[2];
};

static const char *const statement_names[] = { "health", "feed", "post", "create", "like" };
static const char *const statement_sql[] = {
    "SELECT 1",
    "SELECT p.id, p.body, p.created_at, u.username, (SELECT count(*) FROM likes l WHERE l.post_id = p.id)::int AS like_count FROM posts p JOIN users u ON u.id = p.user_id ORDER BY p.created_at DESC, p.id DESC LIMIT 20",
    "SELECT p.id, p.body, p.created_at, u.username, (SELECT count(*) FROM likes l WHERE l.post_id = p.id)::int AS like_count FROM posts p JOIN users u ON u.id = p.user_id WHERE p.id = $1",
    "INSERT INTO posts (user_id, body) VALUES ($1, $2) RETURNING id, created_at",
    "INSERT INTO likes (user_id, post_id) VALUES ($1, $2) ON CONFLICT (user_id, post_id) DO NOTHING"
};
static const int statement_parameters[] = { 0, 0, 1, 2, 2 };

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void database_error(Request *request, const char *message) {
    if (request->route != HEALTH) {
        request_error(request, 500, "internal server error");
        return;
    }
    buffer_free(&request->response);
    request->status = 503;
    if (!buffer_text(&request->response, "{\"status\":\"degraded\",\"db\":\"unreachable\",\"error\":") ||
        !buffer_json(&request->response, message, strlen(message)) ||
        !buffer_text(&request->response, "}"))
        request_error(request, 500, "internal server error");
}

static void disconnect_database(DbPool *pool, DbConnection *db, const char *message, bool complete) {
    char error[512];
    snprintf(error, sizeof(error), "%s", message ? message : "database unavailable");
    if (db->registered_fd >= 0)
        epoll_ctl(pool->epoll_fd, EPOLL_CTL_DEL, db->registered_fd, NULL);
    db->registered_fd = -1;
    db->interest = 0;
    db->dirty = false;
    db->state = DB_DOWN;
    db->retry_ms = pool->now_ms + 1000;
    if (db->connection) PQfinish(db->connection);
    db->connection = NULL;
    while (db->count) {
        Pending *pending = &db->pending[db->head];
        Request *request = pending->request;
        memset(pending, 0, sizeof(*pending));
        db->head = (db->head + 1) % PIPELINE_LIMIT;
        db->count--;
        if (complete) {
            database_error(request, error);
            app_complete(request);
        } else {
            request_destroy(request);
        }
    }
    db->head = 0;
    db->prepared = 0;
}

static bool watch_database(DbPool *pool, DbConnection *db, uint32_t interest) {
    int fd = PQsocket(db->connection);
    if (fd < 0) return false;
    if (fd == db->registered_fd && interest == db->interest) return true;
    struct epoll_event event = { .events = interest | EPOLLRDHUP };
    event.data.u64 = DB_EVENT | ((uint64_t)db->generation << 9) | db->index;
    int operation = EPOLL_CTL_MOD;
    if (fd != db->registered_fd) {
        if (db->registered_fd >= 0)
            epoll_ctl(pool->epoll_fd, EPOLL_CTL_DEL, db->registered_fd, NULL);
        db->registered_fd = -1;
        operation = EPOLL_CTL_ADD;
    }
    if (epoll_ctl(pool->epoll_fd, operation, fd, &event) < 0) {
        if (operation != EPOLL_CTL_MOD || errno != ENOENT ||
            epoll_ctl(pool->epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0)
            return false;
    }
    db->registered_fd = fd;
    db->interest = interest;
    return true;
}

static bool flush_database(DbPool *pool, DbConnection *db) {
    db->dirty = false;
    int result = PQflush(db->connection);
    if (result < 0 || !watch_database(pool, db, EPOLLIN | (result ? EPOLLOUT : 0))) {
        disconnect_database(pool, db, PQerrorMessage(db->connection), true);
        return false;
    }
    return true;
}

static void start_preparing(DbPool *pool, DbConnection *db) {
    if (PQsetnonblocking(db->connection, 1) != 0 || !PQenterPipelineMode(db->connection)) {
        disconnect_database(pool, db, PQerrorMessage(db->connection), true);
        return;
    }
    db->state = DB_PREPARING;
    db->prepared = 0;
    for (unsigned i = 0; i < 5; i++) {
        Oid types[2] = { 20, i == POST_CREATE ? 25 : 20 };
        if (!PQsendPrepare(db->connection, statement_names[i], statement_sql[i], statement_parameters[i], types)) {
            disconnect_database(pool, db, PQerrorMessage(db->connection), true);
            return;
        }
    }
    if (!PQpipelineSync(db->connection)) {
        disconnect_database(pool, db, PQerrorMessage(db->connection), true);
        return;
    }
    flush_database(pool, db);
}

static void poll_connection(DbPool *pool, DbConnection *db) {
    PostgresPollingStatusType result = PQconnectPoll(db->connection);
    if (result == PGRES_POLLING_OK) {
        start_preparing(pool, db);
    } else if (result == PGRES_POLLING_READING || result == PGRES_POLLING_WRITING) {
        if (!watch_database(pool, db, result == PGRES_POLLING_READING ? EPOLLIN : EPOLLOUT))
            disconnect_database(pool, db, "database socket registration failed", true);
    } else {
        disconnect_database(pool, db, PQerrorMessage(db->connection), true);
    }
}

static void start_connection(DbPool *pool, DbConnection *db) {
    db->generation = (db->generation + 1) & 0x7fffff;
    if (!db->generation) db->generation = 1;
    const char *keywords[] = { "dbname", "options", "fallback_application_name", NULL };
    const char *values[] = { pool->url, "-c timezone=UTC -c datestyle=ISO,YMD", "compact-feed", NULL };
    db->connection = PQconnectStartParams(keywords, values, 1);
    db->connect_ms = pool->now_ms;
    db->state = DB_CONNECTING;
    if (!db->connection) {
        disconnect_database(pool, db, "database connection allocation failed", true);
        return;
    }
    if (PQstatus(db->connection) == CONNECTION_BAD) {
        disconnect_database(pool, db, PQerrorMessage(db->connection), true);
        return;
    }
    poll_connection(pool, db);
}

static int64_t binary_integer(const char *data) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; i++) value = (value << 8) | (unsigned char)data[i];
    return (int64_t)value;
}

static bool success_response(Request *request, PGresult *result) {
    Buffer *output = &request->response;
    request->status = 200;
    switch (request->route) {
        case HEALTH:
            return PQntuples(result) == 1 &&
                buffer_text(output, "{\"status\":\"ok\",\"db\":\"ok\",\"uptime_s\":") &&
                buffer_integer(output, (int64_t)app_uptime()) && buffer_text(output, "}");
        case FEED:
            if (!buffer_text(output, "{\"posts\":[")) return false;
            for (int row = 0; row < PQntuples(result); row++) {
                if ((row && !buffer_text(output, ",")) || !buffer_post(output, result, row)) return false;
            }
            return buffer_text(output, "]}");
        case POST_GET:
            if (!PQntuples(result)) {
                request_error(request, 404, "post not found");
                return true;
            }
            return PQntuples(result) == 1 && buffer_text(output, "{\"post\":") &&
                buffer_post(output, result, 0) && buffer_text(output, "}");
        case POST_CREATE:
            request->status = 201;
            return PQntuples(result) == 1 && PQnfields(result) == 2 &&
                PQgetlength(result, 0, 0) == 8 && PQgetlength(result, 0, 1) == 8 &&
                buffer_text(output, "{\"post\":{\"id\":") &&
                buffer_integer(output, binary_integer(PQgetvalue(result, 0, 0))) &&
                buffer_text(output, ",\"body\":") && buffer_json(output, request->body, request->body_len) &&
                buffer_text(output, ",\"created_at\":") &&
                buffer_timestamp(output, PQgetvalue(result, 0, 1), PQgetlength(result, 0, 1)) &&
                buffer_text(output, ",\"author\":") && buffer_json(output, request->username, request->username_len) &&
                buffer_text(output, ",\"like_count\":0}}");
        case POST_LIKE: {
            const char *affected = PQcmdTuples(result);
            bool inserted = !strcmp(affected, "1");
            if (!inserted && strcmp(affected, "0")) return false;
            request->status = inserted ? 201 : 200;
            return buffer_text(output, inserted ?
                "{\"liked\":true,\"already_liked\":false,\"post_id\":" :
                "{\"liked\":true,\"already_liked\":true,\"post_id\":") &&
                buffer_integer(output, request->id) && buffer_text(output, "}");
        }
    }
    return false;
}

static void query_result(Pending *pending, PGresult *result) {
    Request *request = pending->request;
    if (pending->result_seen) {
        request_error(request, 500, "internal server error");
        return;
    }
    pending->result_seen = true;
    ExecStatusType status = PQresultStatus(result);
    if ((status == PGRES_TUPLES_OK && request->route != POST_LIKE) ||
        (status == PGRES_COMMAND_OK && request->route == POST_LIKE)) {
        if (!success_response(request, result)) request_error(request, 500, "internal server error");
        return;
    }
    const char *state = PQresultErrorField(result, PG_DIAG_SQLSTATE);
    if (request->route == POST_LIKE && state && !strcmp(state, "23503"))
        request_error(request, 404, "post not found");
    else
        database_error(request, *PQresultErrorMessage(result) ? PQresultErrorMessage(result) : "database query failed");
}

static void consume_results(DbPool *pool, DbConnection *db) {
    while (db->state != DB_DOWN) {
        int busy = PQisBusy(db->connection);
        if (PQstatus(db->connection) == CONNECTION_BAD) {
            disconnect_database(pool, db, PQerrorMessage(db->connection), true);
            return;
        }
        if (busy) return;
        PGresult *result = PQgetResult(db->connection);
        if (!result) {
            if (db->state == DB_READY && !db->count) return;
            continue;
        }
        ExecStatusType status = PQresultStatus(result);
        if (db->state == DB_PREPARING) {
            if (status == PGRES_COMMAND_OK) {
                db->prepared++;
            } else if (status == PGRES_PIPELINE_SYNC && db->prepared == 5) {
                db->state = DB_READY;
            } else {
                char message[512];
                snprintf(message, sizeof(message), "%s", PQresultErrorMessage(result));
                PQclear(result);
                disconnect_database(pool, db, *message ? message : "database prepare failed", true);
                return;
            }
        } else if (status == PGRES_PIPELINE_SYNC) {
            if (!db->count) {
                PQclear(result);
                disconnect_database(pool, db, "unexpected database synchronization", true);
                return;
            }
            Pending *pending = &db->pending[db->head];
            Request *request = pending->request;
            if (!pending->result_seen) request_error(request, 500, "internal server error");
            memset(pending, 0, sizeof(*pending));
            db->head = (db->head + 1) % PIPELINE_LIMIT;
            db->count--;
            PQclear(result);
            app_complete(request);
            continue;
        } else if (db->count) {
            query_result(&db->pending[db->head], result);
        } else {
            PQclear(result);
            disconnect_database(pool, db, "unexpected database result", true);
            return;
        }
        PQclear(result);
    }
}

DbPool *db_create(int epoll_fd, const char *url, unsigned reads, unsigned writes) {
    if (!url || !reads || reads > 512 || writes > 512 || reads + writes > 512) return NULL;
    DbPool *pool = calloc(1, sizeof(*pool));
    if (!pool) return NULL;
    pool->epoll_fd = epoll_fd;
    pool->reads = reads;
    pool->writes = writes;
    pool->total = reads + writes;
    pool->url = strdup(url);
    pool->connections = calloc(pool->total, sizeof(*pool->connections));
    if (!pool->url || !pool->connections) {
        free(pool->url);
        free(pool->connections);
        free(pool);
        return NULL;
    }
    pool->now_ms = monotonic_ms();
    for (unsigned i = 0; i < pool->total; i++) {
        DbConnection *db = &pool->connections[i];
        db->index = i;
        db->registered_fd = -1;
        start_connection(pool, db);
    }
    return pool;
}

static unsigned request_group(DbPool *pool, Request *request) {
    return pool->writes && (request->route == POST_CREATE || request->route == POST_LIKE);
}

static DbConnection *select_connection(DbPool *pool, unsigned group, bool *available) {
    unsigned start = group ? pool->reads : 0, end = group ? pool->total : pool->reads;
    DbConnection *selected = NULL;
    *available = false;
    for (unsigned i = start; i < end; i++) {
        DbConnection *db = &pool->connections[i];
        if (db->state != DB_READY) continue;
        *available = true;
        if (db->count < PIPELINE_LIMIT && (!selected || db->count < selected->count)) selected = db;
    }
    return selected;
}

static void send_request(DbPool *pool, DbConnection *selected, Request *request) {
    bool writing = request->route == POST_CREATE || request->route == POST_LIKE;
    if (request->route == POST_CREATE && memchr(request->body, '\0', request->body_len)) {
        request_error(request, 500, "internal server error");
        app_complete(request);
        return;
    }
    char first[32], second[32];
    const char *parameters[2] = { first, second };
    if (request->route == POST_GET) {
        snprintf(first, sizeof(first), "%lld", (long long)request->id);
    } else if (writing) {
        snprintf(first, sizeof(first), "%lld", (long long)request->user_id);
        if (request->route == POST_CREATE) parameters[1] = request->body;
        else snprintf(second, sizeof(second), "%lld", (long long)request->id);
    }
    unsigned index = (selected->head + selected->count) % PIPELINE_LIMIT;
    selected->pending[index] = (Pending){ .request = request, .sent_ms = monotonic_ms() };
    selected->count++;
    if (!PQsendQueryPrepared(selected->connection, statement_names[request->route],
            statement_parameters[request->route], parameters, NULL, NULL, 1)) {
        disconnect_database(pool, selected, PQerrorMessage(selected->connection), true);
        return;
    }
#if defined(COMPACT_DB_BATCH) && defined(LIBPQ_HAS_SEND_PIPELINE_SYNC)
    if (!PQsendPipelineSync(selected->connection)) {
        disconnect_database(pool, selected, PQerrorMessage(selected->connection), true);
        return;
    }
    selected->dirty = true;
#else
    if (!PQpipelineSync(selected->connection)) {
        disconnect_database(pool, selected, PQerrorMessage(selected->connection), true);
        return;
    }
    flush_database(pool, selected);
#endif
}

static void queue_request(DbPool *pool, unsigned group, Request *request) {
    if (pool->waiting_count[group] == WAITING_LIMIT) {
        database_error(request, "database waiting queue full");
        app_complete(request);
        return;
    }
    request->next = NULL;
    if (pool->waiting_tail[group]) pool->waiting_tail[group]->next = request;
    else pool->waiting_head[group] = request;
    pool->waiting_tail[group] = request;
    pool->waiting_count[group]++;
}

static Request *dequeue_request(DbPool *pool, unsigned group) {
    Request *request = pool->waiting_head[group];
    pool->waiting_head[group] = request->next;
    if (!pool->waiting_head[group]) pool->waiting_tail[group] = NULL;
    pool->waiting_count[group]--;
    request->next = NULL;
    return request;
}

static void drain_waiting(DbPool *pool) {
    for (unsigned group = 0; group < 2; group++) {
        while (pool->waiting_head[group]) {
            bool available;
            DbConnection *db = select_connection(pool, group, &available);
            if (!db && available) break;
            Request *request = dequeue_request(pool, group);
            if (db) send_request(pool, db, request);
            else {
                database_error(request, "database pool unavailable");
                app_complete(request);
            }
        }
    }
}

void db_submit(DbPool *pool, Request *request) {
    unsigned group = request_group(pool, request);
    bool available;
    DbConnection *db = select_connection(pool, group, &available);
    if (!available) {
        database_error(request, "database pool unavailable");
        app_complete(request);
    } else if (pool->waiting_head[group] || !db) {
        queue_request(pool, group, request);
    } else {
        send_request(pool, db, request);
    }
}

void db_event(DbPool *pool, unsigned token, uint32_t events) {
    unsigned index = token & 511;
    if (index >= pool->total) return;
    DbConnection *db = &pool->connections[index];
    if (db->state == DB_DOWN || db->generation != token >> 9) return;
    if (db->state == DB_CONNECTING) {
        poll_connection(pool, db);
        return;
    }
    if (events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
        if (!PQconsumeInput(db->connection)) {
            disconnect_database(pool, db, PQerrorMessage(db->connection), true);
            return;
        }
    }
    if ((events & EPOLLOUT) && !flush_database(pool, db)) return;
    consume_results(pool, db);
}

void db_tick(DbPool *pool, uint64_t now_ms) {
    pool->now_ms = now_ms;
    drain_waiting(pool);
#if defined(COMPACT_DB_BATCH) && defined(LIBPQ_HAS_SEND_PIPELINE_SYNC)
    for (unsigned i = 0; i < pool->total; i++) {
        DbConnection *db = &pool->connections[i];
        if (db->dirty) flush_database(pool, db);
    }
#endif
    if (now_ms < pool->tick_ms) return;
    pool->tick_ms = now_ms + 250;
    for (unsigned i = 0; i < pool->total; i++) {
        DbConnection *db = &pool->connections[i];
        if (db->state == DB_DOWN && now_ms >= db->retry_ms)
            start_connection(pool, db);
        else if ((db->state == DB_CONNECTING || db->state == DB_PREPARING) &&
            now_ms - db->connect_ms >= CONNECT_TIMEOUT)
            disconnect_database(pool, db, "database connection timeout", true);
        else if (db->count && now_ms - db->pending[db->head].sent_ms >= REQUEST_TIMEOUT)
            disconnect_database(pool, db, "database request timeout", true);
    }
}

void db_destroy(DbPool *pool) {
    if (!pool) return;
    for (unsigned group = 0; group < 2; group++)
        while (pool->waiting_head[group]) request_destroy(dequeue_request(pool, group));
    for (unsigned i = 0; i < pool->total; i++)
        disconnect_database(pool, &pool->connections[i], "server shutting down", false);
    free(pool->connections);
    free(pool->url);
    free(pool);
}
