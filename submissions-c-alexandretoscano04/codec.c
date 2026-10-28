#include "postgres_fe.h"
#include "libpq-int.h"
#include "app.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(__AVX2__)
#include <immintrin.h>
#endif

bool buffer_append(Buffer *b, const void *data, size_t len) {
    if (len > SIZE_MAX - b->len - 1) return false;
    size_t need = b->len + len + 1;
    if (need > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        while (cap < need) {
            if (cap > SIZE_MAX / 2) { cap = need; break; }
            cap *= 2;
        }
        char *next = realloc(b->data, cap);
        if (!next) return false;
        b->data = next;
        b->cap = cap;
    }
    if (len) memcpy(b->data + b->len, data, len);
    b->len += len;
    b->data[b->len] = 0;
    return true;
}

bool buffer_text(Buffer *b, const char *text) {
    return buffer_append(b, text, strlen(text));
}

bool buffer_integer(Buffer *b, int64_t n) {
    char text[20], *end = text + sizeof(text), *p = end;
    uint64_t value = (uint64_t)n;
    if (n < 0) value = 0 - value;
    do {
        *--p = (char)('0' + value % 10);
        value /= 10;
    } while (value);
    if (n < 0) *--p = '-';
    return buffer_append(b, p, (size_t)(end - p));
}

static size_t next_escape(const char *text, size_t offset, size_t len) {
#if defined(__AVX2__)
    const __m256i zero = _mm256_setzero_si256();
    const __m256i high = _mm256_set1_epi8(-32);
    const __m256i quote = _mm256_set1_epi8('"');
    const __m256i slash = _mm256_set1_epi8('\\');
    while (len - offset >= 32) {
        __m256i value = _mm256_loadu_si256((const __m256i *)(text + offset));
        __m256i control = _mm256_cmpeq_epi8(_mm256_and_si256(value, high), zero);
        __m256i special = _mm256_or_si256(control, _mm256_or_si256(
            _mm256_cmpeq_epi8(value, quote), _mm256_cmpeq_epi8(value, slash)));
        unsigned mask = (unsigned)_mm256_movemask_epi8(special);
        if (mask) return offset + (unsigned)__builtin_ctz(mask);
        offset += 32;
    }
#endif
    while (offset < len) {
        unsigned char c = (unsigned char)text[offset];
        if (c < 32 || c == '"' || c == '\\') break;
        offset++;
    }
    return offset;
}

bool buffer_json(Buffer *b, const char *text, size_t len) {
    static const char hex[] = "0123456789abcdef";
    if (!buffer_text(b, "\"")) return false;
    size_t start = 0;
    for (size_t i = next_escape(text, 0, len); i < len; i = next_escape(text, i + 1, len)) {
        unsigned char c = (unsigned char)text[i];
        if (!buffer_append(b, text + start, i - start)) return false;
        char escape[6] = {'\\', 'u', '0', '0', hex[c >> 4], hex[c & 15]};
        if (c == '"' || c == '\\') {
            escape[1] = (char)c;
            if (!buffer_append(b, escape, 2)) return false;
        } else if (!buffer_append(b, escape, sizeof(escape))) return false;
        start = i + 1;
    }
    return buffer_append(b, text + start, len - start) && buffer_text(b, "\"");
}

void buffer_free(Buffer *b) {
    free(b->data);
    *b = (Buffer){0};
}

static uint64_t read_u64(const char *data) {
    uint64_t n = 0;
    for (unsigned i = 0; i < 8; i++) n = (n << 8) | (unsigned char)data[i];
    return n;
}

static void decimal_pair(char *out, unsigned n) {
    out[0] = (char)('0' + n / 10);
    out[1] = (char)('0' + n % 10);
}

bool buffer_timestamp(Buffer *b, const char *data, int len) {
    if (len != 8) return false;
    uint64_t raw = read_u64(data);
    int64_t us;
    memcpy(&us, &raw, sizeof(us));
    if (us == INT64_MIN || us == INT64_MAX) return false;
    int64_t seconds = us / 1000000 + INT64_C(946684800);
    int64_t remainder = us % 1000000;
    if (remainder < 0) { seconds--; remainder += 1000000; }
    int64_t days = seconds / 86400, daytime = seconds % 86400;
    if (daytime < 0) { days--; daytime += 86400; }
    if (days < -719528 || days > 2932896) return false;
    unsigned serial = (unsigned)(days + 719528);
    unsigned year = (unsigned)((uint64_t)serial * 400 / 146097);
    unsigned begin = 365 * year + (year + 3) / 4 - (year + 99) / 100 + (year + 399) / 400;
    if (serial < begin) {
        year--;
        begin = 365 * year + (year + 3) / 4 - (year + 99) / 100 + (year + 399) / 400;
    } else {
        unsigned next = year + 1;
        unsigned end = 365 * next + (next + 3) / 4 - (next + 99) / 100 + (next + 399) / 400;
        if (serial >= end) { year = next; begin = end; }
    }
    unsigned day = serial - begin;
    bool leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    static const unsigned short starts[2][13] = {
        {0,31,59,90,120,151,181,212,243,273,304,334,365},
        {0,31,60,91,121,152,182,213,244,274,305,335,366}
    };
    unsigned month = (day * 5 + 2) / 153;
    if (month > 11) month = 11;
    while (day >= starts[leap][month + 1]) month++;
    while (day < starts[leap][month]) month--;
    char text[] = "\"0000-00-00T00:00:00.000Z\"";
    unsigned milliseconds = (unsigned)(remainder / 1000);
    decimal_pair(text + 1, year / 100);
    decimal_pair(text + 3, year % 100);
    decimal_pair(text + 6, month + 1);
    decimal_pair(text + 9, day - starts[leap][month] + 1);
    decimal_pair(text + 12, (unsigned)daytime / 3600);
    decimal_pair(text + 15, (unsigned)daytime / 60 % 60);
    decimal_pair(text + 18, (unsigned)daytime % 60);
    text[21] = (char)('0' + milliseconds / 100);
    decimal_pair(text + 22, milliseconds % 100);
    return buffer_append(b, text, sizeof(text) - 1);
}

bool buffer_post(Buffer *b, PGresult *result, int row) {
    if (!result || result->numAttributes != 5 || row < 0 || row >= result->ntups) return false;
    PGresAttValue *fields = result->tuples[row];
    for (int field = 0; field < 5; field++)
        if (fields[field].len < 0 || result->attDescs[field].format != 1) return false;
    if (fields[0].len != 8 || fields[4].len != 4) return false;
    uint64_t raw = read_u64(fields[0].value);
    int64_t id;
    memcpy(&id, &raw, sizeof(id));
    const unsigned char *likes = (const unsigned char *)fields[4].value;
    uint32_t count_raw = ((uint32_t)likes[0] << 24) | ((uint32_t)likes[1] << 16) |
                         ((uint32_t)likes[2] << 8) | likes[3];
    int32_t count;
    memcpy(&count, &count_raw, sizeof(count));
    return buffer_text(b, "{\"id\":") && buffer_integer(b, id) &&
           buffer_text(b, ",\"body\":") && buffer_json(b, fields[1].value, (size_t)fields[1].len) &&
           buffer_text(b, ",\"created_at\":") && buffer_timestamp(b, fields[2].value, fields[2].len) &&
           buffer_text(b, ",\"author\":") && buffer_json(b, fields[3].value, (size_t)fields[3].len) &&
           buffer_text(b, ",\"like_count\":") && buffer_integer(b, count) && buffer_text(b, "}");
}

void request_destroy(Request *request) {
    if (!request) return;
    free(request->body);
    free(request->username);
    buffer_free(&request->response);
    free(request);
}

void request_error(Request *request, int status, const char *message) {
    request->status = status;
    request->response.len = 0;
    if (!buffer_text(&request->response, "{\"error\":") ||
        !buffer_json(&request->response, message, strlen(message)) ||
        !buffer_text(&request->response, "}")) request->response.len = 0;
}
