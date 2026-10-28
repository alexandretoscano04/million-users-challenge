# C / epoll feed server

C17 with GCC 13 and a custom Linux epoll HTTP server for Ubuntu 24.04.

Dependencies: **libpq 18.6**, **yyjson 0.10.0**, **libdeflate 1.23**, and system **OpenSSL 3**. Downloads are version-pinned and SHA256-verified; libpq and libdeflate are statically linked.

## Build and run

From this directory:

```sh
sudo bash install.sh
bash build.sh
DATABASE_URL='postgres://feed:password@db-host:5432/feed' \
JWT_SECRET='YOUR_SECRET' HOST=0.0.0.0 PORT=80 EXTRA_PORT=81 \
bash start.sh
```

The server stays in the foreground and serves both ports. Worker count follows available CPU and cgroup quota.

## Implementation

- Compact 24-byte idle connection slots and bounded worker-owned buffers/queues.
- Exact prepared SQL, batched database flushes, and commit-confirmed write responses.
- Fresh HS256 verification and expiry checks on each authenticated request.
- Direct binary-row JSON output, bounded SIMD escaping, UTC millisecond timestamps, and negotiated gzip.

Result decoding uses the internal layout of the same pinned libpq source used to build the static driver. No responses, query results, or authentication results are cached. No host settings or schema are changed.

Verified: 42 official checks and nine extended checks under ASan/UBSan. Build artifacts are excluded by `.gitignore`.
