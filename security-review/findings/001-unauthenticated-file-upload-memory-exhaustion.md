# Finding 001 — Unauthenticated file upload buffers the whole body before the size check (memory-exhaustion DoS)

- **Severity:** Medium (availability / denial of service)
- **Component:** `backend/server` — HTTP file store
- **Status:** Confirmed by code inspection
- **Related:** README concedes "DoS hardening is incomplete"; this documents a concrete, unauthenticated instance.

## Description

The reference server exposes a content-addressed file store at `PUT /file/{hash}`.
The handler reads the **entire** request body into memory before any size limit is
applied:

```rust
// backend/server/src/http.rs:160-175
async fn handle_file_put(req: Request<Body>, hash: &str, file_store: Arc<FileStore>)
    -> Result<Response<Body>, Infallible>
{
    let body_bytes: Bytes = match hyper::body::to_bytes(req.into_body()).await {   // <-- whole body buffered
        Ok(bytes) => bytes,
        ...
    };
    match file_store.put(hash, &body_bytes) { ... }   // size check happens only here
}
```

The 50 MiB cap lives in `FileStore::put`, which runs **after** the body is fully
materialized:

```rust
// backend/server/src/file_store.rs:26-36
pub fn put(&self, hash: &str, data: &[u8]) -> io::Result<()> {
    if data.len() > MAX_FILE_SIZE {   // MAX_FILE_SIZE = 50 MiB, checked AFTER buffering
        return Err(io::Error::new(io::ErrorKind::InvalidData, ...));
    }
    ...
}
```

`hyper::body::to_bytes` imposes no limit of its own, and the server is built on raw
hyper with **no `tower_http::limit::RequestBodyLimit` / `Content-Length` pre-check
layer** (`handle_request` in `backend/server/src/http.rs:13` dispatches straight to
`handle_file`). So the allocation is bounded only by what the client chooses to send.

The endpoint is effectively **unauthenticated**. Reaching it requires only a
well-formed `?auth=` parameter, which is a base64url JSON `AuthContext` that the
server never verifies (`parse_auth_from_query`, `http.rs:94`; the auth-is-a-placeholder
caveat is the enabler here). `get_or_create_space` is then called with the
attacker-supplied `space_id`, so an attacker does not even need to belong to a real
Space.

## Exploit / failure scenario

1. Attacker crafts `auth = base64url({"uid":null,"space_id":<any>})`.
2. Attacker sends `PUT /file/<64 hex chars>?auth=...` with a multi-gigabyte body,
   or a chunked body with no `Content-Length` (so the server cannot even pre-reject
   on the header).
3. The server calls `to_bytes` and allocates the entire body in RAM before the
   50 MiB check rejects it.
4. A handful of concurrent such requests exhaust server memory and OOM-kill the
   process. Because all Spaces share one process (`SPACES` global map), this takes
   down every Space on the instance.

A secondary amplification: each distinct `space_id` in the `?auth=` blob triggers
`get_or_create_space`, letting an unauthenticated attacker allocate unbounded
per-Space state as well.

## Recommended fix

- Enforce a hard body-size limit **before** buffering. Either:
  - Reject on `Content-Length` when present and over the cap, and
  - Stream the body with a running byte counter (e.g. `http_body_util`/manual
    frame loop, or a `tower_http::limit::RequestBodyLimitLayer` if migrating to a
    tower stack), aborting as soon as the cap is exceeded — never call
    `to_bytes` on an unbounded body.
- Pass the cap (`MAX_FILE_SIZE`) into the read path so the limit is enforced at
  ingestion, not after.
- Gate `get_or_create_space` behind real authentication (tracked separately as the
  auth-placeholder issue) so anonymous callers cannot allocate Spaces or file
  stores.
