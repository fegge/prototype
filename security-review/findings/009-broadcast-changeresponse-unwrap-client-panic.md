# Finding 009 — Malicious broadcast frame panics the (wasm) client via `ChangeResponse::try_from(...).unwrap()`

- **Severity:** Medium (server-triggered, repeatable client crash / DoS)
- **Component:** `sdk/src/websocket_transport.rs`
- **Status:** Confirmed by code inspection

## Description

The WebSocket broadcast handler converts the proto `ChangeResponse` with an
unchecked `.unwrap()`:

```rust
// sdk/src/websocket_transport.rs:454-473
match (b.change_entry, b.change_response) {
    (Some(ce_proto), Some(cr_proto)) => {
        let entry = ChangelogEntry::try_from(ce_proto).unwrap();   // safe: Infallible
        let cr    = ChangeResponse::try_from(cr_proto).unwrap();   // <-- fallible, panics
        ...
    }
    _ => { log_debug!("... missing required fields ..."); }        // graceful for MISSING
}
```

`ChangeResponse::try_from` is fallible: `decode_root` (`backend/src/proto/mod.rs:438-442`)
returns `Err` when `old_root`/`new_root` is not exactly 32 bytes. The author handled the
*missing-field* case gracefully (the `_ =>` arm) but not the *present-but-invalid* case.
This runs inside the wasm `onmessage` closure, so a panic traps the WebAssembly module —
a persistent client crash, not a recoverable error.

## Exploit / failure scenario

1. A malicious (or buggy) server sends any client in the target Space a `Broadcast` frame
   whose `change_response.new_root` (or `old_root`) is present but not 32 bytes long.
2. `ChangeResponse::try_from` returns `Err`; `.unwrap()` panics; the wasm instance traps.
3. The client is dead and stays dead — reconnecting and re-subscribing invites the same
   frame again. An unauthenticated/positional broadcast (the server chooses recipients)
   makes this a one-frame, repeatable denial of service against any chosen client,
   contributing to the insider/DoS surface the design aims to resist.

## Recommended fix

- Replace the `.unwrap()` with the same graceful drop-and-log already used for the
  missing-field arm: `match ChangeResponse::try_from(cr_proto) { Ok(cr) => {...}, Err(e)
  => { log_debug!("bad broadcast ChangeResponse: {e}"); } }`.
- Audit the codebase for other `try_from(...).unwrap()` / `expect()` on server-supplied
  proto/postcard data on the client receive path and convert them to error handling.
