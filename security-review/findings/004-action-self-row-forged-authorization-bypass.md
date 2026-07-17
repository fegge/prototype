# Finding 004 — Action `self.*` context is attacker-forged for Delete/Update legs (assertion bypass + ACL-free cascade to arbitrary rows)

- **Severity:** High (within the prototype's own threat model) — breaks
  cryptographically-enforced access control and "verifiable history." The client
  verifier is the sole authorization boundary, and the **fast-forward zkVM guest runs
  the identical `changelog_core` code**, so even fast-forwarded clients accept the
  forged operation.
- **Component:** `ffproof/changelog_core/src/ops/action_op.rs` (with
  `ops/delete_op.rs`, `ops/update_op.rs`)
- **Status:** Confirmed by code inspection

## Description

When the verifier dispatches an `OpType::Action` entry, it builds the `self.*`
assertion/cascade context from the **values of the primary leg's kv pairs in the signed
entry**:

```rust
// ffproof/changelog_core/src/ops/action_op.rs:145-147
let primary_kvs = &per_leg_kvs[0];
let self_row = self_row_from_leg_kvs(primary_kvs);
evaluate_action_asserts(&action_name, &action.asserts, &self_row, entry.uid, reader)?;
```

```rust
// action_op.rs:269-292 (abridged)
fn self_row_from_leg_kvs(leg_kvs: &[KvData]) -> BTreeMap<String, i64> {
    ...
    for kv in leg_kvs {
        let Ok(ParsedKey::Column { column, row_id, .. }) = parse_key(&kv.key) else { continue };
        ...
        if let Ok(value) = bytes_to_value(&kv.value) {      // <-- value comes from the signed entry
            if let Some(i) = value.as_i64() { out.insert(column, i); }
        }
    }
    // `id` alone is taken from the authenticated column KEY, not the value:
    if let (Some(id), false) = (common_row_id, row_id_inconsistent) { out.insert("id".into(), id); }
    out
}
```

This is only sound when the primary leg is an **Insert** — there `InsertOp` validates
the kv values against schema and write-ACL, so `self.*` equals the authorized row. For a
**Delete** primary leg it is unsound: `DeleteOp::extract_and_validate`
(`ops/delete_op.rs:15-95`) determines what to delete from the column **keys** only and
reads the *stored* values from the tree for its own ACL — it **never inspects or
constrains `kv.value`** and never requires it to be empty. So a malicious member can put
**arbitrary values** in a delete leg's kvs, and `self_row_from_leg_kvs` reads them
verbatim (only `self.id` is authenticated, since it derives from the key). For an
**Update** primary leg the values are the attacker's *proposed* new values, constrained
only if a column happens to appear in the write-ACL or `cols` allowlist.

That forged `self_row` then feeds two authorization-critical consumers:

1. **Action assertions** (`evaluate_action_asserts` → `resolve_self_value`,
   `action_op.rs:294-414`), evaluated before any leg runs. `self.<col>` resolves
   straight out of the forged map.
2. **Cascade-delete FK selection** (`dispatch_cascade_delete`, `action_op.rs:421-473`):
   ```rust
   let fk_value = self_row.get(where_self_column).copied()...;      // action_op.rs:430
   let row_ids = read_indexed_row_ids(table, where_column, fk_value, ...)?;  // :441
   // ... deletes every returned row with NO per-row ACL (:451-469)
   ```
   Crucially, the cross-table cascade path has **no guard that `where_self_column ==
   "id"`** (that guard exists only in the same-table partition path). So the FK selector
   can be a forged non-`id` `self.<col>`.

## Exploit / failure scenario

Both require the app schema to declare an action of the relevant shape. Attackers cannot
define actions (schema is admin-controlled), but both shapes are ordinary, documented
usage (`docs/actions.md` presents `assert` as an authorization mechanism and
`cascade_delete where="row.x == self.y"` with a generic `self.y`).

**Vector A — assertion authorization bypass.** Consider an action whose authorization is
expressed as an assertion over a non-`id` column, with a delete primary leg, e.g.:

```kdl
action "delete_post" {
    assert "self.author_id == auth.user_id"
    delete
}
```

with no *redundant* `allow delete "auth.user_id == row.author_id"` rule on the table (the
action author reasonably treats the assertion as the gate). Attacker (uid 99) deletes
victim's post (row key names the victim's row) and stuffs the `author_id` kv with
`value = 99`. `self.author_id` resolves to 99, `99 == 99` passes, the delete proceeds.
The "only the author may delete" invariant is broken. (A table that *also* declares a
per-row `allow delete` over the stored value is saved for this vector, because `DeleteOp`
re-checks it against the tree — but the cascade vector below is not.)

**Vector B — ACL-free cascade to arbitrary rows (privilege escalation).** Consider:

```kdl
table "folders" {
    rules {
        allow delete "auth.user_id == row.owner"
        only_via_actions delete "delete_folder"
        action "delete_folder" {
            delete
            cascade_delete table="documents" where="row.folder_id == self.folder_id"
        }
    }
}
```

The attacker deletes a folder they legitimately own (primary-leg ACL passes against the
stored `owner`), but sets the forged `self.folder_id` in the primary leg's kvs to a
**victim's** folder id. `dispatch_cascade_delete` then reads the `documents` secondary
index for that victim folder id and deletes **every** document in it — with no per-row
ACL. Net: "authorized to delete my own folder" escalates to "delete any user's
documents." Because cascade legs explicitly skip per-row ACL, no redundant rule mitigates
this.

In both cases the forged operation carries a valid signature (the attacker signs their
own entry), passes the verifier, mutates the authenticated data commitment, and — since
the FF guest runs the same `changelog_core` verifier — is equally accepted by clients
that fast-forward over it. `exists(...)` gates inside assertions are weakened the same
way, since `self.<col>` inside an `exists` body resolves from the same forged map.

## Recommended fix

- **For non-Insert primary legs, source `self.<col>` from authenticated stored state**,
  not from the signed entry's kv values: read the primary row's columns from the tree
  (as `DeleteOp` already does for its ACL) and build `self_row` from those. Insert legs
  can continue to use the entry values because `InsertOp` validates them.
- **Restrict cross-table `CascadeDelete.where_self_column`** to `"id"` (or to a stored,
  ACL-covered value), mirroring the same-table path's existing guard, so the cascade
  selector can never be an unauthenticated attacker value.
- Optionally, reject non-empty `kv.value` on delete-leg kvs so the forged values cannot
  be smuggled in at all.
- Add regression tests: a delete-primary action gated only by `assert "self.<col> ==
  auth.user_id"` must be denied when the attacker forges `self.<col>`; a non-`id`
  cross-table cascade must be rejected at schema load or dispatch.
