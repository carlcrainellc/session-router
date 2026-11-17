# Exit lease admission

`SessionEndpoint::validate` (src/handlers/session.cpp) runs before any inbound map/accept
(`session_post_init`) and again in `map_session_v4` / `map_session_v6`. Upstream never called it,
which is why `auth-type=whitelist` used to be ignored.

Checks, in order:

1. Explicit open: `auth-type` none **and** no static tokens **and** an empty whitelist.
2. Static token hit.
3. Whitelist hit.
4. A **signed v2 admission** in the store file `SR_EXIT_LEASE_ADMISSIONS`, signed by the Ed25519
   issuer key `SR_EXIT_LEASE_ISSUER_PUBKEY` (64 hex characters).

A v2 record:

| Field | Rule |
|-------|------|
| `kind` | `exit_lease_admission` |
| `scope` | `exit_lease` |
| `v` | `2` (unsigned v1 is refused) |
| `lock_seller_id` | exact match to this exit's own client `.sesh` |
| `client_sesh` | exact match to the inbound `remote` |
| `exp` | unix seconds, `exp > now` |
| `tid` | optional string, covered by the signature |
| `sig` | hex Ed25519 over `srnet-exit-admission/v2\n{seller}\n{client}\n{exp}\n{tid}` |

The check fails closed: if either env var is unset, or the record is malformed, forged, for the
wrong seller or client, or expired, nobody is admitted by step 4.

The seller-side issuer is `contrib/exit-lease/admission.py`. To check a record exactly the way the
exit would, run `exit-lease-verify`.
