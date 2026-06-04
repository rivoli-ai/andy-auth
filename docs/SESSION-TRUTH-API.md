# Session-Truth API & Revocation Signal (SM.2.1)

Tracks: rivoli-ai/conductor#2003 (feature #1976, epic #1975).

## Why this exists — the #1861 root cause

Before this change a native client (Conductor) could not distinguish:

- a **transient** 5xx / proxy blip on the auth path (the correct response is **retry**), from
- a **genuine** session revocation or invalid token (the correct response is **sign out**).

Both collapsed into the same client-visible failure, so a momentary hiccup on
launch signed the user out ("all-red on launch", conductor#1861). SM.2.1 makes
the backend emit cleanly-separated, machine-readable signals so the client's
SessionState reflector (Conductor SM.5) reflects backend truth instead of
guessing from a timeout heuristic.

## Authoritative channel

andy-auth has **no NATS / event bus**. The revocation signal is therefore
**HTTP-pull**, not an event:

- `GET /auth/session` is the **authoritative reconciliation endpoint** — the
  client polls it on launch (and on demand) to reconcile its durable
  "I think I'm signed in" marker against backend truth.
- **410 Gone** on this protected call is the explicit revocation *push* a client
  observes the moment it next touches the endpoint.

If/when andy-auth gains an event bus, an `auth.session.revoked` event can be
added as an additive optimization; until then `GET /auth/session` + 410 is the
contract.

## `GET /auth/session`

Bearer-authenticated (`Authorization: Bearer <access_token>`, OpenIddict
validation scheme). Resolves the session truth for the token's `sub` (and the
`session_id` claim when present).

| Outcome | Status | Body | Meaning | Client action |
|---|---|---|---|---|
| Live session | `200` | `{ "authenticated": true, "subject": "...", "sessionId": "...", "expiresAt": "...", "revoked": false }` | The session is active. | stay signed in |
| Revoked session | `410` | `{ "reason": "session_revoked", "description": "..." }` | The session was explicitly revoked (admin force-logout, account delete, /signout revoke-all, concurrent-limit, inactivity). **Permanent.** | **sign out** |
| Invalid / deleted-account token | `401` | `{ "reason": "invalid_token", "description": "..." }` (+ `WWW-Authenticate: Bearer error="invalid_token"`) | Token is bound to an account that no longer exists or may no longer sign in. **Permanent.** | **sign out** |
| No active session | `200` | `{ "authenticated": false, "revoked": false }` | Token valid but no live/revoked session (expired or none). A clean "not signed in" — **never a 500.** | sign out / re-auth |
| Transient backend failure | `503` | `{ "reason": "temporarily_unavailable", "description": "..." }` (+ `Retry-After: 5`) | A dependency the auth service relies on is momentarily unavailable. **Transient.** | **retry** (honor `Retry-After`) |

`SessionTruthDto` also carries `revokedAt` (the revocation watermark) so a client
can reconcile a stale status read against a newer revocation: the higher
`revokedAt` wins.

## Error taxonomy → client action

The single decision table the client keys off:

| Code | Status | Class | Client action |
|---|---|---|---|
| `temporarily_unavailable` | `503` | **transient** | retry (honor `Retry-After`) |
| `invalid_token` | `401` | **permanent** | sign out |
| `session_revoked` | `410` | **permanent** | sign out |

Invariant (the #1861 conflation guard): **a transient failure NEVER surfaces as
`401`**. If `GET /auth/session` cannot resolve truth because of an
upstream/dependency error, it returns `503 temporarily_unavailable`, not `401`
and not a generic `500`. Verified by
`SessionApiControllerTests.Transient503_DoesNotCollapseTo401`.

## Revocation sources

Any path that flips `UserSession.IsRevoked` is observable through `GET
/auth/session` as `410` / `revoked:true`:

- user-initiated `/signout` revoke-all (`SessionService.RevokeAllSessionsAsync`),
- admin force-logout / account delete (`AdminController`, sets `DeletedAt` → 401),
- concurrent-session-limit eviction, inactivity timeout, manual single-session revoke.

## Downstream (Conductor SM.5 — not in this story)

Conductor reads `GET /auth/session` + observes 410; it never decides revocation
client-side (reflect-not-orchestrate). 503/circuit classify as *transient*;
401/410 classify as *sustained*. This ungates conductor SM.5.2.

## Tests

- `SessionServiceTests` — `ResolveSessionTruthAsync` active / revoked / expired /
  none, live-wins-over-revoked-sibling, explicit-session-id precedence, latest
  revocation watermark.
- `SessionApiControllerTests` — 200 / 410 / 401 (deleted, unknown, cannot-sign-in)
  / 200-not-authenticated / **503-does-not-collapse-to-401**.
