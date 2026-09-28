# day-journal

A journaling API built as a hexagonal (ports-and-adapters) application in Go,
with email/password and Google sign-in, JWT sessions, and a login/logout audit
trail. It is the backend for the DayJournal iOS app.

Gin, Postgres, Redis, bcrypt, JWT and Google are all *adapters* plugged into
the edges. The business rules in `internal/core` import none of them and are
tested without a single container running.

## The dependency rule

```
          driving side                                     driven side
     (things that call us)                              (things we call)

                                                   ──► EntryRepository ─┐
                                                   ──► UserRepository   ├─► Postgres
                    ┌──► EntryService ──┐          ──► SessionRepository│
  HTTP / Gin ───────┤                   ├─► CORE   ──► AuditLog ────────┘
                    └──► AuthService ───┘          ──► EntryCache ──────┐
                        (driving ports)            ──► SessionDenylist  ├─► Redis
                                                   ──► RateLimiter ─────┘
                                                   ──► TokenIssuer ────────► JWT (HS256)
                                                   ──► PasswordHasher ─────► bcrypt
                                                   ──► GoogleVerifier ─────► Google
                                                   ──► EventPublisher ─────► no-op (NATS parked)
```

Dependencies point **inwards only**. `cmd/app` is the composition root, the
one place that knows every concrete adapter. `internal/core/architecture_test.go`
fails the build if the core ever imports an adapter or a driver.

## Layout

```
cmd/app/main.go                  composition root: config, migrations, wiring, graceful shutdown
internal/
  core/                          the hexagon — no framework or driver imports
    domain/                      Entry, User, Session, AuthEvent, Mood, Day; domain errors
    port/                        driving (EntryService, AuthService) and driven interfaces
    service/                     use cases: entry.go, auth.go
  adapter/
    driving/http/                Gin: router, handlers, DTOs, bearer-token middleware, error mapping
    driven/postgres/             pgx repositories + embedded migration runner
    driven/redis/                entry cache, session denylist, rate limiter
    driven/jwt/                  access-token issuer with key rotation
    driven/crypto/               bcrypt password hasher
    driven/google/               Google ID-token verifier
    driven/nats/                 JetStream publisher (commented out until messaging is on)
  config/                        environment loading (the only os.Getenv)
migrations/                      SQL schema, embedded into the binary
```

## Running it

```bash
cp .env.example .env
make up                 # postgres, redis, nats
make run                # API on :8080 — migrates the database on boot
make test               # unit tests + architecture guard, no containers needed
make test-integration   # adds the Postgres adapter tests (needs `make up`)
```

Migrations run automatically at startup inside a Postgres advisory lock, so any
number of replicas can boot at once. Each applied version is recorded in
`schema_migrations`.

## Authentication

### Tokens

Signing in returns a **token pair**:

| Token   | Lifetime | Form | Stored on the server as |
| ------- | -------- | ---- | ----------------------- |
| Access  | 15 min   | HS256 JWT: `sub` = user id, `sid` = session id | not stored; verified by signature |
| Refresh | 30 days, sliding | `<session id>.<256-bit secret>` | SHA-256 of the secret, on the session row |

Send the access token as `Authorization: Bearer <token>`. When it expires,
exchange the refresh token at `/auth/refresh` for a new pair.

**Refresh tokens rotate on every use.** The session remembers the previous
token's hash, so if a rotated-away token is ever presented again (meaning it
leaked and someone raced the real client), the whole session is revoked and a
`refresh_token_reuse` event is audited. A made-up secret paired with a real
session id is simply rejected. Knowing a session id, which anyone holding a JWT
can read, isn't enough to log someone out.

**Logout takes effect immediately**, even though JWTs are stateless: the session
id goes onto a Redis denylist for one access-token lifetime, and every request
checks it. If Redis is unreachable, the check falls back to the session row in
Postgres, so a logged-out token never gets through because the cache is down.

### Passwords

bcrypt (cost 12 by default), 8–72 bytes. A login against an unknown email still
runs a bcrypt comparison, so response time doesn't reveal which emails have
accounts, and every failure returns the same `invalid email or password`,
including a password attempt on a Google-only account.

Attempts are rate-limited in Redis, shared across replicas: 10 per email and
50 per IP per 15 minutes for login, 20 registrations per IP. Over the limit is
`429` with `Retry-After`. If Redis is down, the limiter allows requests rather
than locking everyone out; bcrypt still makes each guess expensive.

### Google

The client obtains a Google **ID token** and posts it to `/auth/google`. The
server verifies its signature against Google's public keys, its issuer, expiry,
and that its audience is one of `GOOGLE_CLIENT_IDS`. Then:

1. A known Google account signs in.
2. Otherwise, a password account with the same email is **linked**, but only if
   Google marks the email verified. An unverified Google email can't claim
   someone else's account.
3. Otherwise, a new account is created (`201`, `"created": true`).

With `GOOGLE_CLIENT_IDS` empty, the endpoint answers `501` and everything else
keeps working.

### Audit trail

Two records, deliberately different in strength:

- **`sessions`**: one row per sign-in. `created_at` is the login time and
  `revoked_at` + `revoke_reason` are the logout time and why. These are written
  in the same statement that grants or ends access, so they can never disagree
  with what actually happened.
- **`auth_events`**: append-only: `registered`, `login`, `login_failed` (with
  the attempted email, even an unknown one), `logout`, `logout_all`,
  `refresh_token_reuse`, `google_linked`, each with IP and user agent. It has no
  foreign keys, so rows outlive the accounts they describe. Writing it is
  best-effort: an audit hiccup never fails a sign-in.

Client IPs come from the TCP connection unless `HTTP_TRUSTED_PROXIES` names the
load balancers allowed to set `X-Forwarded-For`. Without that, a client could
choose the IP that gets recorded and dodge per-IP limits.

### Deleting an account

`DELETE /api/v1/me` with `{"password": "..."}`, or for an account without a
password `{"google_id_token": "..."}` from a fresh Google sign-in (it must be
the *same* Google account). A valid token alone is not enough, so an unlocked
phone can't be used to wipe someone's journal.

| Response | Meaning |
| -------- | ------- |
| `204` | Deleted |
| `400` `field: password` | No proof of identity supplied |
| `403` `field: password` | Wrong password or wrong Google account. Deliberately **not** `401`, which clients read as "token expired, refresh or sign out" |
| `429` | Five failed confirmations in 15 minutes; the endpoint can't be used to brute-force a password |

In order: every session is revoked and denylisted, so tokens on *all* devices die
at once. Then the user row is deleted, and its entries and sessions cascade in
the same statement. Then the account's audit events are **anonymised**: the
timeline of what happened and when is kept for security, but email, IP and
user agent are blanked. The email can be registered again straight away.
Cached entries in Redis expire within their 10-minute TTL and can no longer be
read, since no token maps to the deleted user.

## API

| Method | Path | Auth | Purpose |
| ------ | ---- | ---- | ------- |
| POST   | `/api/v1/auth/register`   | —      | Create an account with email + password → token pair |
| POST   | `/api/v1/auth/login`      | —      | Sign in with email + password → token pair |
| POST   | `/api/v1/auth/google`     | —      | Sign in or register with a Google ID token |
| POST   | `/api/v1/auth/refresh`    | —      | Rotate a refresh token → new token pair |
| POST   | `/api/v1/auth/logout`     | Bearer | End this session |
| POST   | `/api/v1/auth/logout-all` | Bearer | End every session for the account |
| GET    | `/api/v1/me`              | Bearer | The signed-in user |
| PATCH  | `/api/v1/me`              | Bearer | Change display name |
| DELETE | `/api/v1/me`              | Bearer | Permanently delete the account (see below) |
| GET    | `/api/v1/me/sessions`     | Bearer | Sign-in history: login/logout times, device, IP |
| GET    | `/api/v1/me/audit-events` | Bearer | The account's authentication audit log |
| POST   | `/api/v1/entries`         | Bearer | Create an entry |
| GET    | `/api/v1/entries`         | Bearer | List: `?from=&to=&mood=&tag=&search=&limit=&offset=` |
| GET    | `/api/v1/entries/:id`     | Bearer | Fetch one (read-through Redis) |
| PATCH  | `/api/v1/entries/:id`     | Bearer | Partial update |
| DELETE | `/api/v1/entries/:id`     | Bearer | Delete |
| GET    | `/healthz`                | —      | Liveness, no dependencies touched |
| GET    | `/readyz`                 | —      | Readiness: probes Postgres and Redis |

`from`/`to` take an RFC 3339 instant or a `YYYY-MM-DD` date (a UTC day), as a
half-open range `[from, to)`. Clients that know the user's timezone should send
instants; the iOS app sends local midnight to midnight so "today" is the user's
today. Moods are `happy`, `neutral`, `sad`, `angry`, `tired`. Any number of
entries may share a day.

Auth and account responses are `Cache-Control: no-store`. Errors are
`{"error": "...", "field": "...", "trace_id": "..."}`, and the trace id matches
the server log line.

```bash
# register, keep the access token, write an entry
TOKEN=$(curl -s -X POST localhost:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"correct horse","display_name":"Ada"}' \
  | jq -r .tokens.access_token)

curl -X POST localhost:8080/api/v1/entries \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"occurred_at":"2026-09-28T09:00:00Z","title":"Shipped it","mood":"happy"}'
```

## Configuration

Everything is environment variables; see `.env.example`. The ones that matter
for production:

| Variable | Default | Notes |
| -------- | ------- | ----- |
| `APP_ENV` | `development` | Anything else refuses to start with the dev JWT secret |
| `JWT_SECRET` | public dev value | **Required** outside development; ≥ 32 bytes (`openssl rand -base64 48`) |
| `JWT_PREVIOUS_SECRETS` | — | Old secrets, still verified during a rotation |
| `ACCESS_TOKEN_TTL` / `REFRESH_TOKEN_TTL` | `15m` / `720h` | |
| `GOOGLE_CLIENT_IDS` | — | Comma-separated; empty disables Google |
| `HTTP_TRUSTED_PROXIES` | — | Load balancer CIDRs allowed to set `X-Forwarded-For` |
| `BCRYPT_COST` | `12` | |

**Rotating the JWT secret** without signing anyone out: move the current value
into `JWT_PREVIOUS_SECRETS`, set a new `JWT_SECRET`, deploy. After one access
token lifetime (15 min), remove the old value. Tokens carry a `kid`, so each is
checked against the key that signed it.

## Events

Each entry write builds a domain event (`entry.created|updated|deleted`). NATS is
parked for now: `service.NopPublisher` logs events at debug level. To turn
messaging on, uncomment `internal/adapter/driven/nats/publisher.go` and the
marked block in `cmd/app/main.go`. Nothing in the core changes.

## Adding a use case

1. Add the method to a driving port in `internal/core/port`.
2. Implement it in `internal/core/service` against the driven ports.
3. Add a handler in the HTTP adapter and a route in `router.go`, inside the
   `private` group if it needs a signed-in user.
4. Extend a repository adapter only if new persistence is needed.
