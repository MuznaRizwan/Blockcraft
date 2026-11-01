# Blockcraft server

One Node.js process serves the game page and its API. Data is stored in a SQLite file.
No npm packages are needed: it uses Node's built-in `node:sqlite` (Node 22.13 or newer).

## Run locally

    npm start            # http://localhost:3000
    npm test             # 18 API tests, each run against a temporary database

## Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `BLOCKCRAFT_KEY` | Yes in production | Secret used to encrypt authenticator keys at rest. Keep it safe: changing it makes existing sign-ins fail. |
| `DATA_DIR` | Recommended | Folder for `blockcraft.db` and the key file. Put it on a persistent disk. Default `./data`. |
| `COOKIE_SECURE` | Yes behind HTTPS | Set to `1` so the session cookie is sent only over HTTPS. Also turns on HSTS. |
| `PORT` | No | Defaults to 3000. Hosts usually set this for you. |

## Endpoints

| Method and path | Purpose |
|---|---|
| `POST /api/signup` | Validate details and hold the sign-up. Returns the authenticator key. |
| `POST /api/signup/confirm` | Check the first 6-digit code and create the account. Starts a session. |
| `POST /api/login` | Check the password (with lockout). Returns a pending sign-in. |
| `POST /api/login/confirm` | Check the 6-digit code and start a session. |
| `POST /api/logout`, `GET /api/me` | End or read the current session. |
| `GET /api/profile` | Play time, blocks placed and broken, best round, last 5 finished games. |
| `POST /api/stats` | Add to play time and block counts (batched by the page). |
| `POST /api/games` | Record a finished round or game. |
| `GET /api/worlds`, `GET/PUT/DELETE /api/worlds/:id` | List, load, save and delete your worlds (up to 8). |

## Security in place

- Passwords are hashed with PBKDF2-SHA256 (210,000 rounds) and a random salt per user. The plain password is never stored or logged.
- Every sign-up and sign-in needs a 6-digit code from an authenticator app (RFC 6238). A code cannot be used twice.
- Authenticator keys are encrypted with AES-256-GCM before they go into the database.
- Five wrong passwords or codes lock the account, with the wait doubling up to 15 minutes.
- Sessions use random tokens. Only a SHA-256 hash of each token is stored. The cookie is HttpOnly and SameSite=Strict, and expires after 12 hours.
- Every input is checked on the server, with the same rules as the page. Worlds are checked block by block, and the bottom layer can't be broken.
- Every SQL statement uses parameters. User text is never built into queries.
- Writes must be JSON from the same origin. Request bodies are limited to 300 KB.
- Sign-in responses do not reveal whether an email is registered.
- Security headers include a Content-Security-Policy, nosniff, frame denial and no-referrer.

## Deploying (for example Render, Railway or Fly.io)

1. Create a web service from this folder. Build command: none. Start command: `npm start`.
2. Use Node 22.13 or newer. Set `NODE_VERSION` to `22` if the host asks.
3. Add a persistent disk or volume, mounted at `/data`, and set `DATA_DIR=/data`. SQLite needs a disk that survives restarts. Without one, every deploy wipes all accounts.
4. Set `BLOCKCRAFT_KEY` to a long random string, and `COOKIE_SECURE=1`.
5. Open the service URL. The game and its sign-in are served from the same address.

## Limits to know about

- **Lost authenticator means lost account.** There are no backup codes or email recovery yet.
- SQLite runs on one server instance. Scaling out would need a shared database such as Postgres or Supabase.
- Rate limits are kept in memory, so they reset on restart.
- Play stats are reported by the browser, so a player could inflate their own numbers. That is fine for stats, but not for competitive scores.
- The page still uses `'unsafe-inline'` for scripts because it is one HTML file. Moving the script into a separate file would remove that.
