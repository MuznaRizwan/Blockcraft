# Blockcraft on Vercel

The game page is a static file (`public/index.html`). The server part is one serverless function
(`api/[...path].js`) that answers every `/api/*` request. Data lives in a Turso (libSQL) database,
because Vercel functions have no disk that survives between requests.

## 1. Create the database (Turso)

    curl -sSfL https://get.tur.so/install.sh | bash      # or: brew install tursodatabase/tap/turso
    turso auth signup
    turso db create blockcraft
    turso db show blockcraft --url          # copy this: libsql://blockcraft-yourname.turso.io
    turso db tokens create blockcraft       # copy this token

The function creates its own tables the first time it runs. You do not need to run any SQL.

## 2. Set three environment variables in Vercel

Project, then Settings, then Environment Variables (tick Production, Preview and Development):

| Name | Value |
|---|---|
| `TURSO_DATABASE_URL` | the `libsql://...` address from step 1 |
| `TURSO_AUTH_TOKEN` | the token from step 1 |
| `BLOCKCRAFT_KEY` | a long random secret: `openssl rand -base64 48`. Keep a copy. Changing it later makes every existing sign-in fail, because it encrypts the authenticator keys. |

Optional: `ALLOWED_ORIGINS` (comma-separated) if a different website needs to call this API.

## 3. Deploy

Push this folder to GitHub and import it in Vercel. Framework preset: **Other**. No build command and no output
directory are needed: Vercel serves `public/` as the site and `api/` as the functions.
After adding or changing environment variables, redeploy, since they only apply to new deployments.

To check it: open `https://YOUR-SITE.vercel.app/api/healthz` (should show `{"ok":true}`), then open the site and sign up.
If something fails, open the project in Vercel, then Logs. A missing setting is named in the log.

**Pick a region near your database.** In Vercel, Settings, Functions, set the region to match your Turso location.
A far-away function makes every request slower, because each request makes several database calls.

## Run the tests

    npm install
    npm test        # 21 API tests, against a temporary local database file

## What changed from the Express version

- No Express and no CORS package. Page and API share one address, so cross-site access is not needed and stays blocked.
- Every database call is awaited (the libSQL client is async), and multi-step changes use all-or-nothing batches.
- The sign-up and login rate limits are stored in the database, because each request may run on a different instance.
- The authenticator-key secret comes from `BLOCKCRAFT_KEY`, not a file, and `public/index.html` is served by Vercel itself.
- Password hashing runs asynchronously so it does not block the function.

## Limits to know about

- Lost authenticator means lost account: there are no backup codes or email recovery yet.
- Free Vercel plans cap function time (10 seconds by default). Sign-up and login take well under one second.
- Play stats are reported by the browser, so they are fine for fun but not for competitive scores.
- The page still allows inline scripts because it is one HTML file.
