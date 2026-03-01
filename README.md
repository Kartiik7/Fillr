# Fillr

Fillr is a privacy-conscious placement-form assistant made of three parts:

1. A hardened Express API that stores structured candidate profiles, issues JWTs, and manages revocable Chrome Extension keys.
2. A static client (vanilla HTML/CSS/JS) for onboarding, authentication, and profile management.
3. A Manifest V3 Chrome Extension that securely autofills campus placement and recruitment forms (including Google Forms) using the saved profile.

---

## Live Links
- **Web Dashboard**: [https://fillr.kartikpatel.tech](https://fillr.kartikpatel.tech)
- **Chrome Extension**: [Fillr - Placement Form Autofill](https://chromewebstore.google.com/detail/fillr-%E2%80%93-placement-form-au/cicemomehhbojaaemfldindpdgpfllmi)

---

## Feature Highlights
- **Multi-channel authentication**: Email/password, Google OAuth, and extension secret-key exchange, all sharing a unified JWT strategy.
- **Security-first API**: Helmet, strict CORS, IP-based rate limiting, NoSQL injection sanitization, encrypted secrets, and compliance-oriented profile endpoints.
- **Revocable extension keys**: Users can generate, rotate, revoke, and audit up to five active extension keys tied to devices.
- **Adaptive autofill engine**: Content script understands Google Forms widgets, standard HTML fields, and learns site-specific mappings over time.
- **Privacy tooling**: GDPR-ready data export, right-to-erasure workflows, async password reset and email verification flows.
- **Extension isolation**: Tokens never touch page context; background service worker proxies all API traffic and keeps credentials in chrome.storage.

---

## Tech Stack
- **Backend**: Node.js, Express 5, Mongoose, JWT, Joi, Resend API
- **Database**: MongoDB (SRV / Atlas / self-hosted)
- **Frontend**: Vanilla HTML/CSS/JS served statically (deployable to Netlify/Vercel)
- **Browser Extension**: Chrome Manifest V3 (background service worker + content/popup scripts)

---

## Folder Structure
```
.
├── client/        # Public-facing site (landing, auth, dashboard) + fetch helpers
├── extension/     # Chrome extension source (MV3 manifest, popup, background, content)
├── server/        # Express API + Mongo models, controllers, middleware, routes
├── .github/       # (Optional) workflows / issue templates
└── fillr-extension-v1.0.0-beta.zip, package.zip  # Release artifacts
```

### Key Directories
- `client/`: Static pages (`index.html`, `dashboard.html`, etc.), shared `api.js`, and `env.js` for API base configuration.
- `server/`: `src/app.js` wires middleware, rate limiting, static serving, and routers. Controllers in `src/controllers/` contain all business logic.
- `extension/`: `background.js` is the secure API proxy, `content.js` handles detection/autofill, `popup.js` drives the UI, and `manifest.json` declares permissions.

---

## Getting Started

### Prerequisites
- Node.js 18+ and npm
- MongoDB cluster / URI
- A Google Cloud project with OAuth Client ID (Web)
- Resend account (or any SMTP equivalent) for transactional email
- Chrome 121+ for extension testing

### 1. Clone the repo
```bash
git clone https://github.com/Kartiik7/Fillr.git
cd Fillr
```

### 2. Configure the API (`server/`)
1. Create `server/.env` (see **Environment Variables** below).
2. Install dependencies and start the API:
   ```bash
   cd server
   npm install
   npm run dev   # or npm start for production
   ```
   The server defaults to `http://localhost:5000`.

### 3. Configure the web client (`client/`)
1. Edit `client/env.js` so `API_URL` points at your Express instance (e.g. `http://localhost:5000/api`).
2. Serve the folder locally (optional) using any static server:
   ```bash
   npx serve .
   ```
   or deploy to a static host (Netlify, Vercel, GitHub Pages).

### 4. Load the Chrome Extension (`extension/`)
1. Update `extension/env.js` with your backend origin (no `/api`).
2. Visit `chrome://extensions`, enable **Developer mode**, click **Load unpacked**, and select the `extension/` folder.
3. Generate an extension secret key from the Fillr dashboard (Profile → Extension Keys) and paste it into the popup to establish a session.

---

## Environment Variables
Create `server/.env` with the following keys:

| Variable | Required | Description |
| --- | --- | --- |
| `NODE_ENV` | No (default `development`) | `development` or `production`. Controls logging and error verbosity. |
| `PORT` | No (default `5000`) | HTTP port for Express. |
| `MONGO_URI` | **Yes** | MongoDB connection string. |
| `JWT_SECRET` | **Yes** | 32+ character secret for signing access tokens. Startup aborts if too short. |
| `GOOGLE_CLIENT_ID` | **Yes** | Google OAuth client ID (must match `client/env.js`). |
| `FRONTEND_URL` | **Yes** | Public origin hosting the static client (used for CORS + password/verification links). |
| `CORS_ORIGINS` | No | Comma-separated extra origins allowed to hit the API. |
| `EXTENSION_ID` | No | Chrome extension ID to lock CORS to a published build (recommended in production). |
| `RESEND_API_KEY` | Yes (prod) | Enables password reset + verification email delivery. Optional in dev (logs links). |
| `RESEND_FROM` | Yes (prod) | Verified sender, e.g. `Fillr <noreply@fillr.app>`. |

Additional optional flags:
- `RATE_LIMIT_*` values rely on defaults but can be overridden by editing the route-level limiters.
- `CORS_ORIGINS` should list staging domains if multiple dashboards exist.

Chrome extension configuration (`extension/env.js`):
```js
var ENV = Object.freeze({
  API_URL: 'http://localhost:5000'
});
```
Client configuration (`client/env.js`):
```js
const ENV = Object.freeze({
  API_URL: 'http://localhost:5000/api',
  GOOGLE_CLIENT_ID: '<same-as-server>'
});
```

---

## Usage Examples

### REST API
Authenticate and manage profile data via the Express API (replace host with yours):

```bash
# Register (email/password)
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "student@example.com",
    "password": "StrongPass1",
    "termsAccepted": true
  }'

# Login and capture JWT
token=$(curl -s -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"student@example.com","password":"StrongPass1"}' | jq -r '.accessToken')

# Read profile
token="$token" curl -H "Authorization: Bearer $token" \
  http://localhost:5000/api/profile

# Generate an extension key (requires password confirmation)
curl -X POST http://localhost:5000/api/keys/generate \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d '{"password":"StrongPass1","deviceName":"My Laptop"}'
```

Other helpful endpoints:
- `POST /api/auth/google` – Google credential exchange (token verified server-side).
- `POST /api/auth/forgot-password` & `POST /api/auth/reset-password` – secure password reset flow.
- `GET /api/user/me` – GDPR Art. 15 data export.
- `DELETE /api/user/delete` – GDPR Art. 17 erasure (password required).
- `GET /health` – readiness probe (reports DB state).

### Chrome Extension Workflow
1. Log in on the dashboard, complete your profile, and visit **Extension Keys**.
2. Click **Generate Key**, confirm with your password, and copy the one-time secret.
3. In the Chrome extension popup, paste the key and click **Connect**. The background worker exchanges it for a JWT and stores both securely.
4. Navigate to a Google Form or standard HTML form and press **Scan Page** to preview mappings. Medium-confidence matches show up in the "Needs confirmation" list.
5. Press **Autofill Page** to push high-confidence data immediately and step through confirmations for the rest. The extension highlights each target field for review.
6. If you revoke/rotate keys on the server, the extension automatically clears invalidated secrets and prompts you to reconnect.

---

## Contribution Guidelines
1. **Fork & branch**: Create feature branches from `master` (`git checkout -b feat/awesome-thing`).
2. **Environment parity**: Keep `client/env.js`, `extension/env.js`, and `server/.env` aligned so Google OAuth IDs and API domains stay in sync.
3. **Code style**: Follow existing conventions (CommonJS on server, inline documentation explaining security posture). Prefer small, well-commented commits.
4. **Testing**: Manually exercise at least the affected routes/features (auth flows, rate-limited endpoints, extension actions) and document results in PR notes.
5. **Security posture**: Never commit secrets. If you touch auth, rate limiting, or cryptography, describe the threat model changes in the PR.
6. **PR checklist**:
   - Lint/format locally (if tooling exists).
   - Add/update documentation and UI copy.
   - Reference related issues and describe verification steps.

---

## License
This project is released under the **ISC License** (see `server/package.json`). Add a `LICENSE` file if distributing binaries or forks.
