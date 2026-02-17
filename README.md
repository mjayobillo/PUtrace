# PUtrace

**QR-based campus lost-item recovery system** built with Node.js, Express, and Supabase.

Students register their valuables, print unique QR labels, and attach them to items. When someone finds a lost item, they scan the QR code and submit a report — the owner is notified instantly.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Runtime | Node.js ≥ 18 |
| Framework | Express 4 |
| Database | Supabase (Postgres) |
| Templating | EJS |
| Authentication | express-session + bcryptjs |
| QR Generation | qrcode (stored as data-URL in DB) |
| Image Upload | Multer (memory storage, 5 MB limit) |
| Image Processing | Sharp (resize to 800 px, JPEG @ 75 %) |
| File Storage | Supabase Storage (`item-images` bucket) |

## Features

- **Auth** — sign up, login, logout with hashed passwords
- **Item Registration** — name, description, category, optional photo upload
- **QR Codes** — auto-generated per item; download as PNG
- **Found Page** — public page shown when a QR code is scanned
- **Finder Reports** — finders submit name, email, location hint, and message
- **Lost Board** — public listing of all items marked as "lost," with sighting reports
- **Dashboard** — search, filter by category/status, view open reports, manage items
- **Item Status** — toggle between *active*, *lost*, and *recovered*
- **Report Resolution** — mark finder reports as resolved
- **Account Management** — update display name, change password
- **Item Deletion** — remove items and associated reports

### Item Categories

Electronics · ID / Cards · Clothing · Bags · Bottles · Books · Accessories · Keys · Other

## Project Structure

```
server.js            Main Express app and all routes
views/               EJS templates
  home.ejs           Landing page
  signup.ejs         Registration form
  login.ejs          Login form
  dashboard.ejs      Owner dashboard (items + reports)
  found.ejs          Public page shown after QR scan
  lost.ejs           Public lost-item board
  account.ejs        Profile & password settings
  not_found.ejs      404 page
  partials_header.ejs  Shared header partial
  partials_footer.ejs  Shared footer partial
static/styles.css    Stylesheet
db/schema.sql        Supabase SQL schema (users, items, finder_reports)
Procfile             Render / Heroku start command
.env                 Environment variables (not committed)
```

## Routes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | — | Landing page |
| GET | `/signup` | — | Sign-up form |
| POST | `/signup` | — | Create account |
| GET | `/login` | — | Login form |
| POST | `/login` | — | Authenticate |
| GET | `/logout` | — | Destroy session |
| GET | `/dashboard` | Yes | List items & reports (search/filter) |
| POST | `/dashboard` | Yes | Register new item (with optional image) |
| GET | `/lost` | — | Public lost-item board |
| POST | `/lost/:id/sighting` | — | Submit sighting report |
| GET | `/found/:token` | — | Public found page (QR scan target) |
| POST | `/found/:token` | — | Submit finder report |
| POST | `/report/:id/resolve` | Yes | Mark report as resolved |
| GET | `/account` | Yes | Profile page |
| POST | `/account` | Yes | Update display name |
| POST | `/account/password` | Yes | Change password |
| POST | `/item/:id/status` | Yes | Toggle item status |
| POST | `/item/:id/delete` | Yes | Delete item + reports |
| GET | `/download/:token` | Yes | Download QR code PNG |

## Database Schema

Three tables managed via `db/schema.sql`:

- **users** — `id` (uuid), `full_name`, `email` (unique), `password_hash`, `created_at`
- **items** — `id` (uuid), `user_id` (FK), `item_name`, `item_description`, `category`, `item_status`, `image_url`, `token` (unique), `qr_data_url`, `created_at`
- **finder_reports** — `id` (bigserial), `item_id` (FK), `finder_name`, `finder_email`, `location_hint`, `message`, `status`, `created_at`

## Environment Variables

Create a `.env` file in the project root:

```env
PORT=5000
BASE_URL=http://localhost:5000
SESSION_SECRET=your-strong-secret
SUPABASE_URL=https://YOUR_PROJECT.supabase.co
SUPABASE_SERVICE_ROLE_KEY=YOUR_SERVICE_ROLE_KEY
```

## Getting Started

```bash
# Install dependencies
npm install

# Run the SQL schema in your Supabase project's SQL editor
# (paste the contents of db/schema.sql)

# Create an "item-images" bucket in Supabase Storage (public access)

# Start the dev server
npm run dev
```

The app will be available at `http://localhost:5000`.

## Deployment (Render)

| Setting | Value |
|---------|-------|
| Build command | `npm install` |
| Start command | `node server.js` |
| Environment | Add all `.env` variables in the Render dashboard |

## Pilot Testing (10 Students)

1. Create 10 student accounts.
2. Each student registers at least one valuable item.
3. Print and attach QR labels to items.
4. Simulate the lost/found flow by scanning a QR code.
5. Measure recovery response rate and turnaround time.
