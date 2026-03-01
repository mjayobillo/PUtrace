# PUTrace

QR-based campus lost-and-found recovery system built with Node.js, Express, EJS, and Supabase. Students register valuables, attach printed QR labels, and receive finder reports when someone scans the code. Includes a messaging system between owners and finders, a Lost Board, and a Found Items Board.

## Tech Stack

- **Runtime**: Node.js >= 18
- **Framework**: Express 4
- **Templates**: EJS
- **Database**: Supabase (Postgres)
- **Auth**: `express-session` + `bcryptjs` (custom, no Supabase Auth)
- **QR codes**: `qrcode` (stored as data URL in DB)
- **Image uploads**: Multer (memory storage, 5 MB max) + Sharp (resize to 800×800, JPEG 75%)
- **File storage**: Supabase Storage bucket `item-images`
- **Email**: SendGrid HTTP API (password reset emails)

## Core Features

- Sign up / login / logout (school email restricted to `@panpacificu.edu.ph`)
- Register items with optional image upload and auto-generated QR code
- Download QR code as PNG
- QR scan page for finders to submit reports (no login required)
- Lost Board — items marked lost, with sighting reports (login required)
- Found Items Board — post and claim found items (login required)
- Owner ↔ finder messaging per report thread
- Dashboard with item search, category/status filtering, and open report counts
- Item status management (`active`, `lost`, `recovered`)
- Resolve finder reports
- Account page — update name, change password, send password reset link
- Password reset via email (SendGrid)

## Item Status Flow

- `active` — normal tracked item, visible in owner dashboard
- `lost` — appears on the Lost Board so others can report sightings
- `recovered` — item recovered, stays visible in dashboard

Notes:
- New items are created as `active`.
- The Lost Board only shows items marked `lost`.
- Owners can change status from the dashboard.

## Project Structure

```text
server.js
views/
  _header.ejs
  _footer.ejs
  _dashboard_item_card.ejs
  _dashboard_report_row.ejs
  home.ejs
  signup.ejs
  login.ejs
  forgot_password.ejs
  reset_password.ejs
  dashboard.ejs
  new_item.ejs
  lost.ejs
  found_qr.ejs
  found_items.ejs
  messages.ejs
  message_thread.ejs
  account.ejs
  not_found.ejs
static/
  styles.css
db/
  schema.sql
Procfile
```

## Main Routes

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/` | Home page |
| GET/POST | `/signup` | Register account |
| GET/POST | `/login` | Login |
| GET | `/logout` | Logout |
| GET/POST | `/forgot-password` | Request password reset email |
| GET/POST | `/reset-password/:token` | Reset password via token |
| GET | `/dashboard` | Owner dashboard |
| GET/POST | `/items/new` | Register new item |
| POST | `/item/:id/status` | Update item status |
| POST | `/item/:id/delete` | Delete item |
| GET | `/download/:token` | Download QR code as PNG |
| GET | `/lost` | Lost Board |
| POST | `/lost/:id/sighting` | Submit sighting report |
| GET | `/found/:token` | QR scan page |
| POST | `/found/:token` | Submit finder report from QR |
| GET/POST | `/found-items` | Found Items Board |
| POST | `/found-items/:id/claim` | Claim a found item |
| POST | `/report/:id/resolve` | Resolve a finder report |
| GET | `/messages` | Messages list |
| GET/POST | `/messages/:reportId` | Message thread |
| GET/POST | `/account` | Account settings |
| POST | `/account/password` | Change password |
| POST | `/account/password/reset-link` | Send reset link from account page |

## Database Tables

Defined in `db/schema.sql`:

- `users`
- `items`
- `finder_reports`
- `report_messages`
- `found_posts`
- `password_reset_tokens`

## Environment Variables

```env
PORT=5000
BASE_URL=http://localhost:5000
SESSION_SECRET=your-strong-secret
SUPABASE_URL=https://YOUR_PROJECT.supabase.co
SUPABASE_SERVICE_ROLE_KEY=YOUR_SERVICE_ROLE_KEY
SENDGRID_API_KEY=your-sendgrid-api-key
SENDGRID_FROM_EMAIL=your-verified-sender@gmail.com
```

`SENDGRID_API_KEY` and `SENDGRID_FROM_EMAIL` are optional — if not set, password reset links are logged to the console instead.

## Local Setup

```bash
npm install
npm run dev
```

Before running:
- Execute `db/schema.sql` in the Supabase SQL editor
- Create a public storage bucket named `item-images` in Supabase Storage

App runs at `http://localhost:5000`

## Deploy (Render)

- **Build command**: `npm install`
- **Start command**: `node server.js`
- Set all environment variables in Render → Environment
