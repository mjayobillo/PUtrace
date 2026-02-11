# PUtrace (Node.js + Supabase)


## Stack
- Backend: Express (Node.js)
- Database: Supabase Postgres
- Templating: EJS
- Session auth: express-session + bcryptjs
- QR generation: qrcode (stored as data URL in DB)

## Features
- Sign up, login, logout
- Register high-value items
- Generate unique QR code per item
- Download/print QR label
- Public found page from scanned QR
- Finder report submission form
- Owner inbox + resolve workflow

## Project Structure
- `server.js` - main app and routes
- `views/` - EJS templates
- `static/styles.css` - UI styles
- `db/schema.sql` - Supabase SQL schema
- `Procfile` - deploy command

## Environment Variables
Create `.env`:

```env
PORT=5000
BASE_URL=http://localhost:5000
SESSION_SECRET=your-strong-secret
SUPABASE_URL=https://YOUR_PROJECT.supabase.co
SUPABASE_SERVICE_ROLE_KEY=YOUR_SERVICE_ROLE_KEY
```

## Setup
```bash
npm install
npm run dev
```

## Supabase Setup
1. Open Supabase SQL editor.
2. Run `db/schema.sql`.
3. Start the app.

## Deploy (Render)
- Build command: `npm install`
- Start command: `node server.js`
- Add all env vars in Render dashboard.

## Pilot with 10 students
1. Create 10 student accounts.
2. Each student registers at least one valuable item.
3. Print and attach QR to item.
4. Simulate lost/found flow by scanning QR.
5. Measure recovery response rate and turnaround time.
