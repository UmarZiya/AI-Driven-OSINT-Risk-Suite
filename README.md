# AI-Driven OSINT Risk Suite

An AI-powered digital footprint analysis platform that integrates passive reconnaissance, machine learning risk classification, and real-time monitoring to provide comprehensive security insights.

## Features

- **Breach Detection** — checks email against LeakCheck, EmailRep, and PwnedPasswords
- **Domain Analysis** — WHOIS lookup and full DNS enumeration
- **Network Exposure** — Shodan integration for open ports and vulnerability detection
- **Social Media Footprint** — username presence check across 20+ platforms
- **NLP Threat Detection** — pattern-based threat signal analysis
- **ML Risk Scoring** — weighted risk score across all modules
- **User Authentication** — JWT-based register/login
- **Scan History** — all scans saved to MongoDB and viewable anytime

---

## Project Structure

```
AI-Driven OSINT Risk Suite/
├── frontend/           # React + Vite + TypeScript + Tailwind CSS
├── osint-api-free/     # Node.js + Express + MongoDB (main backend)
└── README.md
```

---

## Prerequisites

Make sure you have these installed before starting:

- [Node.js](https://nodejs.org/) v18 or higher
- [Git](https://git-scm.com/)
- A free [MongoDB Atlas](https://www.mongodb.com/atlas) account

---

## Step 1 — Clone the Repository

```bash
git clone https://github.com/<your-username>/<your-repo-name>.git
cd "AI-Driven OSINT Risk Suite"
```

---

## Step 2 — MongoDB Atlas Setup

1. Go to [cloud.mongodb.com](https://cloud.mongodb.com) and sign in
2. Create a free cluster (M0 — Free Tier)
3. Click **Connect** → **Drivers** → copy the connection string
4. It looks like: `mongodb+srv://<username>:<password>@cluster0.xxxxx.mongodb.net/`
5. Replace `<username>` and `<password>` with your Atlas credentials
6. Add `/osint_risk_suite` at the end as the database name

Your final URI should look like:
```
mongodb+srv://john:mypassword@cluster0.abc123.mongodb.net/osint_risk_suite
```

Also make sure your IP is whitelisted:
- Atlas Dashboard → **Network Access** → **Add IP Address** → **Allow Access from Anywhere**

---

## Step 3 — Backend Setup (osint-api-free)

```bash
# Go to the backend folder
cd osint-api-free

# Install dependencies
npm install

# Create your .env file from the example
copy .env.example .env        # Windows
# cp .env.example .env        # Mac/Linux
```

Open `.env` and fill in your values:

```env
PORT=5000
NODE_ENV=development
CLIENT_URL=http://localhost:5173

MONGO_URI=mongodb+srv://<username>:<password>@cluster0.xxxxx.mongodb.net/osint_risk_suite

JWT_SECRET=any_long_random_string_here
JWT_EXPIRES_IN=7d

# Optional free API keys — system works without them
SHODAN_API_KEY=
RAPIDAPI_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=
```

Start the backend:

```bash
npm run dev
```

You should see:
```
✅  MongoDB connected
🚀  OSINT Risk Suite API running on http://localhost:5000
```

Verify it works: open `http://localhost:5000/api/health` in your browser — you should see:
```json
{ "status": "ok", "dbStatus": "connected" }
```

---

## Step 4 — Frontend Setup

Open a **new terminal** (keep the backend running):

```bash
# Go to the frontend folder
cd frontend

# Install dependencies
npm install
```

Create the frontend `.env` file:

```bash
# Windows
copy NUL .env

# Mac/Linux
touch .env
```

Add this line to `frontend/.env`:

```env
VITE_API_URL=http://localhost:5000/api
```

Start the frontend:

```bash
npm run dev
```

Frontend will run on: `http://localhost:5173`

---

## Step 5 — Running Both Together

You need **two terminals open at the same time**:

**Terminal 1 — Backend:**
```bash
cd osint-api-free
npm run dev
```

**Terminal 2 — Frontend:**
```bash
cd frontend
npm run dev
```

Then open `http://localhost:5173` in your browser.

---

## First Time Use

1. Open `http://localhost:5173`
2. Click **Register** and create an account
3. Log in with your credentials
4. Click **New Scan**
5. Enter any combination of:
   - Email address (breach check)
   - Domain name e.g. `example.com` (WHOIS + DNS)
   - Username e.g. `johndoe` (social media footprint)
   - IP address e.g. `8.8.8.8` (network exposure)
6. Click **Start Deep Scan** and wait ~20–30 seconds
7. View the full report with risk score breakdown

---

## What Works Without API Keys

| Module | Method | API Key Required |
|---|---|---|
| Port scanning | Node.js built-in `net` | No |
| DNS enumeration | Node.js built-in `dns` | No |
| WHOIS lookup | `whois-json` library | No |
| Social footprint | HTTP status checks | No |
| NLP threat detection | Pattern matching | No |
| EmailRep.io breach check | Free (1000 req/day) | No |
| LeakCheck.io breach check | Free public endpoint | No |
| PwnedPasswords | k-Anonymity API | No |
| Shodan host lookup | Free account | Optional |
| BreachDirectory | RapidAPI free tier | Optional |

---

## Optional Free API Keys

These improve results but are not required:

| Service | Register At | Free Tier |
|---|---|---|
| Shodan | https://account.shodan.io | 100 queries/month |
| RapidAPI (BreachDirectory) | https://rapidapi.com | 50 lookups/day |
| Censys | https://accounts.censys.io/register | 250 queries/month |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React, TypeScript, Vite, Tailwind CSS |
| UI Components | shadcn/ui |
| Charts | Recharts |
| Backend | Node.js, Express.js |
| Database | MongoDB Atlas (Mongoose) |
| Authentication | JWT (jsonwebtoken + bcryptjs) |
| Security | Helmet, CORS, Rate Limiting |

---

## Common Issues

**MongoDB connection fails**
- Check your `MONGO_URI` in `.env` is correct
- Make sure your IP is whitelisted in Atlas Network Access

**Frontend shows "Scan failed"**
- Make sure the backend is running on port 5000
- Check `VITE_API_URL=http://localhost:5000/api` is in `frontend/.env`

**"Route not found" on `http://localhost:5000/`**
- This is normal — there is no root route. Use `http://localhost:5000/api/health` to verify

**Port 5000 already in use**
- Change `PORT=5001` in `osint-api-free/.env` and update `VITE_API_URL=http://localhost:5001/api` in `frontend/.env`
