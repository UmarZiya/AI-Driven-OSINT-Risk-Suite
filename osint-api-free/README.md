# OSINT Risk Suite — API (100% Free Version)

> **For:** Riyaz — Capstone Level 2, OSINT Digital Footprint Risk Scorer  
> **Stack:** Node.js · Express · MongoDB

---

## ✅ What Works With Zero API Keys (No Registration Needed)

| Feature | How it works | Key needed? |
|---|---|---|
| Port scanning | Node.js built-in `net` module — direct TCP | ❌ None |
| DNS enumeration | Node.js built-in `dns` module | ❌ None |
| WHOIS lookup | `whois-json` npm package | ❌ None |
| EXIF extraction | `exifr` npm package | ❌ None |
| Social footprint | HTTP presence checks | ❌ None |
| NLP threat detection | Pattern matching | ❌ None |
| EmailRep.io breach | Free, 1000 req/day | ❌ None |
| LeakCheck.io breach | Free public endpoint | ❌ None |
| PwnedPasswords | k-Anonymity, always free | ❌ None |

---

## 🔑 Free Optional Keys (Improve Results, Still Free)

Getting these takes under 5 minutes each:

### 1. Shodan Free Account
Adds service banners and historical data on top of your port scan.
- Go to: **https://account.shodan.io** → Register → My Account → API Key
- Free tier: 100 host lookups/month, no credit card
- Add to `.env`: `SHODAN_API_KEY=your_key`

### 2. Censys Free Account
Second source for open port data.
- Go to: **https://accounts.censys.io/register**
- Free tier: 250 queries/month
- Add to `.env`: `CENSYS_API_ID=` and `CENSYS_API_SECRET=`

### 3. RapidAPI Free Account (for BreachDirectory)
50 breach lookups/day free.
- Go to: **https://rapidapi.com** → Register (free)
- Then subscribe free: **https://rapidapi.com/rohan-patra/api/breachdirectory**
- Add to `.env`: `RAPIDAPI_KEY=your_key`

---

## Quick Start

```bash
cd backend
npm install
cp .env.example .env
# Fill in MONGO_URI at minimum. Everything else is optional.
npm run dev
```

Server runs on `http://localhost:5000`

---

## API Endpoints

Base URL: `/api/osint`

### 🔍 Full Scan — Main Endpoint
```
POST /api/osint/scan/full
```
```json
{
  "email":    "target@example.com",
  "domain":   "example.com",
  "username": "johndoe",
  "ip":       "8.8.8.8"
}
```
At least one field required. Returns `finalScore (0-100)`, `riskLevel`, full `breakdown`, `recommendations`.

---

### 📧 Breach Detection
```
POST /api/osint/breach/email     → { email }
POST /api/osint/breach/bulk      → { emails: [] }  max 5
```
Sources: LeakCheck.io + EmailRep.io + PwnedPasswords (all free, no key needed)  
With `RAPIDAPI_KEY`: also checks BreachDirectory

---

### 🌐 Domain Analysis
```
POST /api/osint/domain/whois     → { domain }   WHOIS only
POST /api/osint/domain/dns       → { domain }   DNS records only
POST /api/osint/domain/full      → { domain }   WHOIS + DNS + risk score
```

---

### 🛡️ Network Exposure
```
POST /api/osint/network/ports    → { host }   Direct TCP port scan (NO KEY NEEDED)
POST /api/osint/network/ip       → { ip }     Port scan + Shodan/Censys if configured
POST /api/osint/network/domain   → { domain } Resolve + scan
```
The `/ports` endpoint runs with zero API keys — it directly connects to ports using Node's `net` module.  
Scans these ports: 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 2375, 3306, 3389, 4444, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017

---

### 👤 Social Media Footprint
```
POST /api/osint/social/username  → { username }
```
Checks 20 platforms: GitHub, Twitter/X, Instagram, Reddit, GitLab, Dev.to, Medium, Pastebin, Twitch, TikTok, Keybase, HackerNews, YouTube, Pinterest, Telegram, DockerHub, npm, Gravatar, About.me, LinkedIn

---

### 📷 EXIF Metadata Extraction
```
POST /api/osint/exif/extract
Content-Type: multipart/form-data
Field: file  (JPEG/PNG/TIFF/HEIC, max 20MB)
```
Extracts GPS coordinates, device info, owner name, camera serial, timestamps.

---

### 🧠 NLP Threat Detection
```
POST /api/osint/threat/analyze-text   → { text, context? }
POST /api/osint/threat/analyze-url    → { url }
```
Detects: credential leaks, hacking language, dark web refs, malware, phishing, data dumps, personal info patterns.

---

### 📊 Risk Score Calculator
```
POST /api/osint/risk-score/calculate
```
```json
{
  "target": { "email": "...", "domain": "..." },
  "subScores": { "breach": 70, "network": 45, "domain": 20, "social": 30, "threat": 10 }
}
```
Weights: breach 30% · network 25% · threat 20% · domain 10% · social 10% · exif 5%  
Levels: LOW (0–34) · MEDIUM (35–59) · HIGH (60–79) · CRITICAL (80–100)

---

## Connecting to the Frontend

The "New Scan" form in the frontend maps exactly to the full scan endpoint:

```typescript
// In your React component (frontend/src/...)
const res = await fetch(`${import.meta.env.VITE_API_URL}/osint/scan/full`, {
  method:  "POST",
  headers: { "Content-Type": "application/json" },
  body:    JSON.stringify({ email, domain, username, ip }),
});
const data = await res.json();
// data.finalScore  → feed to the score gauge on dashboard
// data.riskLevel   → "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
// data.breakdown   → individual module scores for the breakdown chart
// data.results     → detailed findings per module
```

Make sure `frontend/.env` has: `VITE_API_URL=http://localhost:5000/api`

---

## File Structure
```
backend/
├── app.js
├── package.json
├── .env.example
├── models/ScanResult.js
├── routes/
│   ├── osint.js
│   └── osint/
│       ├── scan.js         ← orchestrator — call this from the frontend
│       ├── breach.js       ← free breach detection
│       ├── domain.js       ← WHOIS + DNS
│       ├── network.js      ← port scanner + optional Shodan/Censys
│       ├── social.js       ← social footprint
│       ├── exif.js         ← EXIF metadata
│       ├── threat.js       ← NLP threat analysis
│       └── riskScore.js    ← weighted score calculator
└── services/               ← reusable logic for orchestrator
```

## Running Tests
```bash
npm test
```
All external calls are mocked — no API keys or internet needed to run tests.
