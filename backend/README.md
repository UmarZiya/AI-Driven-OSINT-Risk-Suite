# OSINT Risk Suite — Backend

This folder contains the backend setup for the AI-Driven OSINT Risk Suite.

## Tech Stack
- **Runtime:** Node.js
- **Framework:** Express.js
- **Database:** MongoDB (via Mongoose)
- **Auth:** JWT + bcryptjs

---

## Setup Instructions

### 1. Install dependencies
```bash
cd backend
npm install
```

### 2. Configure environment variables
```bash
cp .env.example .env
```
Fill in your values in `.env`:
- `MONGO_URI` — get from MongoDB Atlas (see below)
- `JWT_SECRET` — any long random string
- `CLIENT_URL` — frontend dev server URL

### 3. MongoDB Atlas Setup
1. Go to https://www.mongodb.com/atlas and create a free account
2. Create a free **M0** cluster
3. Go to **Database Access** → create a user with read/write access
4. Go to **Network Access** → allow your IP (or `0.0.0.0/0` for dev)
5. Go to your cluster → **Connect** → **Drivers** → copy the connection string
6. Paste it into `MONGO_URI` in your `.env` file, replacing `<password>`

### 4. Run the server
```bash
npm run dev   # development (with nodemon)
npm start     # production
```

---

## Database Models

### `ScanResult`
Stores all OSINT scan data. Maps directly to the frontend `ScanResult` type.

| Field | Type | Description |
|-------|------|-------------|
| `target` | Object | Email, domain, username, IP |
| `status` | String | pending / scanning / completed / failed |
| `breaches` | Array | Data breach findings |
| `whois` | Object | WHOIS/DNS data |
| `shodan` | Object | Network exposure data |
| `socialMedia` | Array | Social media profiles found |
| `exifData` | Array | Image metadata findings |
| `nlpAnalysis` | Object | NLP threat analysis results |
| `riskScore` | Object | ML risk scores by category |
| `recommendations` | Array | Security recommendations |
| `userId` | ObjectId | Reference to User (for auth) |
| `createdAt` | Date | Auto-generated timestamp |

### `User`
Stores user accounts for authentication.

| Field | Type | Description |
|-------|------|-------------|
| `name` | String | Full name |
| `email` | String | Unique email |
| `password` | String | Hashed (bcrypt) |
| `role` | String | user / admin |

---

## API Routes to Implement

```
POST   /api/auth/register     - Register new user
POST   /api/auth/login        - Login, returns JWT

GET    /api/scans             - Get all scans for logged-in user
POST   /api/scans             - Create/save a new scan result
GET    /api/scans/:id         - Get single scan by ID
DELETE /api/scans/:id         - Delete a scan

GET    /api/scans/stats       - Dashboard stats (total scans, avg risk, etc.)
```

---

## Frontend Integration Notes
- Frontend runs on `http://localhost:5173` (Vite default)
- All API calls should go to `http://localhost:5000/api`
- JWT token should be sent as `Authorization: Bearer <token>` header
- The frontend `osintEngine.ts` mock will be replaced with real API calls
