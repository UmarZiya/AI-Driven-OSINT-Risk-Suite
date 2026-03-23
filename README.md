# AI-Driven OSINT Risk Suite

An AI-powered digital footprint analysis platform that integrates passive reconnaissance, machine learning risk classification, and real-time monitoring to provide comprehensive security insights.

## Project Structure

```
AI-Driven OSINT Risk Suite/
├── frontend/       # React + Vite + Tailwind CSS
├── backend/        # Node.js + Express + MongoDB
└── README.md
```

---

## Running the Frontend

```bash
# Step 1: Go to frontend folder
cd frontend

# Step 2: Install dependencies
npm install

# Step 3: Start the development server
npm run dev
```

Frontend will run on: `http://localhost:5173`

---

## Running the Backend

```bash
# Step 1: Go to backend folder
cd backend

# Step 2: Install dependencies
npm install

# Step 3: Create your .env file
copy .env.example .env

# Step 4: Open .env and add your MongoDB Atlas connection string
# MONGO_URI=mongodb+srv://<username>:<password>@cluster0.xxxxx.mongodb.net/osint_risk_suite

# Step 5: Start the backend server
npm run dev
```

Backend will run on: `http://localhost:5000`

---

## Running Both Together

Open **two terminals** and run simultaneously:

**Terminal 1 — Frontend:**
```bash
cd frontend
npm run dev
```

**Terminal 2 — Backend:**
```bash
cd backend
npm run dev
```

---

## Environment Variables

### Frontend (`frontend/.env`)
```
VITE_API_URL=http://localhost:5000/api
```

### Backend (`backend/.env`)
```
MONGO_URI=mongodb+srv://<username>:<password>@cluster0.xxxxx.mongodb.net/osint_risk_suite
JWT_SECRET=your_super_secret_jwt_key_here
JWT_EXPIRES_IN=7d
PORT=5000
NODE_ENV=development
CLIENT_URL=http://localhost:5173
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React, TypeScript, Vite, Tailwind CSS |
| Backend | Node.js, Express.js |
| Database | MongoDB Atlas (Mongoose) |
| Charts | Recharts |
| UI Components | shadcn/ui |
