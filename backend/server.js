const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const connectDB = require('./config/db');

dotenv.config();
connectDB();

const app = express();

app.use(cors({ origin: process.env.CLIENT_URL }));
app.use(express.json());

// Health check
app.get('/api/health', (req, res) => res.json({ status: 'OK' }));

// TODO: Add routes
// app.use('/api/auth', require('./routes/auth'));
// app.use('/api/scans', require('./routes/scans'));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
