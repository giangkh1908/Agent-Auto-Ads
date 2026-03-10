const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middlewares
app.use(cors());
app.use(express.json());

// API kiểm tra
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'UP',
    service: 'Auth Service',
    timestamp: new Date().toISOString()
  });
});

// Route mặc định
app.get('/', (req, res) => {
  res.send('Chào mừng bạn đến với Auth Service (Node.js)');
});

// Chạy server
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log(`🚀 Service đang chạy tại: http://localhost:${PORT}`);
});