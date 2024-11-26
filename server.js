const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const http = require('http');
const { Server } = require('socket.io');
require('dotenv').config();

// Routes and Middleware
const apiRoutes = require('./routes/api');
const publicRoutes = require('./routes/public');
const authenticateToken = require('./middleware/auth');

// Initialize Express app
const app = express();
const server = http.createServer(app); // Wrap Express app with HTTP server

// Initialize WebSocket server
const io = new Server(server, {
    cors: {
        origin: process.env.FRONTEND_URL || 'http://localhost:5173',
        methods: ["GET", "POST"],
        allowedHeaders: ["Content-Type", "Authorization"],
        credentials: true,
    },
});

// Middleware
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
    credentials: true,
}));
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(morgan('dev'));
app.use(helmet({
    contentSecurityPolicy: process.env.NODE_ENV === 'production',
}));

// Public Routes - no authentication needed
app.use('/public', publicRoutes);

// Protected Routes - require authentication
app.use('/api', authenticateToken, apiRoutes);

// WebSocket connection setup
io.on('connection', (socket) => {
    console.log('A client connected:', socket.id);

    // Handle custom events
    socket.on('message', (data) => {
        console.log('Message received:', data);
        // Example: Broadcast to all connected clients
        io.emit('message', { sender: socket.id, data });
    });

    // Handle disconnection
    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
    });
});

// Global 404 error handling
app.use((req, res) => {
    res.status(404).json({ error: "Resource not found" });
});

// Global error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(err.status || 500).json({ error: err.message || 'Internal Server Error' });
});

// Start the server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

module.exports = io;
