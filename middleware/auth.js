const jwt = require('jsonwebtoken');
const db = require('../config/db');

const queryAsync = (query, params) => {
    return new Promise((resolve, reject) => {
        db.query(query, params, (err, results) => {
            if (err) return reject(err);
            resolve(results);
        });
    });
};

const generateTokens = (userId) => {
    const newAccessToken = jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const newRefreshToken = jwt.sign({ id: userId }, process.env.JWT_REFRESH_SECRET, { expiresIn: '30d' });
    const newExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    return { newAccessToken, newRefreshToken, newExpiresAt };
};

const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const accessToken = authHeader && authHeader.split(' ')[1];

        if (!accessToken) {
            return res.status(401).json({ error: 'Access token is missing' });
        }

        try {
            const user = jwt.verify(accessToken, process.env.JWT_SECRET);
            req.user = user;
            return next();
        } catch (err) {
            if (err.name === 'TokenExpiredError') {
                const refreshToken = req.cookies?.refreshToken;
                if (!refreshToken) {
                    return res.status(400).json({ error: 'Refresh token is required' });
                }

                try {
                    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
                    const userId = decoded.id;

                    const results = await queryAsync(
                        `SELECT * FROM active_tokens 
                         WHERE user_id = ? AND refresh_token = ? AND expires_at > UTC_TIMESTAMP()`,
                        [userId, refreshToken.trim()]
                    );

                    if (results.length === 0) {
                        return res.status(403).json({ error: 'Invalid or expired refresh token' });
                    }

                    // Generate and set new tokens
                    const { newAccessToken, newRefreshToken, newExpiresAt } = generateTokens(userId);
                    await queryAsync(
                        `UPDATE active_tokens 
                         SET refresh_token = ?, expires_at = ? 
                         WHERE user_id = ?`,
                        [newRefreshToken, newExpiresAt, userId]
                    );

                    res.cookie('refreshToken', newRefreshToken, {
                        httpOnly: true,
                        secure: process.env.NODE_ENV === 'production',
                        sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
                        maxAge: 30 * 24 * 60 * 60 * 1000,
                        path: '/',
                    });

                    req.user = { id: userId };
                    req.newAccessToken = newAccessToken;
                    return next();
                } catch (refreshErr) {
                    console.error('Error refreshing token:', refreshErr);
                    return res.status(403).json({ error: 'Invalid or expired refresh token' });
                }
            }

            return res.status(403).json({ error: 'Token is invalid' });
        }
    } catch (err) {
        console.error('Unexpected error in authenticateToken middleware:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
};

module.exports = authenticateToken;
