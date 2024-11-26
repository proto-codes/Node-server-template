const db = require('../config/db');
const bcrypt = require('bcryptjs');

// Helper function to query the database
const queryAsync = (query, params) => {
    return new Promise((resolve, reject) => {
        db.query(query, params, (err, results) => {
            if (err) return reject(err);
            resolve(results);
        });
    });
};

// Get User Details
const getUserDetails = async (req, res) => {
    if (!req.user || !req.user.id) {
        return res.status(401).json({ error: 'User not authenticated' });
    }

    try {
        // Fetch user details along with profile_pics from the profile table
        const query = `
            SELECT 
                u.id, 
                u.name, 
                u.email, 
                p.profile_pics 
            FROM 
                users u
            LEFT JOIN 
                profile p 
            ON 
                u.id = p.user_id 
            WHERE 
                u.id = ?
        `;

        const results = await queryAsync(query, [req.user.id]);

        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Convert the profile_pics (if exists) to a base64 string for front-end use
        const user = {
            ...results[0],
            profile_pics: results[0].profile_pics 
                ? Buffer.from(results[0].profile_pics).toString('base64') 
                : null,
        };

        res.json(user);
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ error: 'Server error' });
    }
};

// Change Password
const changePassword = async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    if (!req.user || !req.user.id) {
        return res.status(401).json({ error: 'User not authenticated' });
    }

    // Function to check password strength
    const checkPasswordStrength = (password) => {
        const minLength = 8;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSpecialChars = /[!@#$%^&*(),.?":{}|<>]/.test(password);

        if (password.length < minLength || !hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChars) {
            return 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character and be at least 8 characters long';
        }
        return null; // No issues found, password is strong enough
    };

    // Check password strength
    // const passwordStrengthError = checkPasswordStrength(newPassword);
    // if (passwordStrengthError) {
    //     return res.status(400).json({ error: passwordStrengthError });
    // }

    try {
        // Retrieve the user's current password hash from the database
        const results = await queryAsync('SELECT password FROM users WHERE id = ?', [req.user.id]);
        
        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const currentHashedPassword = results[0].password;

        // Check if the new password is the same as the old password
        const isSamePassword = await bcrypt.compare(newPassword, currentHashedPassword);
        if (isSamePassword) {
            return res.status(400).json({ error: 'New password cannot be the same as the old password' });
        }

        const isMatch = await bcrypt.compare(currentPassword, currentHashedPassword);
        if (!isMatch) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await queryAsync('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, req.user.id]);

        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).json({ error: 'Server error' });
    }
};

// Update Notification Preferences
const updateNotificationPreferences = async (req, res) => {
    const { emailNotifications, smsNotifications } = req.body;

    if (!req.user || !req.user.id) {
        return res.status(401).json({ error: 'User not authenticated' });
    }

    // Validate that at least one preference is selected
    if (!emailNotifications && !smsNotifications) {
        return res.status(400).json({ error: 'At least one notification preference must be selected.' });
    }

    try {
        await queryAsync('UPDATE users SET email_notifications = ?, sms_notifications = ? WHERE id = ?', 
            [emailNotifications, smsNotifications, req.user.id]);

        res.json({ message: 'Notification preferences updated successfully' });
    } catch (error) {
        console.error('Error updating notification preferences:', error);
        res.status(500).json({ error: 'Server error' });
    }
};

// Fetch Notification Preferences for the logged-in user
const fetchNotificationPreferences = async (req, res) => {
    if (!req.user || !req.user.id) {
        return res.status(401).json({ error: 'User not authenticated' });
    }

    try {
        const [preferences] = await queryAsync('SELECT email_notifications, sms_notifications FROM users WHERE id = ?', [req.user.id]);

        if (!preferences) {
            return res.status(404).json({ message: 'Notification preferences not found' });
        }

        res.json(preferences);
    } catch (error) {
        console.error('Error fetching notification preferences:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Delete Account
const deleteAccount = async (req, res) => {
    if (!req.user || !req.user.id) {
        return res.status(401).json({ error: 'User not authenticated' });
    }

    try {
        await queryAsync('DELETE FROM users WHERE id = ?', [req.user.id]);
        res.json({ message: 'Account deleted successfully' });
    } catch (error) {
        console.error('Error deleting account:', error);
        res.status(500).json({ error: 'Server error' });
    }
};

module.exports = { 
    getUserDetails, 
    changePassword, 
    updateNotificationPreferences, 
    deleteAccount,
    fetchNotificationPreferences 
};