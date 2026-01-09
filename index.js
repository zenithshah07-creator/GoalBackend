require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const db = require('./db');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const fs = require('fs-extra');
const { parseRoadmapPdf } = require('./pdfService');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware
app.use(cors({
    origin: [process.env.VITE_CLIENT_URL, 'https://taracker.vercel.app', 'http://localhost:5173', 'http://localhost:5174', 'http://localhost:5175', 'http://localhost:5176', 'http://localhost:5177'].filter(Boolean),
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Root route - API Health Check
app.get('/', (req, res) => {
    res.json({ status: 'GoalTracker Pro API is Operational', timestamp: new Date().toISOString() });
});

// CONFIGURATION ENDPOINT (To solve credential setup ease)
app.post('/api/config/setup', async (req, res) => {
    const { google_client_id, email_user, email_pass } = req.body;

    if (!google_client_id || !email_user || !email_pass) {
        return res.status(400).json({ error: 'All configuration fields are required' });
    }

    try {
        const envPath = path.join(__dirname, '.env');
        const clientEnvPath = path.join(__dirname, '..', 'client', '.env');

        const envContent = `EMAIL_USER=${email_user}
EMAIL_PASS=${email_pass}
JWT_SECRET=${process.env.JWT_SECRET}
GOOGLE_CLIENT_ID=${google_client_id}
`;

        const clientEnvContent = `VITE_GOOGLE_CLIENT_ID=${google_client_id}
VITE_API_URL=http://localhost:3000
`;

        await fs.writeFile(envPath, envContent);
        await fs.writeFile(clientEnvPath, clientEnvContent);

        // Update current process env for immediate effect (some basics)
        process.env.EMAIL_USER = email_user;
        process.env.EMAIL_PASS = email_pass;
        process.env.GOOGLE_CLIENT_ID = google_client_id;

        // Re-init transporter
        transporter.set('auth', {
            user: email_user,
            pass: email_pass
        });

        res.json({ success: true, message: 'System configuration updated successfully. Please restart your servers to fully activate.' });
    } catch (error) {
        console.error('Config Error:', error);
        res.status(500).json({ error: 'Failed to update configuration files.' });
    }
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
        req.user = user;
        next();
    });
};

// Upload setup
const upload = multer({ dest: 'uploads/' });

// Routes

// AUTH ROUTES
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = `INSERT INTO users (username, password) VALUES (?, ?)`;
        db.run(sql, [username, hashedPassword], function (err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(400).json({ error: 'Username already exists' });
                }
                return res.status(500).json({ error: err.message });
            }
            res.json({ success: true, message: 'User registered successfully' });
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    const sql = `SELECT * FROM users WHERE username = ?`;

    db.get(sql, [username], async (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(401).json({ error: 'Invalid username or password' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Invalid username or password' });

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { id: user.id, username: user.username } });
    });
});

app.post('/api/auth/google', async (req, res) => {
    const { idToken } = req.body;
    if (!idToken) return res.status(400).json({ error: 'ID Token required' });

    try {
        const ticket = await client.verifyIdToken({
            idToken,
            audience: GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        const { sub: google_id, email, name } = payload;

        // Check if user exists with this google_id
        db.get('SELECT * FROM users WHERE google_id = ?', [google_id], async (err, user) => {
            if (err) return res.status(500).json({ error: err.message });

            if (user) {
                // Existing Google User - Login
                const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
                return res.json({ token, user: { id: user.id, username: user.username } });
            } else {
                // New User - Check if username (email) exists
                db.get('SELECT * FROM users WHERE username = ?', [email], (err, existingUser) => {
                    if (existingUser) {
                        // Link Google to existing account
                        db.run('UPDATE users SET google_id = ? WHERE id = ?', [google_id, existingUser.id], (err) => {
                            if (err) return res.status(500).json({ error: err.message });
                            const token = jwt.sign({ id: existingUser.id, username: existingUser.username }, JWT_SECRET, { expiresIn: '24h' });
                            return res.json({ token, user: { id: existingUser.id, username: existingUser.username } });
                        });
                    } else {
                        // Create new user
                        db.run('INSERT INTO users (username, google_id) VALUES (?, ?)', [email, google_id], function (err) {
                            if (err) return res.status(500).json({ error: err.message });
                            const token = jwt.sign({ id: this.lastID, username: email }, JWT_SECRET, { expiresIn: '24h' });
                            res.json({ token, user: { id: this.lastID, username: email } });
                        });
                    }
                });
            }
        });
    } catch (error) {
        res.status(401).json({ error: 'Invalid Google Token' });
    }
});

app.post('/api/auth/demo', (req, res) => {
    const guestUsername = 'Guest_Operator';
    const sql = `SELECT * FROM users WHERE username = ?`;

    db.get(sql, [guestUsername], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });

        if (user) {
            const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
            return res.json({ token, user: { id: user.id, username: user.username } });
        } else {
            db.run('INSERT INTO users (username) VALUES (?)', [guestUsername], function (err) {
                if (err) return res.status(500).json({ error: err.message });
                const token = jwt.sign({ id: this.lastID, username: guestUsername }, JWT_SECRET, { expiresIn: '24h' });
                res.json({ token, user: { id: this.lastID, username: guestUsername } });
            });
        }
    });
});

// OTP & Password Reset Endpoints

app.post('/api/auth/send-otp', (req, res) => {
    const { identifier, type } = req.body; // type: 'email' or 'phone'
    if (!identifier) return res.status(400).json({ error: 'Identifier required' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = new Date(Date.now() + 10 * 60 * 1000); // 10 mins

    const saveAndSend = (userId, targetIdentifier, targetType) => {
        const query = targetType === 'phone'
            ? 'UPDATE users SET otp_code = ?, otp_expiry = ? WHERE phone = ?'
            : 'UPDATE users SET otp_code = ?, otp_expiry = ? WHERE username = ?';

        db.run(query, [otp, expiry, targetIdentifier], async (err) => {
            if (err) return res.status(500).json({ error: 'Failed to save OTP' });

            console.log(`[AUTH] Generated OTP ${otp} for ${targetIdentifier}`);

            if (targetType === 'email' || targetIdentifier.includes('@')) {
                const mailOptions = {
                    from: `"GoalTracker Pro" <${process.env.EMAIL_USER}>`,
                    to: targetIdentifier,
                    subject: '🔒 Your Mission Verification Code',
                    html: `
                    <div style="font-family: sans-serif; padding: 20px; border: 1px solid #e2e8f0; border-radius: 12px;">
                        <h2 style="color: #4f46e5;">Verification Required</h2>
                        <p style="color: #64748b;">Your one-time passcode for GoalTracker Mission Control is:</p>
                        <h1 style="font-size: 32px; letter-spacing: 5px; color: #1e293b; background: #f1f5f9; padding: 15px; text-align: center; border-radius: 8px;">${otp}</h1>
                        <p style="color: #94a3b8; font-size: 12px;">This code will expire in 10 minutes. Do not share this code with anyone.</p>
                    </div>
                `
                };

                try {
                    await transporter.sendMail(mailOptions);
                    res.json({ success: true, message: 'OTP sent to your email' });
                } catch (error) {
                    console.error('Email Error:', error);
                    res.status(500).json({ error: 'Failed to send email. Ensure SMTP is configured.' });
                }
            } else {
                console.log(`[AUTH] SMS OTP ${otp} to Phone: ${targetIdentifier}`);
                res.json({ success: true, message: `OTP sent to ${targetIdentifier} (Check server console for code)` });
            }
        });
    };

    // Check if user exists
    const checkQuery = type === 'phone'
        ? 'SELECT id FROM users WHERE phone = ?'
        : 'SELECT id FROM users WHERE username = ?';

    db.get(checkQuery, [identifier], (err, user) => {
        if (!user) {
            // Auto-create user for first-time OTP login
            const insertQuery = type === 'phone'
                ? 'INSERT INTO users (phone, otp_code, otp_expiry) VALUES (?, ?, ?)'
                : 'INSERT INTO users (username, otp_code, otp_expiry) VALUES (?, ?, ?)';

            db.run(insertQuery, [identifier, otp, expiry], function (err) {
                if (err) return res.status(500).json({ error: 'Failed to create user during OTP' });
                saveAndSend(this.lastID, identifier, type);
            });
        } else {
            saveAndSend(user.id, identifier, type);
        }
    });
});

app.post('/api/auth/verify-otp', (req, res) => {
    const { identifier, otp, type } = req.body;
    const query = type === 'phone'
        ? 'SELECT * FROM users WHERE phone = ? AND otp_code = ?'
        : 'SELECT * FROM users WHERE username = ? AND otp_code = ?';

    db.get(query, [identifier, otp], (err, user) => {
        if (err || !user) return res.status(401).json({ error: 'Invalid or expired OTP' });

        if (new Date(user.otp_expiry) < new Date()) {
            return res.status(401).json({ error: 'OTP expired' });
        }

        // Clear OTP after use
        db.run('UPDATE users SET otp_code = NULL, otp_expiry = NULL WHERE id = ?', [user.id]);

        const token = jwt.sign({ id: user.id, username: user.username || user.phone }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { id: user.id, username: user.username || user.phone } });
    });
});

app.post('/api/auth/forgot-password', async (req, res) => {
    const { identifier } = req.body;
    const token = crypto.randomBytes(20).toString('hex');
    const expiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    db.run('UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE username = ? OR phone = ?',
        [token, expiry, identifier, identifier], async function (err) {
            if (this.changes === 0) return res.status(404).json({ error: 'User not found' });

            console.log(`[AUTH] Password Reset Token: ${token} for ${identifier}`);

            if (identifier.includes('@')) {
                const mailOptions = {
                    from: `"GoalTracker Pro" <${process.env.EMAIL_USER}>`,
                    to: identifier,
                    subject: '🔑 Password Reset Request',
                    html: `
                    <div style="font-family: sans-serif; padding: 20px; border: 1px solid #e2e8f0; border-radius: 12px;">
                        <h2 style="color: #4f46e5;">Password Recovery</h2>
                        <p style="color: #64748b;">A password reset was requested for your GoalTracker account. Use the token below to set a new passcode:</p>
                        <div style="font-family: monospace; font-size: 16px; background: #f1f5f9; padding: 15px; border-radius: 8px; word-break: break-all; color: #1e293b;">${token}</div>
                        <p style="margin-top: 20px; color: #94a3b8; font-size: 12px;">This token will expire in 1 hour. If you did not request this, please ignore this email.</p>
                    </div>
                `
                };

                try {
                    await transporter.sendMail(mailOptions);
                    res.json({ success: true, message: 'Reset token sent to your email', token });
                } catch (error) {
                    console.error('Email Error:', error);
                    res.status(500).json({ error: 'Failed to send recovery email. Ensure SMTP is configured.' });
                }
            } else {
                res.json({ success: true, message: 'Reset token generated (Check console)', token });
            }
        });
});

app.post('/api/auth/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ error: 'Token and new password required' });

    db.get('SELECT * FROM users WHERE reset_token = ?', [token], async (err, user) => {
        if (err || !user || new Date(user.reset_token_expiry) < new Date()) {
            return res.status(401).json({ error: 'Invalid or expired reset token' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        db.run('UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?',
            [hashedPassword, user.id], (err) => {
                res.json({ success: true, message: 'Password reset successful' });
            });
    });
});

// PROTECTED ROUTES (Require authenticateToken)

// GET Logs
app.get('/api/logs', authenticateToken, (req, res) => {
    const { date } = req.query;
    let sql = 'SELECT * FROM logs WHERE user_id = ?';
    const params = [req.user.id];

    if (date) {
        sql += ' WHERE date = ?';
        params.push(date);
    }

    sql += ' ORDER BY id DESC';

    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// POST Log
app.post('/api/logs', authenticateToken, (req, res) => {
    const { date, topic, hours, status, notes, events } = req.body;
    const createdAt = new Date().toISOString();
    const eventsJson = events ? JSON.stringify(events) : null;
    const sql = `INSERT INTO logs (date, topic, hours, status, notes, created_at, events, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;

    db.run(sql, [date, topic, hours, status, notes, createdAt, eventsJson, req.user.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, created_at: createdAt, ...req.body });
    });
});

// DELETE Log
app.delete('/api/logs/:id', authenticateToken, (req, res) => {
    db.run('DELETE FROM logs WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Log not found or unauthorized' });
        res.json({ success: true, changes: this.changes });
    });
});

// PATCH Log
app.patch('/api/logs/:id', authenticateToken, (req, res) => {
    const { date, topic, hours, status, notes } = req.body;
    const updates = [];
    const params = [];

    if (date !== undefined) { updates.push('date = ?'); params.push(date); }
    if (topic !== undefined) { updates.push('topic = ?'); params.push(topic); }
    if (hours !== undefined) { updates.push('hours = ?'); params.push(hours); }
    if (status !== undefined) { updates.push('status = ?'); params.push(status); }
    if (notes !== undefined) { updates.push('notes = ?'); params.push(notes); }

    if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });

    params.push(req.params.id);
    params.push(req.user.id);
    const sql = `UPDATE logs SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`;

    db.run(sql, params, function (err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Log not found or unauthorized' });
        res.json({ success: true, id: req.params.id, ...req.body });
    });
});

// GET Summary
app.get('/api/summary', authenticateToken, (req, res) => {
    const sql = `
    SELECT 
        (SELECT SUM(hours) FROM logs WHERE user_id = ?) as total_hours,
        (
            (SELECT COUNT(*) FROM logs WHERE status='completed' AND user_id = ?) + 
            (SELECT COUNT(*) FROM todos WHERE is_completed=1 AND user_id = ?)
        ) as completed_topics,
        (
            (SELECT COUNT(*) FROM logs WHERE status='pending' AND user_id = ?) + 
            (SELECT COUNT(*) FROM todos WHERE is_completed=0 AND user_id = ?)
        ) as pending_topics
    `;
    db.get(sql, [req.user.id, req.user.id, req.user.id, req.user.id, req.user.id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({
            total_hours: row.total_hours || 0,
            completed_topics: row.completed_topics || 0,
            pending_topics: row.pending_topics || 0
        });
    });
});

// GET Today's Todo Report
app.get('/api/todos/report/today', authenticateToken, (req, res) => {
    const today = new Date().toISOString().split('T')[0];

    const sql = `
    SELECT 
        (
            (SELECT COUNT(*) FROM todos WHERE date(created_at) = ? AND user_id = ?) +
            (SELECT COUNT(*) FROM logs WHERE date(created_at) = ? AND user_id = ?)
        ) as addedToday,
        (
            (SELECT COUNT(*) FROM todos WHERE date(completed_at) = ? AND user_id = ?) +
            (SELECT COUNT(*) FROM logs WHERE status = 'completed' AND date(created_at) = ? AND user_id = ?)
        ) as completedToday,
        (
            (SELECT COUNT(*) FROM todos WHERE is_completed = 0 AND user_id = ?) +
            (SELECT COUNT(*) FROM logs WHERE status = 'pending' AND user_id = ?)
        ) as pendingTotal
    `;

    db.get(sql, [today, req.user.id, today, req.user.id, today, req.user.id, today, req.user.id, req.user.id, req.user.id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(row);
    });
});

// GET Todos
app.get('/api/todos', authenticateToken, (req, res) => {
    db.all('SELECT * FROM todos WHERE user_id = ? ORDER BY id DESC', [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// POST Todo
app.post('/api/todos', authenticateToken, (req, res) => {
    const { task, details, format, section, source, priority, due_date } = req.body;
    const taskSource = source || 'manual';
    const taskPriority = priority || 'Medium';
    const createdAt = new Date().toISOString();
    db.run('INSERT INTO todos (task, details, format, section, source, created_at, priority, due_date, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [task, details, format, section, taskSource, createdAt, taskPriority, due_date, req.user.id], function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: this.lastID, task, details, format, section, is_completed: 0, source: taskSource, created_at: createdAt, priority: taskPriority, due_date });
        });
});

// DELETE Todo
app.delete('/api/todos/:id', authenticateToken, (req, res) => {
    db.run('DELETE FROM todos WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Todo not found or unauthorized' });
        res.json({ success: true });
    });
});

// UPDATE Todo (Status, Text, Details, Format)
app.patch('/api/todos/:id', authenticateToken, (req, res) => {
    const { is_completed, task, details, format, section, priority, due_date } = req.body;

    const updates = [];
    const params = [];

    if (is_completed !== undefined) {
        const completedValue = (is_completed === true || is_completed === 1) ? 1 : 0;
        updates.push('is_completed = ?');
        params.push(completedValue);

        updates.push('completed_at = ?');
        params.push(completedValue === 1 ? new Date().toISOString() : null);
    }

    if (task !== undefined) { updates.push('task = ?'); params.push(task); }
    if (details !== undefined) { updates.push('details = ?'); params.push(details); }
    if (format !== undefined) { updates.push('format = ?'); params.push(format); }
    if (section !== undefined) { updates.push('section = ?'); params.push(section); }
    if (priority !== undefined) { updates.push('priority = ?'); params.push(priority); }
    if (due_date !== undefined) { updates.push('due_date = ?'); params.push(due_date); }

    if (updates.length === 0) return res.status(400).json({ error: "No fields to update" });

    params.push(req.params.id);
    params.push(req.user.id);
    const sql = `UPDATE todos SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`;

    db.run(sql, params, function (err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Todo not found or unauthorized' });
        res.json({ success: true });
    });
});

// Upload PDF
app.post('/api/upload-roadmap', authenticateToken, upload.single('pdf'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    try {
        const tasks = await parseRoadmapPdf(req.file.path);
        res.json({ message: 'Roadmap parsed', tasks });
    } catch (error) {
        res.status(500).json({ error: 'Failed to parse PDF: ' + error.message });
    }
});

// SECTION MANAGEMENT

// RENAME Section
app.put('/api/sections/:name', authenticateToken, (req, res) => {
    const oldName = req.params.name;
    const { newName } = req.body;

    if (!newName) return res.status(400).json({ error: 'New name required' });

    db.run('UPDATE todos SET section = ? WHERE section = ? AND user_id = ?', [newName, oldName, req.user.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, changes: this.changes });
    });
});

// DELETE Section
app.delete('/api/sections/:name', authenticateToken, (req, res) => {
    const sectionName = req.params.name;

    db.run('DELETE FROM todos WHERE section = ? AND user_id = ?', [sectionName, req.user.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, changes: this.changes });
    });
});

// Batch Insert Todos
app.post('/api/todos/batch', authenticateToken, (req, res) => {
    const { tasks } = req.body;
    if (!tasks || !Array.isArray(tasks)) {
        return res.status(400).json({ error: 'Invalid tasks array' });
    }

    const stmt = db.prepare('INSERT INTO todos (task, details, section, source, created_at, user_id) VALUES (?, ?, ?, ?, ?, ?)');

    db.serialize(() => {
        db.run("BEGIN TRANSACTION");

        try {
            tasks.forEach(sectionObj => {
                const sectionName = sectionObj.section || 'General';
                const createdAt = new Date().toISOString();
                const items = Array.isArray(sectionObj.tasks) ? sectionObj.tasks : [sectionObj];

                items.forEach(taskObj => {
                    const taskText = typeof taskObj === 'string' ? taskObj : taskObj.task;
                    const taskDetails = typeof taskObj === 'object' ? taskObj.details : '';
                    stmt.run(taskText, taskDetails, sectionName, 'pdf', createdAt, req.user.id);
                });
            });

            db.run("COMMIT", (err) => {
                if (err) {
                    console.error(err);
                    return res.status(500).json({ error: 'Failed to batch insert' });
                }
                stmt.finalize();
                res.json({ message: 'Tasks added successfully' });
            });
        } catch (e) {
            console.error(e);
            db.run("ROLLBACK");
            res.status(500).json({ error: 'Batch processing error' });
        }
    });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
