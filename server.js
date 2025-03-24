require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const CryptoJS = require('crypto-js');
const { exec } = require('child_process');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Database Connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) throw err;
    console.log("✅ MySQL Connected");
});

// Generate JWT Token
const generateToken = (user) => {
    return jwt.sign({ user_id: user.user_id }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

// Middleware to Verify Token
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization');

    if (!token) return res.status(401).json({ status: "error", message: "No token provided" });

    const tokenParts = token.split(' ');
    if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer') {
        return res.status(401).json({ status: "error", message: "Invalid token format" });
    }

    jwt.verify(tokenParts[1], process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ status: "error", message: "Invalid or expired token" });

        req.user = user;
        next();
    });
};
const fs = require('fs');
const path = require('path');

const logRequest = (req, res, next) => {
    const startTime = Date.now();
    const { method, url } = req;

    res.on('finish', () => {
        const duration = Date.now() - startTime;
        const log = `${new Date().toISOString()} | ${method} ${url} | Status: ${res.statusCode} | Time: ${duration}ms\n`;
        
        console.log(log); // ✅ Print to console for debugging

        try {
            fs.appendFileSync(path.join(__dirname, 'api.log'), log);
        } catch (error) {
            console.error("❌ Failed to write log:", error);
        }
    });

    next();
};


app.use(logRequest);

// User Signup
app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;
    const hashedPassword = CryptoJS.SHA256(password).toString();

    const sql = "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)";
    db.query(sql, [username, email, hashedPassword], (err, result) => {
        if (err) return res.status(500).json({ status: "error", message: err.message });

        res.json({ status: "success", message: "User registered successfully!" });
    });
});

// User Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = CryptoJS.SHA256(password).toString();

    const sql = "SELECT * FROM users WHERE username = ? AND password_hash = ?";
    db.query(sql, [username, hashedPassword], (err, results) => {
        if (err || results.length === 0) return res.status(400).json({ status: "error", message: "Invalid Credentials" });

        const token = generateToken(results[0]);
        res.json({ status: "success", token });
    });
});

// Lock Folder
app.post('/lock-folder', authenticateToken, (req, res) => {
    const { folder_path } = req.body;
    let encryption_key=123456789012345678901234;
    const userId = req.user.user_id;

    if (!encryption_key || encryption_key.length < 24) {
        return res.status(400).json({ status: "error", message: "Encryption key must be at least 24 characters" });
    }
    const key = CryptoJS.enc.Utf8.parse(encryption_key);
        const encryptedPath = CryptoJS.TripleDES.encrypt(folder_path, key, {
            mode: CryptoJS.mode.ECB,
            padding: CryptoJS.pad.Pkcs7
        }).toString();
    // Check if folder is already locked
    db.query("SELECT file_status, folder_id FROM locked_folders WHERE user_id = ? AND folder_path = ?", 
        [userId, encryptedPath], (err, results) => {
        if (err) return res.status(500).json({ status: "error", message: err.message });
        console.log(userId+" "+folder_path);
        
        if (results.length > 0) {
            console.log(results);
            
            if (results[0].file_status === 'LOCK') {
                return res.status(400).json({ status: "error", message: "This folder is already locked!" });
            } else {
                db.query("UPDATE locked_folders SET file_status = 'LOCK' WHERE user_id = ? AND folder_path = ?", 
                    [userId, encryptedPath], (updateErr) => {
                    if (updateErr) return res.status(500).json({ status: "error", message: "Failed to re-lock folder" });

                    exec(`attrib +h "${folder_path}" && icacls "${folder_path}" /deny Everyone:F`, (error) => {
                        if (error) return res.status(500).json({ status: "error", message: "Failed to lock folder" });
                        db.query("INSERT INTO lock_history (user_id, folder_id, action) VALUES (?, ?, 'LOCK')", 
                            [userId, results[0].folder_id]);

                        res.json({ status: "success", message: "Folder re-locked successfully!" });
                    });
                });
                return;
            }
        }

        // Encrypt folder path
        // const key = CryptoJS.enc.Utf8.parse(encryption_key);
        // const encryptedPath = CryptoJS.TripleDES.encrypt(folder_path, key, {
        //     mode: CryptoJS.mode.ECB,
        //     padding: CryptoJS.pad.Pkcs7
        // }).toString();

        db.query("INSERT INTO locked_folders (user_id, folder_path, encryption_key, file_status) VALUES (?, ?, ?, 'LOCK')", 
            [userId, encryptedPath, encryption_key], (err, result) => {
                if (err) return res.status(500).json({ status: "error", message: err.message });

                exec(`attrib +h "${folder_path}" && icacls "${folder_path}" /deny Everyone:F`, (error) => {
                    if (error) return res.status(500).json({ status: "error", message: "Failed to lock folder" });
                    db.query("INSERT INTO lock_history (user_id, folder_id, action) VALUES (?, ?, 'LOCK')", 
                        [userId, result.insertId]);
                    res.json({ status: "success", message: "Folder locked successfully!" });
                });
            });
    });
});
app.post('/lock-folderen', authenticateToken, (req, res) => {
    const { folder_path } = req.body;
    let encryption_key=123456789012345678901234;
    const userId = req.user.user_id;

    if (!encryption_key || encryption_key.length < 24) {
        return res.status(400).json({ status: "error", message: "Encryption key must be at least 24 characters" });
    }
    const key = CryptoJS.enc.Utf8.parse(encryption_key);
    const decryptedBytes = CryptoJS.TripleDES.decrypt(folder_path, key, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
    });
    const decryptedPath = decryptedBytes.toString(CryptoJS.enc.Utf8);
    if (!decryptedPath) throw new Error("Decryption failed");
    // Check if folder is already locked
    db.query("SELECT file_status, folder_id FROM locked_folders WHERE user_id = ? AND folder_path = ?", 
        [userId, folder_path], (err, results) => {
        if (err) return res.status(500).json({ status: "error", message: err.message });
        console.log(userId+" "+folder_path);
        
        if (results.length > 0) {
            console.log(results);
            
            if (results[0].file_status === 'LOCK') {
                return res.status(400).json({ status: "error", message: "This folder is already locked!" });
            } else {
                db.query("UPDATE locked_folders SET file_status = 'LOCK' WHERE user_id = ? AND folder_path = ?", 
                    [userId, folder_path], (updateErr) => {
                        console.log(decryptedPath);
                        
                    if (updateErr) return res.status(500).json({ status: "error", message: "Failed to re-lock folder" });

                    exec(`attrib +h "${decryptedPath}" && icacls "${decryptedPath}" /deny Everyone:F`, (error) => {
                        if (error) return res.status(500).json({ status: "error", message: "Failed to lock folder" });
                        db.query("INSERT INTO lock_history (user_id, folder_id, action) VALUES (?, ?, 'LOCK')", 
                            [userId, results[0].folder_id]);

                        res.json({ status: "success", message: "Folder re-locked successfully!" });
                    });
                });
                return;
            }
        }else  {
            return res.status(400).json({ status: "error", message: "Folder Not Available" });
        }

        // Encrypt folder path
        // const key = CryptoJS.enc.Utf8.parse(encryption_key);
        // const encryptedPath = CryptoJS.TripleDES.encrypt(folder_path, key, {
        //     mode: CryptoJS.mode.ECB,
        //     padding: CryptoJS.pad.Pkcs7
        // }).toString();

    });
});
// Unlock Folder
app.post('/unlock-folder', authenticateToken, (req, res) => {
    const { folder_id } = req.body;
    let encryption_key=123456789012345678901234
    const userId = req.user.user_id;

    if (!encryption_key || encryption_key.length < 24) {
        return res.status(400).json({ status: "error", message: "Encryption key must be at least 24 characters" });
    }

    db.query("SELECT folder_path FROM locked_folders WHERE folder_id = ? AND user_id = ?", 
        [folder_id, userId], (err, results) => {
        if (err || results.length === 0) 
            return res.status(400).json({ status: "error", message: "Folder not found" });

        const { folder_path } = results[0];

        try {
            const key = CryptoJS.enc.Utf8.parse(encryption_key);
            const decryptedBytes = CryptoJS.TripleDES.decrypt(folder_path, key, {
                mode: CryptoJS.mode.ECB,
                padding: CryptoJS.pad.Pkcs7
            });

            const decryptedPath = decryptedBytes.toString(CryptoJS.enc.Utf8);
            if (!decryptedPath) throw new Error("Decryption failed");
            // exec(`attrib -h "${decryptedPath}" && icacls "${decryptedPath}" /grant Everyone:F`);
            exec(`attrib -h "${decryptedPath}" && icacls "${decryptedPath}" /grant Everyone:F`, (error) => {
                if (error) return res.status(500).json({ status: "error", message: "Failed to unlock folder" });

                db.query("UPDATE locked_folders SET file_status = 'UNLOCK' WHERE folder_id = ? AND user_id = ?", 
                    [folder_id, userId]);
                db.query("INSERT INTO lock_history (user_id, folder_id, action) VALUES (?, ?, 'UNLOCK')", 
                        [userId, folder_id]);

                res.json({ status: "success", message: "Folder unlocked successfully!" });
            });

        } catch (error) {
            res.status(500).json({ status: "error", message: "Decryption failed" });
        }
    });
});
// Get Locked Folders List
app.get('/locked-folders', authenticateToken, (req, res) => {
    const userId = req.user.user_id;
    
    db.query("SELECT folder_id, folder_path FROM locked_folders WHERE user_id = ?", [userId], (err, results) => {
        if (err) return res.status(500).json({ status: "error", message: err.message });

        res.json({ status: "success", folders: results });
    });
});

// Get Lock/Unlock History
app.get('/lock-history', authenticateToken, (req, res) => {
    const userId = req.user.user_id;
    
    db.query("SELECT folder_id, action, action_time FROM lock_history WHERE user_id = ? ORDER BY action_time DESC", 
        [userId], (err, results) => {
        if (err) return res.status(500).json({ status: "error", message: err.message });

        res.json({ status: "success", history: results });
    });
});
// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});


