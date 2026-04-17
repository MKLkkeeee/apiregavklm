const express = require('express');
const cors = require('cors');
const fs = require('fs');
const fsPromises = require('fs').promises;
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nexus_config_secret_2026';
const DB_FILE = path.join(__dirname, 'db.json');
const STORAGE_DIR = path.join(__dirname, 'storage');

// Middleware
app.use(cors());
// เพิ่ม limit สำหรับ body เผื่อเก็บ JSON ใหญ่ๆ
app.use(express.json({ limit: '10mb' })); 
app.use(express.static(path.join(__dirname, 'public')));

// Initialization
async function initDB() {
    if (!fs.existsSync(STORAGE_DIR)) await fsPromises.mkdir(STORAGE_DIR, { recursive: true });
    if (!fs.existsSync(DB_FILE)) {
        await fsPromises.writeFile(DB_FILE, JSON.stringify({ users: [], apikeys: {} }, null, 2));
    }
}

async function readDB() {
    return JSON.parse(await fsPromises.readFile(DB_FILE, 'utf8'));
}
async function writeDB(data) {
    await fsPromises.writeFile(DB_FILE, JSON.stringify(data, null, 2));
}

// Security: ป้องกัน Path Traversal
function getSafePath(userId, targetPath) {
    const userStoragePath = path.resolve(STORAGE_DIR, userId);
    const normalizedTarget = targetPath.replace(/^(\.\.[\/\\])+/, '').replace(/^[/\\]+/, '');
    const resolvedPath = path.resolve(userStoragePath, normalizedTarget);
    
    if (!resolvedPath.startsWith(userStoragePath)) throw new Error('Path traversal detected');
    // บังคับให้เป็นไฟล์ .json เท่านั้น สำหรับระบบนี้
    if (!resolvedPath.endsWith('.json') && path.extname(resolvedPath) !== '') {
        throw new Error('Only .json files are supported');
    }
    return resolvedPath;
}

// --- AUTHENTICATION (สำหรับหน้าเว็บ Dashboard) ---

function authenticateUI(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access denied' });
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
}

app.post('/auth/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

        const db = await readDB();
        if (db.users.find(u => u.username === username)) return res.status(400).json({ error: 'User already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = crypto.randomUUID();
        
        db.users.push({ id: userId, username, password: hashedPassword });
        await writeDB(db);
        await fsPromises.mkdir(path.join(STORAGE_DIR, userId), { recursive: true });

        res.status(201).json({ message: 'User registered' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const db = await readDB();
        const user = db.users.find(u => u.username === username);

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { id: user.id, username: user.username } });
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// --- DASHBOARD API (จัดการไฟล์และการตั้งค่าผ่านหน้าเว็บ) ---

// ดึงรายการไฟล์
app.get('/dashboard/files', authenticateUI, async (req, res) => {
    try {
        const userDir = path.resolve(STORAGE_DIR, req.user.id);
        if (!fs.existsSync(userDir)) return res.json([]);

        // อ่านไฟล์ทั้งหมด (แบบแบนราบ ไม่ใช้โฟลเดอร์ซ้อนกันเพื่อความง่ายในการเรียก API)
        const items = await fsPromises.readdir(userDir, { withFileTypes: true });
        const db = await readDB();
        
        const files = await Promise.all(items.filter(i => i.isFile() && i.name.endsWith('.json')).map(async (item) => {
            const stats = await fsPromises.stat(path.join(userDir, item.name));
            // หา API Key ที่ผูกกับไฟล์นี้
            const apikeys = Object.entries(db.apikeys)
                .filter(([_, data]) => data.owner === req.user.id && data.file === item.name)
                .map(([key, data]) => ({ key, permissions: data.permissions, name: data.name }));

            return {
                name: item.name,
                size: stats.size,
                modified: stats.mtime,
                keys: apikeys
            };
        }));
        
        res.json(files);
    } catch (err) { res.status(400).json({ error: err.message }); }
});

// สร้าง/แก้ไขไฟล์ JSON (ผ่าน Dashboard)
app.post('/dashboard/file', authenticateUI, async (req, res) => {
    try {
        const { filename, content } = req.body;
        if (!filename.endsWith('.json')) return res.status(400).json({ error: 'Filename must end with .json' });
        
        const safePath = getSafePath(req.user.id, filename);
        
        // ตรวจสอบว่าเป็น JSON ที่ถูกต้องไหม
        try {
            JSON.parse(content);
        } catch (e) {
            return res.status(400).json({ error: 'Invalid JSON format' });
        }

        await fsPromises.writeFile(safePath, content, 'utf8');
        res.json({ message: 'File saved successfully' });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

// อ่านไฟล์ JSON (ผ่าน Dashboard)
app.get('/dashboard/file/:name', authenticateUI, async (req, res) => {
    try {
        const safePath = getSafePath(req.user.id, req.params.name);
        if (!fs.existsSync(safePath)) return res.status(404).json({ error: 'File not found' });
        
        const content = await fsPromises.readFile(safePath, 'utf8');
        res.json({ content: JSON.parse(content) }); // ส่งกลับเป็น Object
    } catch (err) { res.status(400).json({ error: err.message }); }
});

// ลบไฟล์ JSON
app.delete('/dashboard/file/:name', authenticateUI, async (req, res) => {
    try {
        const filename = req.params.name;
        const safePath = getSafePath(req.user.id, filename);
        
        if (fs.existsSync(safePath)) {
            await fsPromises.unlink(safePath);
        }

        // ลบ API Keys ที่ผูกกับไฟล์นี้
        const db = await readDB();
        let changed = false;
        for (const [key, data] of Object.entries(db.apikeys)) {
            if (data.owner === req.user.id && data.file === filename) {
                delete db.apikeys[key];
                changed = true;
            }
        }
        if (changed) await writeDB(db);

        res.json({ message: 'File deleted' });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

// สร้าง API Key ใหม่สำหรับไฟล์
app.post('/dashboard/apikey', authenticateUI, async (req, res) => {
    try {
        const { filename, keyName, permissions } = req.body; // permissions: ['read', 'write']
        
        const safePath = getSafePath(req.user.id, filename);
        if (!fs.existsSync(safePath)) return res.status(404).json({ error: 'Target file does not exist' });

        const apiKey = `nx_${crypto.randomBytes(16).toString('hex')}`;
        const db = await readDB();
        
        db.apikeys[apiKey] = {
            owner: req.user.id,
            file: filename,
            name: keyName || 'Unnamed Key',
            permissions: permissions || ['read'],
            createdAt: new Date().toISOString()
        };

        await writeDB(db);
        res.json({ message: 'API Key generated', key: apiKey });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ลบ API Key
app.delete('/dashboard/apikey/:key', authenticateUI, async (req, res) => {
    try {
        const db = await readDB();
        const key = req.params.key;
        
        if (db.apikeys[key] && db.apikeys[key].owner === req.user.id) {
            delete db.apikeys[key];
            await writeDB(db);
            return res.json({ message: 'API Key deleted' });
        }
        res.status(404).json({ error: 'Key not found' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// --- PUBLIC DATA API (สำหรับให้ Bot / App เรียกใช้งาน) ---

// Middleware ตรวจสอบ API Key สำหรับ Service
async function authenticateAPIKey(req, res, next) {
    const apiKey = req.headers['x-api-key'] || req.query.apikey;
    if (!apiKey) return res.status(401).json({ error: 'API Key required' });

    const db = await readDB();
    const keyData = db.apikeys[apiKey];
    
    if (!keyData) return res.status(403).json({ error: 'Invalid API Key' });
    
    req.keyData = keyData; // { owner, file, permissions }
    next();
}

// [GET] อ่านค่า Config ทั้งก้อน
app.get('/api/data', authenticateAPIKey, async (req, res) => {
    try {
        if (!req.keyData.permissions.includes('read')) return res.status(403).json({ error: 'Read permission denied' });
        
        const safePath = getSafePath(req.keyData.owner, req.keyData.file);
        if (!fs.existsSync(safePath)) return res.status(404).json({ error: 'Data file not found' });

        const data = JSON.parse(await fsPromises.readFile(safePath, 'utf8'));
        res.json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// [PUT] เขียนทับ Config ทั้งก้อน (Replace all)
app.put('/api/data', authenticateAPIKey, async (req, res) => {
    try {
        if (!req.keyData.permissions.includes('write')) return res.status(403).json({ error: 'Write permission denied' });
        
        const newData = req.body;
        if (typeof newData !== 'object' || Array.isArray(newData) || newData === null) {
            return res.status(400).json({ error: 'Body must be a JSON object' });
        }

        const safePath = getSafePath(req.keyData.owner, req.keyData.file);
        await fsPromises.writeFile(safePath, JSON.stringify(newData, null, 2), 'utf8');
        
        res.json({ success: true, message: 'Data fully updated' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// [PATCH] อัปเดตเฉพาะบางฟิลด์ (Merge data)
app.patch('/api/data', authenticateAPIKey, async (req, res) => {
    try {
        if (!req.keyData.permissions.includes('write')) return res.status(403).json({ error: 'Write permission denied' });
        
        const patchData = req.body;
        if (typeof patchData !== 'object' || Array.isArray(patchData) || patchData === null) {
            return res.status(400).json({ error: 'Body must be a JSON object' });
        }

        const safePath = getSafePath(req.keyData.owner, req.keyData.file);
        let currentData = {};
        
        if (fs.existsSync(safePath)) {
            currentData = JSON.parse(await fsPromises.readFile(safePath, 'utf8'));
        }

        // รวมข้อมูลเก่าและใหม่เข้าด้วยกัน (Shallow merge)
        const updatedData = { ...currentData, ...patchData };
        
        await fsPromises.writeFile(safePath, JSON.stringify(updatedData, null, 2), 'utf8');
        
        res.json({ success: true, message: 'Data partially updated', data: updatedData });
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// Fallback
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start
initDB().then(() => {
    app.listen(PORT, () => {
        console.log(`Nexus Config API running on port ${PORT}`);
    });
}).catch(console.error);
