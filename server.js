const express = require('express');
const cors = require('cors');
const fs = require('fs');
const fsPromises = require('fs').promises;
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const crypto = require('crypto');
const mime = require('mime-types');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_2026';
const DB_FILE = path.join(__dirname, 'db.json');
const STORAGE_DIR = path.join(__dirname, 'storage');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configure Multer for file uploads
const upload = multer({ dest: path.join(__dirname, 'temp') });

// Database Initialization
async function initDB() {
    if (!fs.existsSync(STORAGE_DIR)) {
        await fsPromises.mkdir(STORAGE_DIR, { recursive: true });
    }
    if (!fs.existsSync(DB_FILE)) {
        const initialData = { users: [], keys: {} };
        await fsPromises.writeFile(DB_FILE, JSON.stringify(initialData, null, 2));
    }
    if (!fs.existsSync(path.join(__dirname, 'temp'))) {
        await fsPromises.mkdir(path.join(__dirname, 'temp'), { recursive: true });
    }
}

// Database Helpers
async function readDB() {
    const data = await fsPromises.readFile(DB_FILE, 'utf8');
    return JSON.parse(data);
}
async function writeDB(data) {
    await fsPromises.writeFile(DB_FILE, JSON.stringify(data, null, 2));
}

// Security: Path Traversal Prevention
function getSafePath(userId, targetPath) {
    const userStoragePath = path.resolve(STORAGE_DIR, userId);
    // Remove leading slashes from targetPath to prevent absolute path resolution issues
    const normalizedTarget = targetPath.replace(/^(\.\.[\/\\])+/, '').replace(/^[/\\]+/, '');
    const resolvedPath = path.resolve(userStoragePath, normalizedTarget);
    
    if (!resolvedPath.startsWith(userStoragePath)) {
        throw new Error('Path traversal detected');
    }
    return resolvedPath;
}

// Authentication Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Access denied' });
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
}

// --- AUTHENTICATION ROUTES ---

app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

        const db = await readDB();
        if (db.users.find(u => u.username === username)) {
            return res.status(400).json({ error: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = crypto.randomUUID();
        
        db.users.push({ id: userId, username, password: hashedPassword });
        await writeDB(db);

        // Create isolated storage for user
        await fsPromises.mkdir(path.join(STORAGE_DIR, userId), { recursive: true });

        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const db = await readDB();
        const user = db.users.find(u => u.username === username);

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { id: user.id, username: user.username } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- FILE SYSTEM ROUTES (PROTECTED) ---

app.get('/api/list', authenticateToken, async (req, res) => {
    try {
        const targetPath = req.query.path || '/';
        const safePath = getSafePath(req.user.id, targetPath);
        
        if (!fs.existsSync(safePath)) {
            return res.status(404).json({ error: 'Directory not found' });
        }

        const items = await fsPromises.readdir(safePath, { withFileTypes: true });
        const db = await readDB();
        
        const result = await Promise.all(items.map(async (item) => {
            const itemPath = path.join(safePath, item.name);
            const stats = await fsPromises.stat(itemPath);
            const relPath = path.posix.join(targetPath, item.name);
            
            // Check if file is shared publicly
            const apiKeyEntry = Object.entries(db.keys).find(([_, data]) => data.path === relPath && data.owner === req.user.id);

            return {
                name: item.name,
                path: relPath,
                isDirectory: item.isDirectory(),
                size: stats.size,
                modified: stats.mtime,
                isPublic: !!apiKeyEntry,
                apiKey: apiKeyEntry ? apiKeyEntry[0] : null
            };
        }));

        // Sort: folders first, then files alphabetically
        result.sort((a, b) => {
            if (a.isDirectory === b.isDirectory) return a.name.localeCompare(b.name);
            return a.isDirectory ? -1 : 1;
        });

        res.json(result);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.post('/api/folder', authenticateToken, async (req, res) => {
    try {
        const { path: folderPath } = req.body;
        const safePath = getSafePath(req.user.id, folderPath);
        await fsPromises.mkdir(safePath, { recursive: true });
        res.json({ message: 'Folder created successfully' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.post('/api/file', authenticateToken, upload.array('files'), async (req, res) => {
    try {
        const targetPath = req.body.path || '/';
        
        for (const file of req.files) {
            const safePath = getSafePath(req.user.id, path.posix.join(targetPath, file.originalname));
            await fsPromises.rename(file.path, safePath);
        }
        res.json({ message: 'Files uploaded successfully' });
    } catch (err) {
        // Cleanup temp files on error
        if (req.files) {
            for (const file of req.files) {
                if (fs.existsSync(file.path)) await fsPromises.unlink(file.path);
            }
        }
        res.status(400).json({ error: err.message });
    }
});

app.put('/api/file', authenticateToken, async (req, res) => {
    try {
        const { path: filePath, content } = req.body;
        const safePath = getSafePath(req.user.id, filePath);
        await fsPromises.writeFile(safePath, content, 'utf8');
        res.json({ message: 'File saved successfully' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.post('/api/delete', authenticateToken, async (req, res) => {
    try {
        const { paths } = req.body; // Array of paths
        for (const p of paths) {
            const safePath = getSafePath(req.user.id, p);
            if (fs.existsSync(safePath)) {
                await fsPromises.rm(safePath, { recursive: true, force: true });
            }
            
            // Clean up API keys if deleting a public file
            const db = await readDB();
            let keysChanged = false;
            for (const [key, data] of Object.entries(db.keys)) {
                if (data.owner === req.user.id && (data.path === p || data.path.startsWith(p + '/'))) {
                    delete db.keys[key];
                    keysChanged = true;
                }
            }
            if (keysChanged) await writeDB(db);
        }
        res.json({ message: 'Items deleted successfully' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.post('/api/move', authenticateToken, async (req, res) => {
    try {
        const { items, destination } = req.body; // items: array of paths, destination: folder path
        for (const p of items) {
            const sourcePath = getSafePath(req.user.id, p);
            const fileName = path.basename(p);
            const destPath = getSafePath(req.user.id, path.posix.join(destination, fileName));
            await fsPromises.rename(sourcePath, destPath);
        }
        res.json({ message: 'Items moved successfully' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// --- API KEYS & PUBLIC SHARING ---

app.post('/api/key', authenticateToken, async (req, res) => {
    try {
        const { path: targetPath, isPublic } = req.body;
        const db = await readDB();
        
        // Remove existing key for this path
        for (const [key, data] of Object.entries(db.keys)) {
            if (data.owner === req.user.id && data.path === targetPath) {
                delete db.keys[key];
            }
        }

        let newKey = null;
        if (isPublic) {
            newKey = crypto.randomBytes(16).toString('hex');
            db.keys[newKey] = {
                owner: req.user.id,
                path: targetPath,
                createdAt: new Date().toISOString()
            };
        }

        await writeDB(db);
        res.json({ message: isPublic ? 'File shared' : 'File made private', key: newKey });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/public/:key', async (req, res) => {
    try {
        const { key } = req.params;
        const db = await readDB();
        const fileRecord = db.keys[key];
        
        if (!fileRecord) return res.status(404).json({ error: 'File not found or private' });

        const safePath = getSafePath(fileRecord.owner, fileRecord.path);
        
        if (!fs.existsSync(safePath)) {
            return res.status(404).json({ error: 'File no longer exists' });
        }

        const stat = await fsPromises.stat(safePath);
        if (stat.isDirectory()) {
            return res.status(400).json({ error: 'Cannot directly download directories' });
        }

        const mimeType = mime.lookup(safePath) || 'application/octet-stream';
        res.setHeader('Content-Type', mimeType);
        
        // Handle download vs inline viewing
        if (req.query.download) {
            res.download(safePath, path.basename(safePath));
        } else {
            res.sendFile(safePath);
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- DASHBOARD STATS ---

// Helper to get folder size
async function getDirectorySize(dirPath) {
    let size = 0;
    const items = await fsPromises.readdir(dirPath, { withFileTypes: true });
    for (const item of items) {
        const itemPath = path.join(dirPath, item.name);
        if (item.isDirectory()) {
            size += await getDirectorySize(itemPath);
        } else {
            const stats = await fsPromises.stat(itemPath);
            size += stats.size;
        }
    }
    return size;
}

// Helper to get total file count recursively
async function getFileCount(dirPath) {
    let count = 0;
    const items = await fsPromises.readdir(dirPath, { withFileTypes: true });
    for (const item of items) {
        const itemPath = path.join(dirPath, item.name);
        if (item.isDirectory()) {
            count += await getFileCount(itemPath);
        } else {
            count += 1;
        }
    }
    return count;
}


app.get('/api/stats', authenticateToken, async (req, res) => {
    try {
        const userStoragePath = path.resolve(STORAGE_DIR, req.user.id);
        const totalSize = await getDirectorySize(userStoragePath);
        const totalFiles = await getFileCount(userStoragePath);
        
        const db = await readDB();
        const publicFiles = Object.values(db.keys).filter(k => k.owner === req.user.id).length;

        res.json({
            totalStorageSize: totalSize,
            totalFiles: totalFiles,
            publicFilesCount: publicFiles
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Fallback to index.html for SPA routing
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Initialize and Start
initDB().then(() => {
    app.listen(PORT, () => {
        console.log(`Cloud Storage SaaS running on http://localhost:${PORT}`);
    });
}).catch(console.error);