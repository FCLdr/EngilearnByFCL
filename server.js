const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'engilearn-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('.'));
app.use('/uploads', express.static('uploads'));

// Création des dossiers
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
if (!fs.existsSync('db')) fs.mkdirSync('db');

// Base de données SQLite
const db = new Database('db/engilearn.db');

// Initialisation des tables
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS pdfs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        filename TEXT NOT NULL,
        subject TEXT NOT NULL,
        category TEXT NOT NULL,
        size INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
`);

// Utilisateur anonyme par défaut pour les PDFs sans connexion
let ANON_USER_ID;
const anon = db.prepare("SELECT id FROM users WHERE username = ?").get('anonymous');
if (!anon) {
    const stmt = db.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');
    const result = stmt.run('anonymous', 'anon@localhost', '');
    ANON_USER_ID = result.lastInsertRowid;
} else {
    ANON_USER_ID = anon.id;
}

// Configuration Multer pour les PDFs
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => {
        const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
        cb(null, unique + '-' + file.originalname);
    }
});
const upload = multer({ 
    storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/pdf') cb(null, true);
        else cb(new Error('Seuls les PDFs sont acceptés'));
    },
    limits: { fileSize: 50 * 1024 * 1024 } // 50 Mo max
});

// Middleware d'authentification (gardé pour les routes auth, mais pas obligatoire pour les PDFs)
function authMiddleware(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token manquant' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        req.username = decoded.username;
        next();
    } catch {
        res.status(401).json({ error: 'Token invalide' });
    }
}

// ========== ROUTES AUTH ==========

// Inscription
app.post('/api/auth/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Tous les champs sont requis' });
    }

    const hashed = await bcrypt.hash(password, 10);
    try {
        const stmt = db.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');
        const result = stmt.run(username, email, hashed);

        const token = jwt.sign({ userId: result.lastInsertRowid, username }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, username });
    } catch (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: "Nom d'utilisateur ou email déjà utilisé" });
        }
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// Connexion
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;

    const stmt = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?');
    const user = stmt.get(username, username);

    if (!user) return res.status(400).json({ error: 'Utilisateur non trouvé' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Mot de passe incorrect' });

    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username: user.username });
});

// Profil
app.get('/api/auth/me', authMiddleware, (req, res) => {
    res.json({ userId: req.userId, username: req.username });
});

// ========== ROUTES PDFs (SANS AUTH) ==========

// Upload
app.post('/api/pdfs', upload.single('pdf'), (req, res) => {
    const { subject, category } = req.body;
    const file = req.file;

    if (!file) return res.status(400).json({ error: 'Aucun fichier uploadé' });

    const stmt = db.prepare(
        'INSERT INTO pdfs (user_id, name, filename, subject, category, size) VALUES (?, ?, ?, ?, ?, ?)'
    );
    const result = stmt.run(ANON_USER_ID, file.originalname, file.filename, subject, category, file.size);

    res.json({ 
        id: result.lastInsertRowid,
        name: file.originalname,
        filename: file.filename,
        subject,
        category,
        size: file.size,
        created_at: new Date().toISOString()
    });
});

// Liste des PDFs
app.get('/api/pdfs', (req, res) => {
    const { subject, category } = req.query;
    let sql = 'SELECT * FROM pdfs WHERE 1=1';
    const params = [];

    if (subject) { sql += ' AND subject = ?'; params.push(subject); }
    if (category) { sql += ' AND category = ?'; params.push(category); }
    sql += ' ORDER BY created_at DESC';

    const stmt = db.prepare(sql);
    const pdfs = stmt.all(...params);
    res.json(pdfs);
});

// Supprimer
app.delete('/api/pdfs/:id', (req, res) => {
    const stmt = db.prepare('SELECT * FROM pdfs WHERE id = ?');
    const pdf = stmt.get(req.params.id);

    if (!pdf) return res.status(404).json({ error: 'PDF non trouvé' });

    // Supprimer le fichier
    const filePath = path.join(__dirname, 'uploads', pdf.filename);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

    // Supprimer de la BDD
    const del = db.prepare('DELETE FROM pdfs WHERE id = ?');
    del.run(req.params.id);

    res.json({ success: true });
});

// Redirection auth → auth.html
app.get('/auth', (req, res) => res.sendFile(path.join(__dirname, 'auth.html')));

app.listen(PORT, () => {
    console.log(`🚀 Engilearn server running on http://localhost:${PORT}`);
});
