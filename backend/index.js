require('dotenv').config();
const express = require('express')
const cors = require('cors')
const fs = require('fs')
const path = require('path')
const multer = require('multer')
const crypto = require('crypto')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const { Pool } = require('pg')

const DATA_DIR = path.join(__dirname, 'data')
const STORAGE_DIR = path.join(__dirname, 'storage')
const KEYS_DIR = path.join(__dirname, 'keys')
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR)
if (!fs.existsSync(STORAGE_DIR)) fs.mkdirSync(STORAGE_DIR)
if (!fs.existsSync(KEYS_DIR)) fs.mkdirSync(KEYS_DIR)

const FILE_DB_PATH = path.join(DATA_DIR, 'db.json')

const connectionString = process.env.POSTGRES_URI || process.env.DATABASE_URL
let pool = null
let usePostgres = false

if (connectionString) {
  const poolConfig = { connectionString }
  if (process.env.POSTGRES_SSL === 'true') {
    poolConfig.ssl = { rejectUnauthorized: false }
  }
  pool = new Pool(poolConfig)
  usePostgres = true
  console.log('POSTGRES_URI detected: backend will use PostgreSQL storage')
} else {
  if (!fs.existsSync(FILE_DB_PATH)) {
    fs.writeFileSync(FILE_DB_PATH, JSON.stringify({ users: [], docs: [] }, null, 2))
  }
  console.log('POSTGRES_URI not set: backend falling back to local JSON storage')
}

function createId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 10)
}

function readFileDb() {
  try {
    return JSON.parse(fs.readFileSync(FILE_DB_PATH, 'utf8'))
  } catch (e) {
    return { users: [], docs: [] }
  }
}

function writeFileDb(data) {
  fs.writeFileSync(FILE_DB_PATH, JSON.stringify(data, null, 2))
}

async function initDb() {
  if (usePostgres) {
    await pool.query('SELECT 1')
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL DEFAULT '',
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'student',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        public_key TEXT
      )
    `)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS documents (
        id TEXT PRIMARY KEY,
        owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        owner_email TEXT NOT NULL,
        title TEXT NOT NULL,
        filename TEXT NOT NULL,
        mime TEXT NOT NULL,
        storage_path TEXT NOT NULL,
        signature TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS document_recipients (
        doc_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
        email TEXT NOT NULL,
        aes_key_encrypted TEXT,
        PRIMARY KEY (doc_id, email)
      )
    `)
    console.log('Connected to PostgreSQL')
  } else {
    if (!fs.existsSync(FILE_DB_PATH)) {
      writeFileDb({ users: [], docs: [] })
    }
    console.log('Using JSON file storage at', FILE_DB_PATH)
  }
}

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me'

// Server keypair remains for optional metadata signing, but core E2E uses per-user keys
const PUB_KEY_PATH = path.join(KEYS_DIR, 'server_pub.pem')
const PRIV_KEY_PATH = path.join(KEYS_DIR, 'server_priv.pem')
let serverKeyPair
if (!fs.existsSync(PUB_KEY_PATH) || !fs.existsSync(PRIV_KEY_PATH)) {
  console.log('Generating server RSA keypair...')
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
  fs.writeFileSync(PUB_KEY_PATH, publicKey.export({ type: 'pkcs1', format: 'pem' }))
  fs.writeFileSync(PRIV_KEY_PATH, privateKey.export({ type: 'pkcs1', format: 'pem' }))
  serverKeyPair = { publicKey, privateKey }
} else {
  serverKeyPair = {
    publicKey: fs.readFileSync(PUB_KEY_PATH, 'utf8'),
    privateKey: fs.readFileSync(PRIV_KEY_PATH, 'utf8'),
  }
}

// DB schema
const app = express()
app.use(cors({ origin: process.env.CORS_ORIGIN || true }))
app.use(express.json())

// Initialize DB (will be done before server starts below)

// helper
function signMetadata(meta) {
  const sign = crypto.createSign('sha256')
  sign.update(JSON.stringify(meta))
  sign.end()
  return sign.sign(serverKeyPair.privateKey, 'base64')
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization
  if (!authHeader) return res.status(401).json({ error: 'Missing auth' })
  const token = authHeader.split(' ')[1]
  try {
    const payload = jwt.verify(token, JWT_SECRET)
    req.user = payload
    next()
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' })
  }
}

async function loadDocumentForVerify(id) {
  if (usePostgres) {
    const metaResult = await pool.query(
      `SELECT id, title, filename, mime, owner_email, created_at, signature
       FROM documents WHERE id = $1`,
      [id]
    )
    if (metaResult.rowCount === 0) return null
    const doc = metaResult.rows[0]
    const recipients = await pool.query(
      'SELECT email FROM document_recipients WHERE doc_id = $1 ORDER BY email ASC',
      [id]
    )
    return {
      id: doc.id,
      title: doc.title,
      filename: doc.filename,
      mime: doc.mime,
      ownerEmail: doc.owner_email,
      createdAt: doc.created_at ? doc.created_at.toISOString() : null,
      signature: doc.signature || null,
      allowed: recipients.rows.map(r => r.email),
    }
  }
  const data = readFileDb()
  const doc = data.docs.find(d => d.id === id)
  if (!doc) return null
  return {
    id: doc.id,
    title: doc.title,
    filename: doc.filename,
    mime: doc.mime,
    ownerEmail: doc.owner_email,
    createdAt: doc.created_at || null,
    signature: doc.signature || null,
    allowed: doc.allowed || [],
  }
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

// Routes
app.post('/api/register', async (req, res) => {
  const { name, email, password, role, publicKey } = req.body
  if (!email || !password) return res.status(400).json({ error: 'email/password required' })
  try {
    const hash = await bcrypt.hash(password, 10)
    const userRole = role || 'student'
    let userId
    if (usePostgres) {
      const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email])
      if (existing.rowCount > 0) return res.status(400).json({ error: 'User exists' })
      userId = createId()
      await pool.query(
        `INSERT INTO users (id, name, email, password_hash, role, public_key)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [userId, name || '', email, hash, userRole, publicKey || null]
      )
    } else {
      const data = readFileDb()
      if (data.users.find(u => u.email === email)) {
        return res.status(400).json({ error: 'User exists' })
      }
      userId = createId()
      const now = new Date().toISOString()
      data.users.push({
        id: userId,
        name: name || '',
        email,
        password_hash: hash,
        role: userRole,
        created_at: now,
        public_key: publicKey || null,
      })
      writeFileDb(data)
    }
    const token = jwt.sign({ id: userId, email, role: userRole }, JWT_SECRET, { expiresIn: '7d' })
    return res.json({ ok: true, token })
  } catch (e) {
    console.error('Register error:', e.message)
    return res.status(500).json({ error: 'Registration failed: ' + e.message })
  }
})

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body
  if (!email || !password) return res.status(400).json({ error: 'email/password required' })
  try {
    let user
    if (usePostgres) {
      const { rows } = await pool.query(
        'SELECT id, email, password_hash, role FROM users WHERE email = $1',
        [email]
      )
      if (rows.length === 0) return res.status(401).json({ error: 'invalid' })
      user = rows[0]
    } else {
      const data = readFileDb()
      const row = data.users.find(u => u.email === email)
      if (!row) return res.status(401).json({ error: 'invalid' })
      user = row
    }
    const ok = await bcrypt.compare(password, user.password_hash)
    if (!ok) return res.status(401).json({ error: 'invalid' })
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' })
    return res.json({ ok: true, token })
  } catch (e) {
    console.error('Login error:', e.message)
    return res.status(500).json({ error: 'Login failed: ' + e.message })
  }
})

// admin: list users
app.get('/api/users', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' })
  let users
  if (usePostgres) {
    const { rows } = await pool.query(
      'SELECT id, name, email, role, created_at, public_key FROM users ORDER BY created_at DESC'
    )
    users = rows.map(row => ({
      id: row.id,
      name: row.name || '',
      email: row.email,
      role: row.role || 'student',
      created_at: row.created_at ? row.created_at.toISOString() : null,
      public_key: row.public_key || null,
    }))
  } else {
    const data = readFileDb()
    users = data.users.map(u => ({
      id: u.id,
      name: u.name || '',
      email: u.email,
      role: u.role || 'student',
      created_at: u.created_at || null,
      public_key: u.public_key || null,
    }))
  }
  return res.json({ users })
})

app.post('/api/users/:id/role', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' })
  const id = req.params.id
  const { role } = req.body
  if (usePostgres) {
    await pool.query('UPDATE users SET role = $1 WHERE id = $2', [role, id])
  } else {
    const data = readFileDb()
    const user = data.users.find(u => u.id === id)
    if (user) {
      user.role = role
      writeFileDb(data)
    }
  }
  return res.json({ ok: true })
})

// set or update current user's public key
app.post('/api/users/me/key', authMiddleware, async (req, res) => {
  const { publicKey } = req.body
  if (!publicKey) return res.status(400).json({ error: 'publicKey required' })
  if (usePostgres) {
    await pool.query('UPDATE users SET public_key = $1 WHERE id = $2', [publicKey, req.user.id])
  } else {
    const data = readFileDb()
    const user = data.users.find(u => u.id === req.user.id)
    if (user) {
      user.public_key = publicKey
      writeFileDb(data)
    }
  }
  res.json({ ok: true })
})

// list users for recipient picker (returns non-sensitive fields)
app.get('/api/users/list', authMiddleware, async (req, res) => {
  let users
  if (usePostgres) {
    const { rows } = await pool.query(
      'SELECT id, name, email, role FROM users ORDER BY name ASC'
    )
    users = rows.map(row => ({
      id: row.id,
      name: row.name || '',
      email: row.email,
      role: row.role || 'student',
    }))
  } else {
    const data = readFileDb()
    users = data.users
      .slice()
      .sort((a, b) => (a.name || '').localeCompare(b.name || ''))
      .map(u => ({
        id: u.id,
        name: u.name || '',
        email: u.email,
        role: u.role || 'student',
      }))
  }
  return res.json({ users })
})

// get public key for an email (used by clients to encrypt AES keys for recipients)
app.get('/api/users/:email/pubkey', async (req, res) => {
  const email = req.params.email
  if (usePostgres) {
    const { rows } = await pool.query(
      'SELECT email, public_key FROM users WHERE email = $1',
      [email]
    )
    if (rows.length === 0 || !rows[0].public_key) {
      return res.status(404).json({ error: 'not found' })
    }
    res.json({ email: rows[0].email, publicKey: rows[0].public_key })
  } else {
    const data = readFileDb()
    const user = data.users.find(u => u.email === email)
    if (!user || !user.public_key) return res.status(404).json({ error: 'not found' })
    res.json({ email: user.email, publicKey: user.public_key })
  }
})

// file upload
const upload = multer({ storage: multer.memoryStorage() })
// Upload expects client-side encrypted file and per-recipient encrypted AES keys.
// Fields:
// - file: binary (already encrypted by client)
// - title
// - allowed: JSON array
// - keys: JSON object mapping recipient email -> base64(encryptedAESKey)
// - signature: base64 signature created by owner over metadata (optional)
app.post('/api/docs', authMiddleware, upload.single('file'), async (req, res) => {
  const file = req.file
  const { title, allowed, keys, signature } = req.body
  if (!file) return res.status(400).json({ error: 'file required' })

  const ownerId = req.user.id
  const ownerEmail = req.user.email
  const parsedAllowed = (() => {
    try {
      return typeof allowed === 'string' ? JSON.parse(allowed) : allowed || []
    } catch {
      return []
    }
  })()
  const keysObj = (() => {
    try {
      return typeof keys === 'string' ? JSON.parse(keys) : keys || {}
    } catch {
      return {}
    }
  })()
  const allowedSet = new Set(Array.isArray(parsedAllowed) ? parsedAllowed : [])
  Object.keys(keysObj || {}).forEach(email => allowedSet.add(email))
  const allowedList = Array.from(allowedSet)

  const docId = createId()
  const storageName = `${Date.now().toString(36)}-${file.originalname.replace(/[^a-zA-Z0-9._-]/g, '')}`
  const storagePath = path.join(STORAGE_DIR, storageName)

  try {
    fs.writeFileSync(storagePath, file.buffer)

    if (usePostgres) {
      const client = await pool.connect()
      try {
        await client.query('BEGIN')
        await client.query(
          `INSERT INTO documents
           (id, owner_id, owner_email, title, filename, mime, storage_path, signature)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
          ,[
            docId,
            ownerId,
            ownerEmail,
            title || file.originalname,
            file.originalname,
            file.mimetype,
            storageName,
            signature || null,
          ]
        )
        for (const email of allowedList) {
          await client.query(
            `INSERT INTO document_recipients (doc_id, email, aes_key_encrypted)
             VALUES ($1, $2, $3)
             ON CONFLICT (doc_id, email) DO UPDATE SET aes_key_encrypted = EXCLUDED.aes_key_encrypted`,
            [docId, email, keysObj[email] || null]
          )
        }
        await client.query('COMMIT')
      } catch (err) {
        await client.query('ROLLBACK')
        throw err
      } finally {
        client.release()
      }
    } else {
      const data = readFileDb()
      const created = new Date().toISOString()
      const docRecord = {
        id: docId,
        owner_id: ownerId,
        owner_email: ownerEmail,
        title: title || file.originalname,
        filename: file.originalname,
        mime: file.mimetype,
        storage_path: storageName,
        signature: signature || null,
        created_at: created,
        allowed: allowedList,
        keys: Object.keys(keysObj || {}).map(email => ({
          email,
          aes_key_encrypted: keysObj[email],
        })),
      }
      data.docs.push(docRecord)
      writeFileDb(data)
    }

    const verifyUrl = `${req.protocol}://${req.get('host')}/verify/${docId}`
    return res.json({ ok: true, id: docId, verifyUrl })
  } catch (e) {
    console.error('Document upload failed:', e.message)
    if (fs.existsSync(storagePath)) fs.unlink(storagePath, () => {})
    return res.status(500).json({ error: 'Upload failed: ' + e.message })
  }
})

app.get('/api/docs/:id/verify', async (req, res) => {
  const id = req.params.id
  try {
    const doc = await loadDocumentForVerify(id)
    if (!doc) return res.status(404).json({ error: 'not found' })
    return res.json({
      id: doc.id,
      title: doc.title,
      filename: doc.filename,
      mime: doc.mime,
      owner: { email: doc.ownerEmail },
      allowed: doc.allowed,
      created_at: doc.createdAt,
      signature: doc.signature,
    })
  } catch (e) {
    return res.status(500).json({ error: 'verification lookup failed' })
  }
})

app.get('/verify/:id', async (req, res) => {
  const id = req.params.id
  try {
    const doc = await loadDocumentForVerify(id)
    if (!doc) {
      res.status(404).type('html').send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Document Verification</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, sans-serif; margin: 0; padding: 40px; background: #f6f8fa; color: #111; }
    .card { max-width: 640px; margin: 0 auto; background: #fff; border-radius: 12px; box-shadow: 0 16px 40px rgba(0,0,0,0.08); padding: 32px; }
    h1 { margin-top: 0; font-size: 1.8rem; }
    .meta { margin: 18px 0; }
    .meta dt { font-weight: 600; }
    .meta dd { margin: 0 0 12px 0; color: #334155; }
    .callout { margin-top: 24px; padding: 16px; border-radius: 10px; background: #eff6ff; color: #1d4ed8; }
    .footer { margin-top: 36px; font-size: 0.85rem; color: #64748b; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Document Not Found</h1>
    <p>The verification record for <strong>${escapeHtml(id)}</strong> could not be located. The link may be expired or incorrect.</p>
    <div class="footer">Secure Document Sharing Service</div>
  </div>
</body>
</html>`)
      return
    }

    const allowed = doc.allowed.length
      ? doc.allowed.map(email => `<li>${escapeHtml(email)}</li>`).join('')
      : '<li>No additional recipients recorded</li>'
    const signatureNote = doc.signature
      ? 'Server signature captured for this artifact.'
      : 'No server-side signature recorded.'
    const createdAt = doc.createdAt ? escapeHtml(doc.createdAt) : 'Unknown'

    res.type('html').send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Document Verification • ${escapeHtml(doc.title || doc.filename)}</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, sans-serif; margin: 0; padding: 40px; background: #f6f8fa; color: #111; }
    .card { max-width: 720px; margin: 0 auto; background: #fff; border-radius: 14px; box-shadow: 0 18px 48px rgba(15,23,42,0.12); padding: 36px; }
    h1 { margin: 0 0 12px 0; font-size: 2rem; line-height: 1.1; }
    .badge { display: inline-flex; align-items: center; padding: 6px 12px; border-radius: 999px; background: #eff6ff; color: #1d4ed8; font-weight: 600; font-size: 0.9rem; }
    dl { margin: 28px 0; display: grid; grid-template-columns: minmax(140px, 200px) 1fr; row-gap: 12px; column-gap: 24px; }
    dt { font-weight: 600; color: #0f172a; }
    dd { margin: 0; color: #334155; }
    ul { margin: 12px 0 0 0; padding-left: 18px; }
    .signature { margin-top: 28px; padding: 18px; border-radius: 12px; background: ${doc.signature ? '#dcfce7' : '#fef3c7'}; color: ${doc.signature ? '#166534' : '#92400e'}; }
    .footer { margin-top: 36px; font-size: 0.85rem; color: #64748b; }
  </style>
</head>
<body>
  <div class="card">
    <span class="badge">Document Verification</span>
    <h1>${escapeHtml(doc.title || doc.filename)}</h1>
    <dl>
      <dt>Document ID</dt><dd>${escapeHtml(doc.id)}</dd>
      <dt>Filename</dt><dd>${escapeHtml(doc.filename)}</dd>
      <dt>MIME Type</dt><dd>${escapeHtml(doc.mime || 'n/a')}</dd>
      <dt>Owner</dt><dd>${escapeHtml(doc.ownerEmail)}</dd>
      <dt>Created</dt><dd>${createdAt}</dd>
      <dt>Allowed Recipients</dt>
      <dd><ul>${allowed}</ul></dd>
    </dl>
    <div class="signature">${escapeHtml(signatureNote)}</div>
    <div class="footer">Share this page to let recipients verify the document metadata without needing an account.</div>
  </div>
</body>
</html>`)
  } catch (e) {
    res.status(500).type('html').send('<h1>Verification unavailable</h1>')
  }
})

// Return encrypted AES key for the requesting user (server does not decrypt)
app.get('/api/docs/:id/key', authMiddleware, async (req, res) => {
  const id = req.params.id
  const userEmail = req.user.email
  if (usePostgres) {
    try {
      const { rows } = await pool.query(
        'SELECT owner_email FROM documents WHERE id = $1',
        [id]
      )
      if (rows.length === 0) return res.status(404).json({ error: 'not found' })
      const doc = rows[0]
      const keyResult = await pool.query(
        'SELECT aes_key_encrypted FROM document_recipients WHERE doc_id = $1 AND email = $2',
        [id, userEmail]
      )
      if (req.user.role !== 'admin' && userEmail !== doc.owner_email && keyResult.rowCount === 0) {
        return res.status(403).json({ error: 'forbidden' })
      }
      if (keyResult.rowCount === 0 || !keyResult.rows[0].aes_key_encrypted) {
        return res.status(404).json({ error: 'key not found for user' })
      }
      return res.json({ aesKeyEncrypted: keyResult.rows[0].aes_key_encrypted })
    } catch (e) {
      return res.status(404).json({ error: 'not found' })
    }
  } else {
    const data = readFileDb()
    const doc = data.docs.find(d => d.id === id)
    if (!doc) return res.status(404).json({ error: 'not found' })
    if (req.user.role !== 'admin' && userEmail !== doc.owner_email) {
      if (!((doc.allowed || []).includes(userEmail))) {
        return res.status(403).json({ error: 'forbidden' })
      }
    }
    const keyEntry = (doc.keys || []).find(k => k.email === userEmail && k.aes_key_encrypted)
    if (!keyEntry) return res.status(404).json({ error: 'key not found for user' })
    return res.json({ aesKeyEncrypted: keyEntry.aes_key_encrypted })
  }
})

// Serve encrypted blob (clients will decrypt locally)
app.get('/api/docs/:id/blob', authMiddleware, async (req, res) => {
  const id = req.params.id
  if (usePostgres) {
    try {
      const { rows } = await pool.query(
        `SELECT owner_email, storage_path, mime, filename
         FROM documents WHERE id = $1`,
        [id]
      )
      if (rows.length === 0) return res.status(404).json({ error: 'not found' })
      const doc = rows[0]
      const userEmail = req.user.email
      if (req.user.role !== 'admin' && userEmail !== doc.owner_email) {
        const allowed = await pool.query(
          'SELECT 1 FROM document_recipients WHERE doc_id = $1 AND email = $2',
          [id, userEmail]
        )
        if (allowed.rowCount === 0) return res.status(403).json({ error: 'forbidden' })
      }
      const storagePath = path.join(STORAGE_DIR, doc.storage_path)
      res.setHeader('Content-Type', doc.mime)
      res.setHeader('Content-Disposition', `attachment; filename="${doc.filename}"`)
      return res.sendFile(storagePath)
    } catch (e) {
      return res.status(404).json({ error: 'not found' })
    }
  } else {
    const data = readFileDb()
    const doc = data.docs.find(d => d.id === id)
    if (!doc) return res.status(404).json({ error: 'not found' })
    const userEmail = req.user.email
    if (req.user.role !== 'admin' && userEmail !== doc.owner_email) {
      if (!((doc.allowed || []).includes(userEmail))) {
        return res.status(403).json({ error: 'forbidden' })
      }
    }
    const storagePath = path.join(STORAGE_DIR, doc.storage_path)
    if (!fs.existsSync(storagePath)) return res.status(404).json({ error: 'file missing' })
    res.setHeader('Content-Type', doc.mime)
    res.setHeader('Content-Disposition', `attachment; filename="${doc.filename}"`)
    return res.sendFile(storagePath)
  }
})

// serve server public key so clients can verify signatures
app.get('/api/keys/public', (req, res) => {
  res.type('text').send(fs.readFileSync(PUB_KEY_PATH, 'utf8'))
})

// serve owner's public key via users table (for clients to fetch recipients' public keys)
app.get('/api/users/:email/publickey', async (req, res) => {
  const email = req.params.email
  if (usePostgres) {
    const { rows } = await pool.query(
      'SELECT public_key FROM users WHERE email = $1',
      [email]
    )
    if (rows.length === 0 || !rows[0].public_key) return res.status(404).json({ error: 'not found' })
    res.json({ publicKey: rows[0].public_key })
  } else {
    const data = readFileDb()
    const user = data.users.find(u => u.email === email)
    if (!user || !user.public_key) return res.status(404).json({ error: 'not found' })
    res.json({ publicKey: user.public_key })
  }
})

const PORT = process.env.PORT || 4000
;(async () => {
  await initDb()
  app.listen(PORT, () => {
    console.log('Backend listening on', PORT)
  })
})().catch(e => {
  console.error('Failed to start server:', e)
  process.exit(1)
})

process.on('SIGINT', async () => {
  if (pool) await pool.end()
  process.exit(0)
})
