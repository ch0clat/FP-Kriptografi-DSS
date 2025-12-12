Backend Express server (MongoDB + file fallback)

This backend supports two modes:

- MongoDB mode (recommended): set the `MONGODB_URI` environment variable to point to your MongoDB Atlas or other MongoDB instance. Optionally set `MONGODB_DB` to choose the database name.
- File fallback (local JSON): if `MONGODB_URI` is not provided the backend will store data in `backend/data/db.json` and store files in `backend/storage/` (no native compilation required).

Quick start (from repo root):

1. Change to the backend folder and install packages:

```powershell
cd backend
npm install
```

2. Start the server:

```powershell
# With MongoDB (example using PowerShell):
$env:MONGODB_URI = 'your-mongodb-connection-string'
npm run dev

# Or without MongoDB (uses file fallback):
npm run dev
```

Default server: http://localhost:4000

What it contains:

- Data storage: MongoDB (if configured) or `backend/data/db.json` fallback.
- RSA server keypair at `backend/keys/` (generated on first run).
- Storage folder at `backend/storage/` for encrypted documents.

Security notes:

- Passwords are hashed with bcrypt.
- Documents are encrypted client-side (AES-GCM) and the AES key is stored encrypted per-recipient. The server stores encrypted blobs and per-recipient encrypted AES keys but does not decrypt AES keys in end-to-end mode.
- Metadata signatures: document metadata is signed with the server RSA private key; the public key is available at `/api/keys/public` so clients can verify signatures.

If you plan to use a remote database, create a MongoDB instance (for example MongoDB Atlas) and provide its connection string in `MONGODB_URI`.

For local development without native build toolchains, the file-based fallback allows you to run the backend without compiling native modules.
