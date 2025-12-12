Backend Express server (minimal)

Quick start (from repo root):

1. Change to the backend folder and install packages:

```powershell
cd backend
npm install
```

2. Start the server:

```powershell
npm run dev
```

Default server: http://localhost:4000

What it contains:

- SQLite database at `backend/data/db.sqlite` (created automatically)
- RSA server keypair at `backend/keys/` (generated on first run)
- Storage folder at `backend/storage/` for encrypted documents

Security notes:

- Passwords are hashed with bcrypt.
- Documents are encrypted using AES-256-GCM; the AES key is encrypted with the server RSA public key (hybrid encryption). The server holds the RSA private key and decrypts AES keys to serve files. This is a simple, self-contained approach for demo/prototyping.
- Metadata signatures: document metadata is signed with the server RSA private key; the public key is available at `/api/keys/public` so clients can verify signatures.

Database schema (auto-created): `users`, `docs`, `doc_allowed`.

Next steps (recommended):

- Run the backend behind TLS (nginx or similar) in production.
- Move private keys to a secure KMS or environment protected store.
- Consider encrypting user-sensitive fields and/or implementing per-user keypairs for end-to-end encryption if you need the server to be unable to decrypt documents.
