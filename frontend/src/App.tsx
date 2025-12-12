import { useCallback, useEffect, useState } from "react";
import type { FormEvent, ChangeEvent } from "react";
import "./App.css";
import { apiUrl, apiBase } from "./api";
import * as crypto from "./crypto";

type Role = "student" | "lecturer" | "admin";

type AuthSession = {
  token: string;
  email: string;
  role: Role;
};

type EncryptedPrivateKey = {
  salt: number[];
  iv: number[];
  data: string;
};

type StoredEncryptedKey = {
  email: string;
  payload: EncryptedPrivateKey;
};

type UploadedDoc = {
  id: string;
  title: string;
  verifyUrl: string;
  createdAt: string;
};

type VerifyResponse = {
  id: string;
  title: string;
  filename: string;
  mime: string;
  owner: { email: string };
  allowed: string[];
  created_at: string;
  signature?: string | null;
};

type UserSummary = {
  id: string;
  email: string;
  name: string;
  role: Role;
};

type MessageState = {
  kind: "info" | "success" | "warning" | "error";
  text: string;
};

const STORAGE_KEYS = {
  token: "dss_auth_token",
  encryptedKey: "dss_private_encrypted",
  unlockedKey: "dss_private_unlocked",
  publicKey: "dss_public_key",
  uploads: "dss_recent_uploads",
} as const;

const LEGACY_KEYS = {
  token: "auth_token",
  encryptedKey: "e2e_private",
  unlockedKey: "e2e_private_unlocked",
  publicKey: "e2e_public",
} as const;

const VERIFY_BASE = apiBase
  ? apiBase.replace(/\/+$/, "").replace(/\/api$/i, "")
  : "";

function decodeJwt(token: string): { email?: string; role?: Role } | null {
  try {
    const parts = token.split(".");
    if (parts.length < 2) return null;
    let payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    while (payload.length % 4 !== 0) payload += "=";
    const decoded = atob(payload);
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

async function encryptPrivateKeyPem(
  privateKeyPem: string,
  password: string
): Promise<EncryptedPrivateKey> {
  const encoder = new TextEncoder();
  const pwKey = await window.crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const derived = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 100_000,
      hash: "SHA-256",
    },
    pwKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    derived,
    encoder.encode(privateKeyPem)
  );
  return {
    salt: Array.from(salt),
    iv: Array.from(iv),
    data: crypto.abToBase64(encrypted),
  };
}

async function decryptPrivateKeyPem(
  payload: EncryptedPrivateKey,
  password: string
): Promise<string> {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const salt = new Uint8Array(payload.salt);
  const iv = new Uint8Array(payload.iv);
  const pwKey = await window.crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  const derived = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 100_000,
      hash: "SHA-256",
    },
    pwKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
  const encrypted = crypto.base64ToAb(payload.data);
  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    derived,
    encrypted
  );
  return decoder.decode(decrypted);
}

function readStoredToken(): string | null {
  const stored =
    localStorage.getItem(STORAGE_KEYS.token) ??
    localStorage.getItem(LEGACY_KEYS.token);
  return stored ?? null;
}

function persistToken(token: string) {
  localStorage.setItem(STORAGE_KEYS.token, token);
  localStorage.removeItem(LEGACY_KEYS.token);
}

function loadStoredEncryptedKey(email: string): EncryptedPrivateKey | null {
  const raw =
    localStorage.getItem(STORAGE_KEYS.encryptedKey) ??
    localStorage.getItem(LEGACY_KEYS.encryptedKey);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as StoredEncryptedKey;
    if (parsed.email !== email) return null;
    return parsed.payload;
  } catch {
    return null;
  }
}

function storeEncryptedKey(email: string, payload: EncryptedPrivateKey) {
  const value: StoredEncryptedKey = { email, payload };
  localStorage.setItem(STORAGE_KEYS.encryptedKey, JSON.stringify(value));
  localStorage.removeItem(LEGACY_KEYS.encryptedKey);
}

function loadStoredPublicKey(): string | null {
  return (
    localStorage.getItem(STORAGE_KEYS.publicKey) ??
    localStorage.getItem(LEGACY_KEYS.publicKey) ??
    null
  );
}

function storePublicKey(publicKeyPem: string) {
  localStorage.setItem(STORAGE_KEYS.publicKey, publicKeyPem);
  localStorage.removeItem(LEGACY_KEYS.publicKey);
}

function readStoredUploads(): UploadedDoc[] {
  const raw = localStorage.getItem(STORAGE_KEYS.uploads);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as UploadedDoc[];
    return parsed.map((doc) => ({
      ...doc,
      verifyUrl: resolveVerifyUrl(doc.id, doc.verifyUrl),
    }));
  } catch {
    return [];
  }
}

function persistUploads(docs: UploadedDoc[]) {
  const normalized = docs.map((doc) => ({
    ...doc,
    verifyUrl: resolveVerifyUrl(doc.id, doc.verifyUrl),
  }));
  localStorage.setItem(STORAGE_KEYS.uploads, JSON.stringify(normalized));
}

function clearUnlockedPrivateKey() {
  sessionStorage.removeItem(STORAGE_KEYS.unlockedKey);
  sessionStorage.removeItem(LEGACY_KEYS.unlockedKey);
}

function storeUnlockedPrivateKey(privateKeyPem: string) {
  sessionStorage.setItem(STORAGE_KEYS.unlockedKey, privateKeyPem);
  sessionStorage.removeItem(LEGACY_KEYS.unlockedKey);
}

function readUnlockedPrivateKey(): string | null {
  return (
    sessionStorage.getItem(STORAGE_KEYS.unlockedKey) ??
    sessionStorage.getItem(LEGACY_KEYS.unlockedKey) ??
    null
  );
}

function formatList(values: string[]): string {
  return values.join(", ");
}

function resolveVerifyUrl(docId: string, provided?: string | null): string {
  let targetId = docId;
  if (provided) {
    try {
      const origin =
        typeof window !== "undefined" && window.location
          ? window.location.origin
          : "http://localhost";
      const parsed = new URL(provided, origin);
      if (parsed.pathname.includes("/verify/")) {
        return parsed.toString();
      }
      const queryId = parsed.searchParams.get("verify");
      if (queryId) {
        targetId = queryId;
      }
    } catch {
      /* ignore malformed URLs */
    }
  }

  if (VERIFY_BASE) {
    const normalized = VERIFY_BASE.replace(/\/+$/, "");
    return `${normalized}/verify/${encodeURIComponent(targetId)}`;
  }

  if (typeof window !== "undefined" && window.location?.origin) {
    return `${window.location.origin}?verify=${encodeURIComponent(targetId)}`;
  }

  return `/verify/${encodeURIComponent(targetId)}`;
}

function App() {
  const [auth, setAuth] = useState<AuthSession | null>(() => {
    const token = readStoredToken();
    if (!token) return null;
    const payload = decodeJwt(token);
    if (!payload?.email) return null;
    return {
      token,
      email: payload.email,
      role: payload.role ?? "student",
    };
  });

  const [mode, setMode] = useState<"login" | "register">("login");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("student");
  const [authMessage, setAuthMessage] = useState<string | null>(null);
  const [keychainWarning, setKeychainWarning] = useState<string | null>(null);

  const [uploadTitle, setUploadTitle] = useState("");
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [allUsers, setAllUsers] = useState<UserSummary[]>([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [usersError, setUsersError] = useState<string | null>(null);
  const [recipientQuery, setRecipientQuery] = useState("");
  const [selectedRecipients, setSelectedRecipients] = useState<string[]>([]);
  const [uploadMessage, setUploadMessage] = useState<string | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [fileInputKey, setFileInputKey] = useState(0);
  const [recentDocs, setRecentDocs] = useState<UploadedDoc[]>(() =>
    readStoredUploads()
  );
  const [keyImportText, setKeyImportText] = useState("");
  const [isImportingKey, setIsImportingKey] = useState(false);
  const [keyBackupNotice, setKeyBackupNotice] = useState<MessageState | null>(
    null
  );
  const [dashboardView, setDashboardView] = useState<"home" | "profile">(
    "home"
  );

  useEffect(() => {
    persistUploads(recentDocs);
  }, [recentDocs]);
  useEffect(() => {
    if (!auth) {
      setKeyImportText("");
      setKeyBackupNotice(null);
      setDashboardView("home");
    }
  }, [auth]);

  const [verifyId, setVerifyId] = useState(() => {
    const url = new URL(window.location.href);
    return url.searchParams.get("verify") ?? "";
  });
  const [isVerifying, setIsVerifying] = useState(false);
  const [verifyMessage, setVerifyMessage] = useState<string | null>(null);
  const [verifyData, setVerifyData] = useState<VerifyResponse | null>(null);
  const [signatureStatus, setSignatureStatus] = useState<string | null>(null);
  const [signatureValid, setSignatureValid] = useState<boolean | null>(null);
  const [downloadMessage, setDownloadMessage] = useState<string | null>(null);
  const [isDownloading, setIsDownloading] = useState(false);

  const runVerification = useCallback(async (docId: string) => {
    const trimmed = docId.trim();
    if (!trimmed) {
      setVerifyMessage("Enter a document id");
      setVerifyData(null);
      setSignatureStatus(null);
      setSignatureValid(null);
      return;
    }

    setIsVerifying(true);
    setVerifyMessage(null);
    setSignatureStatus(null);
    setSignatureValid(null);
    setDownloadMessage(null);

    try {
      const resp = await fetch(
        apiUrl(`/api/docs/${encodeURIComponent(trimmed)}/verify`)
      );
      const text = await resp.text();
      let payload: any = {};
      if (text) {
        try {
          payload = JSON.parse(text);
        } catch {
          setVerifyMessage("Invalid JSON response from server");
          setVerifyData(null);
          return;
        }
      }

      if (!resp.ok) {
        setVerifyMessage(
          typeof payload.message === "string"
            ? payload.message
            : "Document not found"
        );
        setVerifyData(null);
        return;
      }

      setVerifyData(payload as VerifyResponse);

      if (payload.signature) {
        try {
          const keyResp = await fetch(apiUrl("/api/keys/public"));
          const serverPublicKey = await keyResp.text();
          if (!keyResp.ok || !serverPublicKey) {
            setSignatureStatus("Unable to load server public key");
            return;
          }
          const metadata = {
            id: payload.id,
            title: payload.title,
            filename: payload.filename,
            mime: payload.mime,
            owner: payload.owner,
            created_at: payload.created_at,
          };
          const ok = await crypto.verifySignature(
            serverPublicKey,
            payload.signature,
            metadata
          );
          setSignatureValid(ok);
          setSignatureStatus(
            ok
              ? "Signature verified by server key"
              : "Signature verification failed"
          );
        } catch (err) {
          setSignatureStatus("Signature verification error: " + String(err));
        }
      } else {
        setSignatureStatus("No signature stored for this document");
      }
    } catch (err) {
      setVerifyMessage(String(err));
      setVerifyData(null);
    } finally {
      setIsVerifying(false);
    }
  }, []);

  useEffect(() => {
    if (verifyId) {
      runVerification(verifyId).catch(() => undefined);
    }
  }, [runVerification, verifyId]);

  useEffect(() => {
    setSelectedRecipients((prev) =>
      prev.filter((emailValue) =>
        allUsers.some((user) => user.email === emailValue)
      )
    );
  }, [allUsers]);

  const fetchUserDirectory = useCallback(async (token: string) => {
    setUsersLoading(true);
    setUsersError(null);
    try {
      const resp = await fetch(apiUrl("/api/users/list"), {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!resp.ok) {
        const txt = await resp.text();
        let payload: any = {};
        if (txt) {
          try {
            payload = JSON.parse(txt);
          } catch {
            /* ignore parse error */
          }
        }
        throw new Error(
          payload.error || `Failed to load users (${resp.status})`
        );
      }
      const payload = (await resp.json()) as { users: UserSummary[] };
      setAllUsers(payload.users || []);
    } catch (err) {
      setUsersError(String(err));
      setAllUsers([]);
    } finally {
      setUsersLoading(false);
    }
  }, []);

  const buildBackupJson = useCallback(():
    | { json: string }
    | { error: string } => {
    if (!auth) {
      return { error: "Login to manage private key backups." };
    }
    const encrypted = loadStoredEncryptedKey(auth.email);
    if (!encrypted) {
      return {
        error:
          "No encrypted private key found on this device. Register or import one first.",
      };
    }
    const backup = {
      version: 1,
      email: auth.email,
      exportedAt: new Date().toISOString(),
      encryptedPrivateKey: encrypted,
      publicKeyPem: loadStoredPublicKey(),
    };
    return { json: JSON.stringify(backup, null, 2) };
  }, [auth]);

  const handleExportKey = useCallback(() => {
    const outcome = buildBackupJson();
    if ("error" in outcome) {
      setKeyBackupNotice({ kind: "warning", text: outcome.error });
      return;
    }

    const json = outcome.json;
    const blob = new Blob([json], { type: "application/json" });
    const safeEmail = auth?.email
      ? auth.email.replace(/[^a-z0-9]+/gi, "_")
      : "backup";
    const filename = `dss-key-backup-${safeEmail}-${Date.now()}.json`;
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    setKeyBackupNotice({
      kind: "success",
      text: "Encrypted private key downloaded. Keep the file in a safe place.",
    });
  }, [auth?.email, buildBackupJson]);

  const handleCopyBackup = useCallback(async () => {
    const outcome = buildBackupJson();
    if ("error" in outcome) {
      setKeyBackupNotice({ kind: "warning", text: outcome.error });
      return;
    }

    const json = outcome.json;
    try {
      if (!navigator.clipboard) {
        throw new Error("Clipboard API unavailable");
      }
      await navigator.clipboard.writeText(json);
      setKeyBackupNotice({
        kind: "success",
        text: "Backup JSON copied to clipboard.",
      });
    } catch (error) {
      setKeyImportText(json);
      setKeyBackupNotice({
        kind: "info",
        text: "Clipboard copy failed. Backup JSON has been placed in the restore field; copy it manually.",
      });
    }
  }, [buildBackupJson]);

  const handleImportFile = useCallback(
    (event: ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        setKeyImportText(String(reader.result ?? ""));
      };
      reader.onerror = () => {
        setKeyBackupNotice({
          kind: "error",
          text: `Failed to read backup file: ${
            reader.error?.message ?? "Unknown error"
          }`,
        });
      };
      reader.readAsText(file);
      event.target.value = "";
    },
    []
  );

  const handleImportKey = useCallback(async () => {
    if (!auth) {
      setKeyBackupNotice({
        kind: "warning",
        text: "Login to import a private key backup.",
      });
      return;
    }
    if (!keyImportText.trim()) {
      setKeyBackupNotice({
        kind: "warning",
        text: "Paste backup JSON or choose a backup file before importing.",
      });
      return;
    }

    setIsImportingKey(true);
    try {
      const parsed = JSON.parse(keyImportText) as any;
      const backupEmail: string =
        typeof parsed.email === "string" && parsed.email
          ? parsed.email
          : auth.email;
      if (backupEmail !== auth.email) {
        setKeyBackupNotice({
          kind: "warning",
          text: `Backup is for ${backupEmail}, but you are logged in as ${auth.email}.`,
        });
        return;
      }

      const candidate: EncryptedPrivateKey | undefined =
        parsed.encryptedPrivateKey ??
        parsed.payload ??
        parsed.encryptedKey?.payload ??
        parsed.encryptedKey;

      if (
        !candidate ||
        typeof candidate.data !== "string" ||
        !Array.isArray(candidate.salt) ||
        !Array.isArray(candidate.iv)
      ) {
        setKeyBackupNotice({
          kind: "error",
          text: "Backup JSON does not contain a valid encrypted private key.",
        });
        return;
      }

      storeEncryptedKey(auth.email, {
        data: candidate.data,
        salt: Array.from(candidate.salt),
        iv: Array.from(candidate.iv),
      });
      if (typeof parsed.publicKeyPem === "string" && parsed.publicKeyPem) {
        storePublicKey(parsed.publicKeyPem);
      }
      clearUnlockedPrivateKey();
      setKeyImportText("");
      setKeyBackupNotice({
        kind: "success",
        text: "Encrypted key imported. Log in with your password to unlock it.",
      });
    } catch (error) {
      setKeyBackupNotice({
        kind: "error",
        text: `Import failed: ${(error as Error).message ?? String(error)}`,
      });
    } finally {
      setIsImportingKey(false);
    }
  }, [auth, keyImportText]);

  useEffect(() => {
    if (auth) {
      fetchUserDirectory(auth.token).catch(() => undefined);
    }
  }, [auth, fetchUserDirectory]);

  const handleRegister = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      setAuthMessage(null);
      setKeychainWarning(null);

      if (!name || !email || !password) {
        setAuthMessage("Fill out name, email, and password");
        return;
      }

      try {
        setAuthMessage("Generating keys...");
        const keyPair = await crypto.generateRSAKeyPair();

        setAuthMessage("Registering...");
        const resp = await fetch(apiUrl("/api/register"), {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            name,
            email,
            password,
            role,
            publicKey: keyPair.publicKeyPem,
          }),
        });
        const text = await resp.text();
        let payload: any = {};
        if (text) {
          try {
            payload = JSON.parse(text);
          } catch {
            setAuthMessage("Server returned invalid JSON");
            return;
          }
        }

        if (!resp.ok) {
          setAuthMessage(payload.error ?? "Registration failed");
          return;
        }

        const encrypted = await encryptPrivateKeyPem(
          keyPair.privateKeyPem,
          password
        );
        storeEncryptedKey(email, encrypted);
        storeUnlockedPrivateKey(keyPair.privateKeyPem);
        storePublicKey(keyPair.publicKeyPem);

        const token: string = payload.token;
        persistToken(token);
        const decoded = decodeJwt(token);
        const session: AuthSession = {
          token,
          email: decoded?.email ?? email,
          role: decoded?.role ?? role,
        };
        setAuth(session);
        setAuthMessage("Registration successful. You are now logged in.");
        setName("");
        setPassword("");
        fetchUserDirectory(token).catch(() => undefined);
      } catch (err) {
        setAuthMessage("Registration failed: " + String(err));
      }
    },
    [email, fetchUserDirectory, name, password, role]
  );

  const handleLogin = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      setAuthMessage(null);
      setKeychainWarning(null);

      if (!email || !password) {
        setAuthMessage("Enter email and password");
        return;
      }

      try {
        const resp = await fetch(apiUrl("/api/login"), {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ email, password }),
        });
        const text = await resp.text();
        let payload: any = {};
        if (text) {
          try {
            payload = JSON.parse(text);
          } catch {
            setAuthMessage("Server returned invalid JSON");
            return;
          }
        }
        if (!resp.ok) {
          setAuthMessage(payload.error ?? "Login failed");
          return;
        }

        const token: string = payload.token;
        const decoded = decodeJwt(token);
        const accountEmail = decoded?.email ?? email;

        const encrypted = loadStoredEncryptedKey(accountEmail);
        if (encrypted) {
          try {
            const privateKeyPem = await decryptPrivateKeyPem(
              encrypted,
              password
            );
            storeUnlockedPrivateKey(privateKeyPem);
          } catch {
            setAuthMessage(
              "Incorrect password for the stored private key on this device"
            );
            return;
          }
        } else {
          setKeychainWarning(
            "No encrypted private key found on this device. Uploading encrypted files will be disabled until you register again here."
          );
          clearUnlockedPrivateKey();
        }

        persistToken(token);
        const session: AuthSession = {
          token,
          email: accountEmail,
          role: decoded?.role ?? "student",
        };
        setAuth(session);
        setDashboardView("home");
        setAuthMessage("Login successful");
        setPassword("");
        fetchUserDirectory(token).catch(() => undefined);
      } catch (err) {
        setAuthMessage("Login failed: " + String(err));
      }
    },
    [email, fetchUserDirectory, password]
  );

  const handleLogout = useCallback(() => {
    setAuth(null);
    clearUnlockedPrivateKey();
    localStorage.removeItem(STORAGE_KEYS.token);
    localStorage.removeItem(LEGACY_KEYS.token);
    setMode("login");
    setAuthMessage(null);
    setKeychainWarning(null);
    setAllUsers([]);
    setSelectedRecipients([]);
    setRecipientQuery("");
    setKeyImportText("");
    setKeyBackupNotice(null);
    setDashboardView("home");
  }, []);

  const handleUploadSubmit = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      setUploadMessage(null);

      if (!auth) {
        setUploadMessage("Login first");
        return;
      }
      if (!uploadFile) {
        setUploadMessage("Select a file");
        return;
      }

      const privateKeyPem = readUnlockedPrivateKey();
      if (!privateKeyPem) {
        setUploadMessage(
          "Private key is locked. Log in again to unlock it on this device."
        );
        return;
      }

      const allowedList = Array.from(
        new Set(
          selectedRecipients.filter((recipient) =>
            allUsers.some((user) => user.email === recipient)
          )
        )
      );

      const recipients = Array.from(new Set([auth.email, ...allowedList]));

      setIsUploading(true);
      try {
        const fileBuffer = await uploadFile.arrayBuffer();
        const aesKeyRaw = await crypto.generateAesKeyRaw();
        const encryptedPayloadB64 = await crypto.aesGcmEncryptRaw(
          aesKeyRaw,
          fileBuffer
        );
        const encryptedBuffer = crypto.base64ToAb(encryptedPayloadB64);
        const encryptedBlob = new Blob([new Uint8Array(encryptedBuffer)], {
          type: uploadFile.type || "application/octet-stream",
        });

        const keysRecord: Record<string, string> = {};
        const missingKeys: string[] = [];

        for (const recipient of recipients) {
          let publicKeyPem: string | null = null;
          if (recipient === auth.email) {
            publicKeyPem = loadStoredPublicKey();
          }
          if (!publicKeyPem) {
            try {
              const resp = await fetch(
                apiUrl(`/api/users/${encodeURIComponent(recipient)}/publickey`)
              );
              if (resp.ok) {
                const txt = await resp.text();
                if (txt) {
                  try {
                    const parsed = JSON.parse(txt);
                    if (parsed.publicKey) {
                      publicKeyPem = parsed.publicKey as string;
                      if (recipient === auth.email) {
                        storePublicKey(publicKeyPem);
                      }
                    }
                  } catch {
                    // ignore parse errors and treat as missing key
                  }
                }
              }
            } catch {
              // ignored; if fetch fails we will treat as missing
            }
          }

          if (!publicKeyPem) {
            missingKeys.push(recipient);
            continue;
          }

          const encryptedKey = await crypto.rsaEncryptWithPem(
            publicKeyPem,
            aesKeyRaw
          );
          keysRecord[recipient] = encryptedKey;
        }

        if (!keysRecord[auth.email]) {
          setUploadMessage(
            "Could not locate your public key. Re-register on this device."
          );
          return;
        }

        if (missingKeys.length > 0) {
          setUploadMessage(
            `Missing public keys for: ${formatList(missingKeys)}`
          );
          return;
        }

        const form = new FormData();
        form.append("file", encryptedBlob, uploadFile.name);
        form.append("title", uploadTitle || uploadFile.name);
        form.append(
          "allowed",
          JSON.stringify(
            recipients.filter((recipient) => recipient !== auth.email)
          )
        );
        form.append("keys", JSON.stringify(keysRecord));

        const resp = await fetch(apiUrl("/api/docs"), {
          method: "POST",
          body: form,
          headers: { Authorization: `Bearer ${auth.token}` },
        });
        const text = await resp.text();
        let payload: any = {};
        if (text) {
          try {
            payload = JSON.parse(text);
          } catch {
            setUploadMessage("Server returned invalid JSON");
            return;
          }
        }

        if (!resp.ok) {
          setUploadMessage(payload.error ?? "Upload failed");
          return;
        }

        const docId = payload.id as string;
        const verifyUrl = resolveVerifyUrl(docId, payload.verifyUrl);
        const createdAt = new Date().toISOString();
        const record: UploadedDoc = {
          id: docId,
          title: uploadTitle || uploadFile.name,
          verifyUrl,
          createdAt,
        };
        setRecentDocs((prev) => [record, ...prev].slice(0, 5));
        setUploadMessage(`Upload complete. Document id: ${docId}`);
        setUploadTitle("");
        setUploadFile(null);
        setSelectedRecipients([]);
        setRecipientQuery("");
        setFileInputKey((key) => key + 1);
      } catch (err) {
        setUploadMessage("Upload failed: " + String(err));
      } finally {
        setIsUploading(false);
      }
    },
    [allUsers, auth, selectedRecipients, uploadFile, uploadTitle]
  );

  const handleDownload = useCallback(async () => {
    if (!auth) {
      setDownloadMessage("Login to download");
      return;
    }
    if (!verifyData) {
      setDownloadMessage("Load a document first");
      return;
    }

    const privateKeyPem = readUnlockedPrivateKey();
    if (!privateKeyPem) {
      setDownloadMessage(
        "Private key unavailable in this session. Log in again to unlock it."
      );
      return;
    }

    setIsDownloading(true);
    setDownloadMessage(null);
    try {
      const keyResp = await fetch(apiUrl(`/api/docs/${verifyData.id}/key`), {
        headers: { Authorization: `Bearer ${auth.token}` },
      });
      const keyText = await keyResp.text();
      let keyPayload: any = {};
      if (keyText) {
        try {
          keyPayload = JSON.parse(keyText);
        } catch {
          setDownloadMessage("Invalid key response from server");
          return;
        }
      }
      if (!keyResp.ok) {
        setDownloadMessage(keyPayload.error ?? "No key available for you");
        return;
      }

      const aesKeyEncrypted = keyPayload.aesKeyEncrypted as string;
      const aesKeyRaw = await crypto.rsaDecryptWithPem(
        privateKeyPem,
        aesKeyEncrypted
      );

      const blobResp = await fetch(apiUrl(`/api/docs/${verifyData.id}/blob`), {
        headers: { Authorization: `Bearer ${auth.token}` },
      });
      if (!blobResp.ok) {
        setDownloadMessage("Unable to fetch encrypted blob");
        return;
      }

      const encryptedBuffer = await blobResp.arrayBuffer();
      const encryptedPayloadB64 = crypto.abToBase64(encryptedBuffer);
      const decrypted = await crypto.aesGcmDecryptRaw(
        aesKeyRaw,
        encryptedPayloadB64
      );
      const outBlob = new Blob([new Uint8Array(decrypted)], {
        type: verifyData.mime || "application/octet-stream",
      });
      const url = URL.createObjectURL(outBlob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = verifyData.filename || "document.bin";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      setDownloadMessage("File decrypted and downloaded");
    } catch (err) {
      setDownloadMessage("Download failed: " + String(err));
    } finally {
      setIsDownloading(false);
    }
  }, [auth, verifyData]);

  const authSection = (
    <section className="card auth-card">
      <div className="auth-toggle">
        <button
          className={mode === "login" ? "active" : ""}
          onClick={() => {
            setMode("login");
            setAuthMessage(null);
          }}
        >
          Login
        </button>
        <button
          className={mode === "register" ? "active" : ""}
          onClick={() => {
            setMode("register");
            setAuthMessage(null);
          }}
        >
          Register
        </button>
      </div>

      {mode === "login" ? (
        <form onSubmit={handleLogin} className="form">
          <label>Email</label>
          <input
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            autoComplete="username"
          />
          <label>Password</label>
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
          />
          <button type="submit">Sign in</button>
        </form>
      ) : (
        <form onSubmit={handleRegister} className="form">
          <label>Name</label>
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            autoComplete="name"
          />
          <label>Email</label>
          <input
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            autoComplete="username"
          />
          <label>Password</label>
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="new-password"
          />
          <label>Role</label>
          <select
            value={role}
            onChange={(event) => setRole(event.target.value as Role)}
          >
            <option value="student">Student</option>
            <option value="lecturer">Lecturer</option>
          </select>
          <button type="submit">Create account</button>
        </form>
      )}

      {authMessage && <p className="message info">{authMessage}</p>}
      {keychainWarning && <p className="message warning">{keychainWarning}</p>}
    </section>
  );

  const dashboard = auth ? (
    <>
      <div className="dashboard-nav">
        <button
          type="button"
          className={dashboardView === "home" ? "active" : ""}
          onClick={() => setDashboardView("home")}
        >
          Workspace
        </button>
        <button
          type="button"
          className={dashboardView === "profile" ? "active" : ""}
          onClick={() => setDashboardView("profile")}
        >
          Profile
        </button>
      </div>

      {dashboardView === "home" ? (
        <>
          <section className="card">
            <header className="card-header">
              <div>
                <h2>Upload encrypted document</h2>
                <p>
                  Files are encrypted client-side; only recipients with private
                  keys can decrypt.
                </p>
              </div>
              <button className="secondary" onClick={handleLogout}>
                Logout
              </button>
            </header>
            <form onSubmit={handleUploadSubmit} className="form">
              <label>Title</label>
              <input
                value={uploadTitle}
                onChange={(event) => setUploadTitle(event.target.value)}
                placeholder="Optional display title"
              />
              <label>File</label>
              <input
                key={fileInputKey}
                type="file"
                onChange={(event) =>
                  setUploadFile(event.target.files?.[0] ?? null)
                }
              />
              <label>Share with</label>
              <input
                value={recipientQuery}
                onChange={(event) => setRecipientQuery(event.target.value)}
                placeholder="Search users by name or email"
              />
              <div className="recipient-picker">
                {usersLoading ? (
                  <p className="muted">Loading users…</p>
                ) : usersError ? (
                  <p className="message warning">{usersError}</p>
                ) : allUsers.length === 0 ? (
                  <p className="muted">No users found.</p>
                ) : (
                  <ul>
                    {allUsers
                      .filter((user) => user.email !== auth.email)
                      .filter((user) => {
                        if (!recipientQuery.trim()) return true;
                        const q = recipientQuery.trim().toLowerCase();
                        return (
                          user.email.toLowerCase().includes(q) ||
                          (user.name || "").toLowerCase().includes(q)
                        );
                      })
                      .map((user) => {
                        const checked = selectedRecipients.includes(user.email);
                        return (
                          <li key={user.id}>
                            <label>
                              <input
                                type="checkbox"
                                checked={checked}
                                onChange={() => {
                                  setSelectedRecipients((prev) =>
                                    checked
                                      ? prev.filter(
                                          (email) => email !== user.email
                                        )
                                      : [...prev, user.email]
                                  );
                                }}
                              />
                              <span>
                                {user.name || user.email}
                                <span className="recipient-meta">
                                  {user.email}
                                </span>
                              </span>
                            </label>
                          </li>
                        );
                      })}
                  </ul>
                )}
              </div>
              {selectedRecipients.length > 0 && (
                <div className="recipient-chips">
                  {selectedRecipients.map((emailValue) => (
                    <span key={emailValue} className="chip">
                      {emailValue}
                      <button
                        type="button"
                        onClick={() =>
                          setSelectedRecipients((prev) =>
                            prev.filter((entry) => entry !== emailValue)
                          )
                        }
                      >
                        ×
                      </button>
                    </span>
                  ))}
                </div>
              )}
              <button type="submit" disabled={isUploading}>
                {isUploading ? "Uploading..." : "Upload"}
              </button>
            </form>
            {uploadMessage && <p className="message info">{uploadMessage}</p>}
          </section>

          <section className="card">
            <header className="card-header">
              <div>
                <h2>Verify or download</h2>
                <p>Paste a document id or use a verification link.</p>
              </div>
            </header>
            <form
              onSubmit={(event) => {
                event.preventDefault();
                runVerification(verifyId).catch(() => undefined);
              }}
              className="form inline"
            >
              <input
                value={verifyId}
                onChange={(event) => setVerifyId(event.target.value)}
                placeholder="Document id"
              />
              <button type="submit" disabled={isVerifying}>
                {isVerifying ? "Checking..." : "Verify"}
              </button>
            </form>
            {verifyMessage && (
              <p className="message warning">{verifyMessage}</p>
            )}
            {verifyData && (
              <div className="verify-details">
                <dl>
                  <div>
                    <dt>Title</dt>
                    <dd>{verifyData.title}</dd>
                  </div>
                  <div>
                    <dt>Owner</dt>
                    <dd>{verifyData.owner.email}</dd>
                  </div>
                  <div>
                    <dt>Allowed</dt>
                    <dd>
                      {verifyData.allowed.length > 0
                        ? formatList(verifyData.allowed)
                        : "(none)"}
                    </dd>
                  </div>
                  <div>
                    <dt>Created</dt>
                    <dd>{new Date(verifyData.created_at).toLocaleString()}</dd>
                  </div>
                </dl>
                {signatureStatus && (
                  <p
                    className={
                      signatureValid === false
                        ? "message error"
                        : signatureValid
                        ? "message success"
                        : "message info"
                    }
                  >
                    {signatureValid === true
                      ? "✔ "
                      : signatureValid === false
                      ? "✖ "
                      : ""}
                    {signatureStatus}
                  </p>
                )}
                <button
                  className="secondary"
                  onClick={() => {
                    if (navigator.clipboard) {
                      navigator.clipboard
                        .writeText(
                          `${window.location.origin}?verify=${verifyData.id}`
                        )
                        .catch(() => undefined);
                    }
                  }}
                >
                  Copy verification link
                </button>
                <button
                  className="primary"
                  onClick={() => handleDownload().catch(() => undefined)}
                  disabled={isDownloading}
                >
                  {isDownloading ? "Decrypting..." : "Download"}
                </button>
                {downloadMessage && (
                  <p className="message info">{downloadMessage}</p>
                )}
              </div>
            )}
          </section>

          <section className="card">
            <header className="card-header">
              <div>
                <h2>Recent uploads (local)</h2>
                <p>
                  These entries live only in this browser for quick reference.
                </p>
              </div>
            </header>
            {recentDocs.length === 0 ? (
              <p className="muted">No uploads yet.</p>
            ) : (
              <table className="recent-table">
                <thead>
                  <tr>
                    <th>Title</th>
                    <th>Document id</th>
                    <th>Created</th>
                    <th>Link</th>
                  </tr>
                </thead>
                <tbody>
                  {recentDocs.map((doc) => (
                    <tr key={doc.id}>
                      <td>{doc.title}</td>
                      <td className="mono">{doc.id}</td>
                      <td>{new Date(doc.createdAt).toLocaleString()}</td>
                      <td>
                        <a
                          href={doc.verifyUrl}
                          target="_blank"
                          rel="noreferrer"
                        >
                          Open
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        </>
      ) : (
        <>
          <section className="card">
            <header className="card-header">
              <div>
                <h2>Account</h2>
                <p>View your session details and manage access.</p>
              </div>
              <button className="secondary" onClick={handleLogout}>
                Logout
              </button>
            </header>
            <dl className="profile-summary">
              <div>
                <dt>Email</dt>
                <dd>{auth.email}</dd>
              </div>
              <div>
                <dt>Role</dt>
                <dd>{auth.role}</dd>
              </div>
            </dl>
          </section>

          <section className="card">
            <header className="card-header">
              <div>
                <h2>Private key backup</h2>
                <p>
                  Export the encrypted private key on this device or restore one
                  you previously saved.
                </p>
              </div>
            </header>
            <div className="backup-panel">
              <div className="button-row">
                <button
                  type="button"
                  className="primary"
                  onClick={handleExportKey}
                >
                  Download backup file
                </button>
                <button
                  type="button"
                  className="secondary"
                  onClick={() => handleCopyBackup().catch(() => undefined)}
                >
                  Copy backup JSON
                </button>
              </div>
              <div className="import-controls">
                <label className="file-picker">
                  <span>Restore from file</span>
                  <input
                    type="file"
                    accept="application/json"
                    onChange={handleImportFile}
                  />
                </label>
                <label>Restore from pasted JSON</label>
                <textarea
                  value={keyImportText}
                  onChange={(event) => setKeyImportText(event.target.value)}
                  placeholder="Paste encrypted backup JSON here"
                  rows={5}
                />
                <button
                  type="button"
                  className="primary"
                  onClick={() => handleImportKey().catch(() => undefined)}
                  disabled={isImportingKey}
                >
                  {isImportingKey ? "Importing..." : "Import backup"}
                </button>
              </div>
              {keyBackupNotice && (
                <p className={`message ${keyBackupNotice.kind}`}>
                  {keyBackupNotice.text}
                </p>
              )}
            </div>
          </section>
        </>
      )}
    </>
  ) : null;

  return (
    <div className="app">
      <header className="topbar">
        <div className="logo">Secure Document Safe</div>
        {auth && (
          <div className="user-chip">
            <span>{auth.email}</span>
            <span className="role">{auth.role}</span>
          </div>
        )}
      </header>
      <main className="content">{auth ? dashboard : authSection}</main>
    </div>
  );
}

export default App;
