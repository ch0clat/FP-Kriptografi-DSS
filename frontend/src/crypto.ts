// Browser crypto helpers for RSA key generation, AES-GCM encryption, and PEM import/export

// Utilities to convert between ArrayBuffer and base64
export function abToBase64(buf: ArrayBuffer) {
  const bytes = new Uint8Array(buf)
  let binary = ''
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i])
  return btoa(binary)
}

export function base64ToAb(b64: string) {
  const binary = atob(b64)
  const len = binary.length
  const bytes = new Uint8Array(len)
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i)
  return bytes.buffer
}

export async function generateRSAKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt']
  )
  const pub = await window.crypto.subtle.exportKey('spki', keyPair.publicKey)
  const priv = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
  const pubPem = `-----BEGIN PUBLIC KEY-----\n${abToBase64(pub)}\n-----END PUBLIC KEY-----`
  const privPem = `-----BEGIN PRIVATE KEY-----\n${abToBase64(priv)}\n-----END PRIVATE KEY-----`
  return { publicKeyPem: pubPem, privateKeyPem: privPem }
}

export async function importPublicKeyFromPem(pem: string) {
  const b64 = pem.replace(/-----.*?-----/g, '').replace(/\s+/g, '')
  const ab = base64ToAb(b64)
  return await window.crypto.subtle.importKey('spki', ab, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt'])
}

export async function importPrivateKeyFromPem(pem: string) {
  const b64 = pem.replace(/-----.*?-----/g, '').replace(/\s+/g, '')
  const ab = base64ToAb(b64)
  return await window.crypto.subtle.importKey('pkcs8', ab, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt'])
}

export async function rsaEncryptWithPem(publicKeyPem: string, data: ArrayBuffer) {
  const key = await importPublicKeyFromPem(publicKeyPem)
  const encrypted = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, data)
  return abToBase64(encrypted)
}

export async function rsaDecryptWithPem(privateKeyPem: string, b64data: string) {
  const key = await importPrivateKeyFromPem(privateKeyPem)
  const ab = base64ToAb(b64data)
  const decrypted = await window.crypto.subtle.decrypt({ name: 'RSA-OAEP' }, key, ab)
  return decrypted
}

export async function generateAesKeyRaw() {
  const key = await window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
  const raw = await window.crypto.subtle.exportKey('raw', key)
  return raw // ArrayBuffer
}

export async function aesGcmEncryptRaw(keyRaw: ArrayBuffer, data: ArrayBuffer) {
  const key = await window.crypto.subtle.importKey('raw', keyRaw, { name: 'AES-GCM' }, false, ['encrypt'])
  const iv = window.crypto.getRandomValues(new Uint8Array(12))
  const ct = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data)
  // return iv + ct as base64
  const ivBuf = iv.buffer
  const combined = new Uint8Array(ivBuf.byteLength + ct.byteLength)
  combined.set(new Uint8Array(ivBuf), 0)
  combined.set(new Uint8Array(ct), ivBuf.byteLength)
  return abToBase64(combined.buffer)
}

export async function aesGcmDecryptRaw(keyRaw: ArrayBuffer, b64payload: string) {
  const payload = base64ToAb(b64payload)
  const payloadBytes = new Uint8Array(payload)
  const iv = payloadBytes.slice(0, 12)
  const ct = payloadBytes.slice(12).buffer
  const key = await window.crypto.subtle.importKey('raw', keyRaw, { name: 'AES-GCM' }, false, ['decrypt'])
  const decrypted = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct)
  return decrypted // ArrayBuffer
}

// sign/verify using RSA-PSS (owner's keypair) for metadata signatures
export async function importPrivateKeyForSigning(pem: string) {
  const b64 = pem.replace(/-----.*?-----/g, '').replace(/\s+/g, '')
  const ab = base64ToAb(b64)
  return await window.crypto.subtle.importKey('pkcs8', ab, { name: 'RSA-PSS', hash: 'SHA-256' }, true, ['sign'])
}

export async function signDataWithPrivateKey(
  privateKeyPem: string,
  data: unknown
) {
  const key = await importPrivateKeyForSigning(privateKeyPem)
  const enc = new TextEncoder().encode(JSON.stringify(data))
  const sig = await window.crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, key, enc)
  return abToBase64(sig)
}

export async function importPublicKeyForVerify(pem: string) {
  const b64 = pem.replace(/-----.*?-----/g, '').replace(/\s+/g, '')
  const ab = base64ToAb(b64)
  return await window.crypto.subtle.importKey('spki', ab, { name: 'RSA-PSS', hash: 'SHA-256' }, true, ['verify'])
}

export async function verifySignature(
  publicKeyPem: string,
  signatureB64: string,
  data: unknown
) {
  const key = await importPublicKeyForVerify(publicKeyPem)
  const enc = new TextEncoder().encode(JSON.stringify(data))
  const sig = base64ToAb(signatureB64)
  return await window.crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, key, sig, enc)
}
