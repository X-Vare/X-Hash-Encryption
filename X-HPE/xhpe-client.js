/**
 * X-HPE Client — Password hashing in browser
 * PBKDF2-SHA256 with 100,000 iterations.
 * The original password NEVER leaves the browser.
 */

/**
 * Hash password with PBKDF2.
 * @param {string} password - raw password from input
 * @param {string|null} saltHex - existing salt for login, null for registration
 * @returns {{ hash: string, salt: string }} hex-encoded hash and salt
 */
async function hashPasswordClient(password, saltHex = null) {
  const saltBytes = saltHex
    ? hexToBytes(saltHex)
    : crypto.getRandomValues(new Uint8Array(32));

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: saltBytes,
      iterations: 100000
    },
    keyMaterial,
    256
  );

  return {
    hash: bytesToHex(new Uint8Array(bits)),
    salt: bytesToHex(saltBytes)
  };
}

// Registration: generate new salt
// const { hash, salt } = await hashPasswordClient(password);
// Send hash + salt to server. Store salt as device_salt in DB.

// Login: reuse stored salt
// const { hash } = await hashPasswordClient(password, deviceSalt);
// Send hash to server for bcrypt verification.

function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.substr(i * 2, 2), 16);
  return arr;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
