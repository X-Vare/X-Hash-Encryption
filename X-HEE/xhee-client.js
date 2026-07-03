/**
 * X-HEE Client — Email hashing in browser
 * Step 1 of double-hash: SHA-256(email + PUBLIC_SALT)
 * The original email NEVER leaves the browser.
 */

const XHEE_PUBLIC_SALT = 'xvare-xhee-public-salt-v1';

async function hashEmailClient(email) {
  const input = email.toLowerCase().trim() + XHEE_PUBLIC_SALT;
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Usage:
// const clientHash = await hashEmailClient('user@example.com');
// Send clientHash to server — original email stays in browser only
