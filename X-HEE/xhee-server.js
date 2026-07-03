/**
 * X-HEE Server — Final HMAC layer
 * Step 2 of double-hash: HMAC-SHA256(clientHash, SERVER_SECRET)
 * SERVER_SECRET is stored in .env — never exposed to clients.
 */

const crypto = require('crypto');

/**
 * @param {string} clientEmailHash - SHA-256 hash from browser
 * @returns {string} finalHash - stored in database
 */
function hashEmail(clientEmailHash) {
  const secret = process.env.XHE_EMAIL_SECRET;
  if (!secret) throw new Error('XHE_EMAIL_SECRET not set in environment');
  return crypto.createHmac('sha256', secret).update(clientEmailHash).digest('hex');
}

module.exports = { hashEmail };

// Security properties:
// - Even with DB access + source code, attacker needs SERVER_SECRET to brute-force
// - Even with SERVER_SECRET, attacker still needs to brute-force SHA-256 layer
// - Changing SERVER_SECRET invalidates all stored hashes (full re-registration required)
