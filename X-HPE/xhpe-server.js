/**
 * X-HPE Server — bcrypt + pepper layer
 * Receives already-hashed password from client (PBKDF2).
 * Adds pepper + bcrypt on top.
 */

const bcrypt = require('bcrypt');

/**
 * Hash the client-side PBKDF2 hash with pepper + bcrypt.
 * @param {string} clientHash - hex string from browser PBKDF2
 * @returns {string} bcrypt hash for storage
 */
async function hashPassword(clientHash) {
  const pepper = process.env.XHE_PEPPER;
  if (!pepper) throw new Error('XHE_PEPPER not set in environment');
  return await bcrypt.hash(clientHash + pepper, 12);
}

/**
 * Verify login attempt.
 * @param {string} clientHash - PBKDF2 hash from browser (using stored device_salt)
 * @param {string} storedHash - bcrypt hash from DB
 */
async function verifyPassword(clientHash, storedHash) {
  const pepper = process.env.XHE_PEPPER;
  if (!pepper) throw new Error('XHE_PEPPER not set in environment');
  return await bcrypt.compare(clientHash + pepper, storedHash);
}

module.exports = { hashPassword, verifyPassword };
