/**
 * X-HME Server API — minimal routes for key exchange
 * The server only stores public keys and ciphertext.
 * It CANNOT decrypt any messages.
 *
 * Required DB table:
 * CREATE TABLE xhme_keys (
 *   user_id INT PRIMARY KEY,
 *   public_key TEXT NOT NULL,
 *   updated_at DATETIME DEFAULT NOW()
 * );
 */

// Express router example (adapt to your framework)

// Store/update own public key
// POST /api/xhme/pubkey  { public_key: "base64..." }
async function handleStoreKey(userId, publicKey, db) {
  await db.query(
    'INSERT INTO xhme_keys (user_id, public_key, updated_at) VALUES (?, ?, NOW()) ON DUPLICATE KEY UPDATE public_key = ?, updated_at = NOW()',
    [userId, publicKey, publicKey]
  );
  return { success: true };
}

// Get peer's public key
// GET /api/xhme/pubkey?user_id=N
async function handleGetKey(targetUserId, db) {
  const [rows] = await db.query('SELECT public_key FROM xhme_keys WHERE user_id = ?', [targetUserId]);
  return { public_key: rows[0]?.public_key || null };
}

module.exports = { handleStoreKey, handleGetKey };
