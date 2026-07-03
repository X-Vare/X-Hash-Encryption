# X-HME — X-Vare Hash Message Encryption

End-to-end encrypted chat. Messages are encrypted client-side using ECDH P-256 + AES-GCM-256.
The server stores only ciphertext — it **cannot** read messages.

## How it works

```
Alice generates: ECDH P-256 keypair  (private key stored in localStorage only)
Bob   generates: ECDH P-256 keypair  (private key stored in localStorage only)

Key exchange:
  Alice publishes pubKey_A → server stores it
  Bob   publishes pubKey_B → server stores it

Shared secret (computed client-side, never sent to server):
  Alice: ECDH(privKey_A, pubKey_B) → sharedSecret
  Bob:   ECDH(privKey_B, pubKey_A) → sharedSecret  (same result)

Encryption:
  AES-GCM-256(message, sharedSecret, randomIV)

Format stored in DB:
  XHME2:<base64(IV[12] + ciphertext)>
```

## Security properties
- Private keys never leave the device (localStorage)
- Server cannot decrypt messages even with full DB access
- Each message has unique random IV (nonce)
- Compromise of one device does not affect other conversations (no shared secret reuse across pairs)

## Files
- `xhme-crypto.js` — complete browser implementation (ECDH + AES-GCM)
- `xhme-server-api.js` — minimal server routes (store/retrieve public keys + ciphertext only)

## Server API required
- `POST /api/xhme/pubkey` — store user's public key
- `GET  /api/xhme/pubkey?user_id=N` — retrieve peer's public key
