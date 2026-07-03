# X-HEE — X-Vare Hash Email Encryption

Zero-knowledge email protection. The server **never** stores or sees the original email.

## How it works

```
Client:  SHA-256(email.toLowerCase() + PUBLIC_SALT)  →  clientHash
Server:  HMAC-SHA256(clientHash, SERVER_SECRET)       →  finalHash (stored in DB)
```

- Original email exists in memory only during verification code sending
- DB stores only the double hash — impossible to reverse
- Even if DB leaks, emails cannot be recovered

## Files
- `xhee-client.js` — browser-side hashing (SHA-256)
- `xhee-server.js` — server-side HMAC (Node.js)
