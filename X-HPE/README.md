# X-HPE — X-Vare Hash Password Encryption

Zero-knowledge password protection. The original password **never leaves the browser**.

## How it works

```
Client:  PBKDF2-SHA256(password, randomSalt, 100_000 iterations)  →  clientHash + deviceSalt
Server:  bcrypt(clientHash + PEPPER, cost=12)                      →  storedHash (in DB)
```

- Password is hashed client-side with 100k PBKDF2 iterations before transmission
- Server adds pepper + bcrypt on top — double protection
- `deviceSalt` stored in DB to reproduce the same PBKDF2 hash on login

## Files
- `xhpe-client.js` — browser-side PBKDF2 hashing
- `xhpe-server.js` — server-side bcrypt + pepper
