# X-HE — X-Vare Hash Encryption System

A suite of zero-knowledge cryptographic protocols for the X-Vare ecosystem.

| Module | Purpose | Algorithm |
|--------|---------|-----------|
| **X-HEE** | Email protection | SHA-256 (client) + HMAC-SHA256 (server) |
| **X-HPE** | Password protection | PBKDF2-SHA256 100k iter (client) + bcrypt+pepper (server) |
| **X-HME** | Message E2E encryption | ECDH P-256 + AES-GCM-256 (client only) |

## Core principle

> The server never receives sensitive data in plaintext.
> All cryptographic operations happen in the browser before transmission.

## Modules

- [`X-HEE/`](./X-HEE) — Email hashing
- [`X-HPE/`](./X-HPE) — Password hashing  
- [`X-HME/`](./X-HME) — End-to-end message encryption

## License

MIT — X-Vare Ecosystem
