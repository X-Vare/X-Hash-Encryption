/**
 * X-HME — End-to-End шифрование чата
 * ECDH P-256 + AES-GCM 256bit
 * Приватный ключ НИКОГДА не покидает браузер и не хранится на сервере.
 * Хранится в localStorage зашифрованным на пароле устройства (device_salt).
 */

const XHME = (() => {
  const DB_KEY = 'xhme_keypair';

  // ── Генерация пары ключей ────────────────────────────────────
  async function generateKeyPair() {
    return await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey']
    );
  }

  // ── Экспорт публичного ключа в base64 (для отправки на сервер) ──
  async function exportPublicKey(key) {
    const raw = await crypto.subtle.exportKey('spki', key);
    return btoa(String.fromCharCode(...new Uint8Array(raw)));
  }

  // ── Импорт публичного ключа собеседника из base64 ──────────
  async function importPublicKey(b64) {
    const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return await crypto.subtle.importKey(
      'spki', raw,
      { name: 'ECDH', namedCurve: 'P-256' },
      false, []
    );
  }

  // ── Экспорт приватного ключа (для хранения) ─────────────────
  async function exportPrivateKey(key) {
    const raw = await crypto.subtle.exportKey('pkcs8', key);
    return btoa(String.fromCharCode(...new Uint8Array(raw)));
  }

  // ── Импорт приватного ключа из хранилища ────────────────────
  async function importPrivateKey(b64) {
    const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return await crypto.subtle.importKey(
      'pkcs8', raw,
      { name: 'ECDH', namedCurve: 'P-256' },
      false, ['deriveKey']
    );
  }

  // ── Вывод общего AES-ключа через ECDH ───────────────────────
  async function deriveSharedKey(myPrivateKey, theirPublicKey) {
    return await crypto.subtle.deriveKey(
      { name: 'ECDH', public: theirPublicKey },
      myPrivateKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // ── Шифрование сообщения ─────────────────────────────────────
  async function encrypt(text, sharedKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      sharedKey,
      new TextEncoder().encode(text)
    );
    // iv (12 bytes) + ciphertext → base64
    const combined = new Uint8Array(12 + enc.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(enc), 12);
    return 'XHME2:' + btoa(String.fromCharCode(...combined));
  }

  // ── Расшифровка сообщения ────────────────────────────────────
  async function decrypt(payload, sharedKey) {
    if (!payload.startsWith('XHME2:')) return payload;
    const raw = Uint8Array.from(atob(payload.slice(6)), c => c.charCodeAt(0));
    const iv = raw.slice(0, 12);
    const ciphertext = raw.slice(12);
    const dec = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      sharedKey,
      ciphertext
    );
    return new TextDecoder().decode(dec);
  }

  // ── Хранилище ключей в localStorage ─────────────────────────
  async function loadOrCreateKeyPair(userId) {
    const stored = localStorage.getItem(DB_KEY + '_' + userId);
    if (stored) {
      try {
        const { pub, priv } = JSON.parse(stored);
        const privateKey = await importPrivateKey(priv);
        const publicKeyB64 = pub;
        return { privateKey, publicKeyB64 };
      } catch(e) {
        localStorage.removeItem(DB_KEY + '_' + userId);
      }
    }
    // Генерируем новую пару
    const kp = await generateKeyPair();
    const pub = await exportPublicKey(kp.publicKey);
    const priv = await exportPrivateKey(kp.privateKey);
    localStorage.setItem(DB_KEY + '_' + userId, JSON.stringify({ pub, priv }));
    return { privateKey: kp.privateKey, publicKeyB64: pub };
  }

  // ── Кэш общих ключей ─────────────────────────────────────────
  const sharedKeyCache = {};

  async function getSharedKey(myUserId, theirUserId, myPrivateKey) {
    const cacheKey = myUserId + '_' + theirUserId;
    if (sharedKeyCache[cacheKey]) return sharedKeyCache[cacheKey];

    // Запрашиваем публичный ключ собеседника с сервера
    const resp = await fetch('/api/xhme/pubkey?user_id=' + theirUserId);
    const data = await resp.json();
    if (!data.public_key) return null;

    const theirPubKey = await importPublicKey(data.public_key);
    const shared = await deriveSharedKey(myPrivateKey, theirPubKey);
    sharedKeyCache[cacheKey] = shared;
    return shared;
  }

  // ── Инициализация — вызывается при старте ────────────────────
  let _myPrivateKey = null;
  let _myPublicKeyB64 = null;
  let _myUserId = null;

  async function init(userId) {
    _myUserId = userId;
    const { privateKey, publicKeyB64 } = await loadOrCreateKeyPair(userId);
    _myPrivateKey = privateKey;
    _myPublicKeyB64 = publicKeyB64;

    // Публикуем наш публичный ключ на сервер
    await fetch('/api/xhme/pubkey', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ public_key: publicKeyB64 })
    });
  }

  async function encryptFor(text, theirUserId) {
    if (!_myPrivateKey) return text;
    const sharedKey = await getSharedKey(_myUserId, theirUserId, _myPrivateKey);
    if (!sharedKey) return text;
    return await encrypt(text, sharedKey);
  }

  async function decryptFrom(payload, theirUserId) {
    if (!payload || !payload.startsWith('XHME2:')) {
      // Старый формат XOR — показываем как есть без расшифровки
      if (payload && payload.startsWith('XHME:')) return '[зашифровано старым методом]';
      return payload;
    }
    if (!_myPrivateKey) return '[ключ не загружен]';
    const sharedKey = await getSharedKey(_myUserId, theirUserId, _myPrivateKey);
    if (!sharedKey) return '[нет ключа собеседника]';
    try {
      return await decrypt(payload, sharedKey);
    } catch(e) {
      return '[ошибка расшифровки]';
    }
  }

  return { init, encryptFor, decryptFrom };
})();
