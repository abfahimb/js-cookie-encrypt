# JS-cookie-encrypt (Secure & Protected by Private Keys)

**JS-cookie-encrypt** is a lightweight, high-performance JavaScript/TypeScript package designed to securely manage data in browser cookies using advanced encryption techniques. This package ensures that sensitive data stored in cookies is encrypted and protected, providing a higher level of security for client-side storage.

It offers flexible configurations supporting standard cookie attributes (path, domain, expires, sameSite, secure), and introduces modern cryptographic standards, change subscriptions, environment fallbacks, and precise deep type-safe path manipulations.

```
// Example of how the raw cookie appears in the browser:
gcm:aGVsbG8gd29ybGQ...  (AES-GCM, recommended)
rc4:UHzDpCrDicOQd1XC...  (RC4 legacy)
```

---

## Key Features

* **AES-GCM 256-bit (Recommended)**: Native asynchronous authenticated encryption via the browser's Web Cryptography API (`SubtleCrypto`). Use this in production.
* **Legacy Synchronous Ciphers (RC4 / XOR)**: Available for environments that cannot use async APIs. Not recommended for new projects — RC4 and XOR are weak ciphers. A warning is logged when they are used.
* **Enterprise Key Rotation**: Pass an array of keys in `privateKey`. The first key encrypts; the rest are fallback decryption keys. Cookies are automatically re-encrypted with the new primary key on read.
* **All Four Change Events**: Subscribe to `set`, `update`, `delete`, and `clear` events in real-time. Each method fires the correct event type.
* **SSR-Friendly & Incognito Fallback**: Automatically falls back to an in-memory cache when running server-side (Next.js/Nuxt) or when cookies are blocked.
* **Deep Nested Path Operations**: Retrieve, set, update, or delete deep nested values (`user.preferences.theme`) with full TypeScript type inference.
* **Cookie Size Warnings**: Warns if a cookie payload exceeds the standard 4KB browser limit.
* **Input Validation**: Throws on empty `storageKey` or `privateKey` at construction time.
* **Regex-Injection Safe**: Cookie names are escaped before use in regex matching.
* **URL-Encoded Storage**: Cookie names and values are `encodeURIComponent`-encoded on write and decoded on read.

---

## Table of Contents

* [Installation](#installation)
* [Basic Usage (Synchronous)](#basic-usage-synchronous)
* [Advanced Features](#advanced-features)
  * [1. Asynchronous AES-GCM 256-bit (Recommended)](#1-asynchronous-aes-gcm-256-bit-recommended)
  * [2. Key Rotation](#2-key-rotation)
  * [3. Change Subscriptions (Events)](#3-change-subscriptions-events)
  * [4. Deep Path Operations](#4-deep-path-operations)
  * [5. SSR & In-Memory Fallback](#5-ssr--in-memory-fallback)
* [API Reference](#api-reference)
* [Security Considerations](#security-considerations)
* [Migration Notes](#migration-notes)
* [License](#license)

---

## Installation

```bash
npm install js-cookie-encrypt
# or
yarn add js-cookie-encrypt
# or
pnpm add js-cookie-encrypt
```

---

## Basic Usage (Synchronous)

> **Note:** RC4 is a legacy cipher and logs a warning. For production use, see [AES-GCM](#1-asynchronous-aes-gcm-256-bit-recommended) below.

```typescript
import JsCookieEncrypt from 'js-cookie-encrypt';

const cookieStore = new JsCookieEncrypt({
  storageKey: 'userProfile',
  cryptoConfig: {
    privateKey: 'your-private-key-here',
    algorithm: 'rc4',           // legacy — use 'aes-gcm' for production
    encryptByDefault: true,
  }
});

// Set
cookieStore.set({
  id: 101,
  name: 'John Doe',
  preferences: { theme: 'dark', notifications: true }
});

// Get
const profile = cookieStore.get();
console.log(profile?.name); // 'John Doe'

// Get single field
const name = cookieStore.get('name'); // 'John Doe'

// Update fields (fires 'update' event)
cookieStore.update({ name: 'Johnathan Doe' });

// Delete specific fields (fires 'delete' event)
cookieStore.deleteFields(['name']);

// Clear cookie (fires 'clear' event)
cookieStore.clear();
```

---

## Advanced Features

### 1. Asynchronous AES-GCM 256-bit (Recommended)

AES-GCM is authenticated encryption — it provides both confidentiality and integrity. It uses the browser's native `SubtleCrypto` API and requires the `*Async` methods:

```typescript
const secureStore = new JsCookieEncrypt({
  storageKey: 'secureSession',
  cryptoConfig: {
    privateKey: 'my-super-secret-key',
    algorithm: 'aes-gcm',
  }
});

// Set
await secureStore.setAsync({ token: 'jwt-token-xyz' });

// Get
const session = await secureStore.getAsync();
console.log(session?.token);

// Get single field
const token = await secureStore.getAsync('token');

// Path operations
const value = await secureStore.getByPathAsync('token');
await secureStore.setByPathAsync('token', 'new-jwt');
```

---

### 2. Key Rotation

Pass an array in `privateKey`. Index `0` is the active encryption key; all others are legacy decryption fallbacks. When a cookie is successfully decrypted with a fallback key it is automatically re-encrypted with the primary key.

```typescript
const rotatedStore = new JsCookieEncrypt({
  storageKey: 'userConfig',
  cryptoConfig: {
    privateKey: ['new-key-2026', 'old-key-2025'],
    algorithm: 'aes-gcm',
  }
});

// Decrypts with 'old-key-2025' if needed, re-saves with 'new-key-2026'
const config = await rotatedStore.getAsync();
```

---

### 3. Change Subscriptions (Events)

All four event types now fire correctly:

| Method | Event fired |
|--------|------------|
| `set()` / `setAsync()` | `'set'` |
| `update()` / `updateAsync()` / `updateByPath()` | `'update'` |
| `deleteFields()` / `deleteByPath()` | `'delete'` |
| `clear()` / `clearAsync()` | `'clear'` |

```typescript
const store = new JsCookieEncrypt({
  storageKey: 'cart',
  cryptoConfig: { privateKey: 'secret', algorithm: 'aes-gcm' }
});

const unsubscribe = store.subscribe((event) => {
  console.log(event.type);     // 'set' | 'update' | 'delete' | 'clear'
  console.log(event.oldValue);
  console.log(event.newValue);
});

await store.setAsync({ items: [10, 20] });   // fires 'set'
await store.updateAsync({ items: [10] });    // fires 'update'
await store.clearAsync();                    // fires 'clear'

unsubscribe();
```

---

### 4. Deep Path Operations

TypeScript infers exact types for dot-notation path strings:

```typescript
interface AppData {
  user: {
    name: string;
    address: { city: string };
  };
}

const store = new JsCookieEncrypt<AppData>({
  storageKey: 'appData',
  cryptoConfig: { privateKey: 'secret', algorithm: 'aes-gcm' }
});

await store.setAsync({ user: { name: 'Alice', address: { city: 'Los Angeles' } } });

// Get nested value — typed as string
const city = await store.getByPathAsync('user.address.city');

// Set nested value
await store.setByPathAsync('user.address.city', 'San Francisco');

// Deep merge nested object
await store.updateByPathAsync('user.address', { city: 'NYC' });

// Check existence
const exists = await store.hasAsync('user.address.city'); // true

// Delete nested field
await store.deleteByPathAsync('user.address.city');
```

---

### 5. SSR & In-Memory Fallback

When `document.cookie` is unavailable (SSR, incognito blocks), the library transparently falls back to an in-memory Map. No crashes, no code changes needed.

```typescript
// Safe to instantiate at module level in Next.js / Nuxt
const store = new JsCookieEncrypt({
  storageKey: 'ssr-safe',
  cryptoConfig: { privateKey: 'secret', algorithm: 'aes-gcm' }
});

if (JsCookieEncrypt.isSupported()) {
  console.log('Browser cookies available');
} else {
  console.log('Using in-memory fallback (SSR or cookies blocked)');
}
```

---

## API Reference

### Constructor

```typescript
new JsCookieEncrypt(config: StorageConfig)
```

Throws if `storageKey` is empty or any `privateKey` value is an empty string.

```typescript
interface StorageConfig {
  storageKey: string;           // must be non-empty
  cryptoConfig: {
    privateKey: string | string[]; // must be non-empty; array = key rotation
    saltLength?: number;           // default: 16
    encryptByDefault?: boolean;    // default: true
    algorithm?: 'aes-gcm' | 'rc4' | 'xor'; // default: 'rc4' (legacy)
  };
  defaultOptions?: CookieOptions;
}

interface CookieOptions {
  path?: string;
  expires?: number | Date;  // number = milliseconds from now
  secure?: boolean;
  domain?: string;
  sameSite?: 'strict' | 'lax' | 'none';
  httpOnly?: boolean;       // no-op in JS — server-only via Set-Cookie header
}
```

---

### Static Methods

```typescript
// Check if document.cookie is writable
JsCookieEncrypt.isSupported(): boolean

// Return all cookies as name→value map (decoded)
JsCookieEncrypt.getAllCookies(): Record<string, string>

// Delete all cookies for path/domain
JsCookieEncrypt.clearAll(domain?: string, path?: string, clearSubDomain?: boolean): void
```

---

### Instance Methods — Synchronous

> RC4 and XOR only. Use `*Async` methods with `algorithm: 'aes-gcm'` in production.

```typescript
set(value: T, options?: CookieOptions, helpers?: { encrypt?: boolean; merge?: boolean }): void
get(field?: keyof T): T | T[keyof T] | null
getByPath(path: string): PathValue | null
setByPath(path: string, value: any, options?: CookieOptions): void
updateByPath(path: string, value: any, options?: CookieOptions): void
deleteByPath(path: string): void
update(updates: Partial<T>, options?: CookieOptions): void
deleteFields(fields: Array<keyof T>): void
extend(durationSecs: number, options?: CookieOptions): void  // duration in seconds
clear(options?: CookieOptions): void
has(pathOrField?: string): boolean
subscribe(listener: CookieListener<T>): () => void           // returns unsubscribe fn
```

---

### Instance Methods — Asynchronous (AES-GCM)

```typescript
setAsync(value: T, options?: CookieOptions, helpers?: { encrypt?: boolean; merge?: boolean }): Promise<void>
getAsync(field?: keyof T): Promise<T | T[keyof T] | null>
getByPathAsync(path: string): Promise<PathValue | null>
setByPathAsync(path: string, value: any, options?: CookieOptions): Promise<void>
updateByPathAsync(path: string, value: any, options?: CookieOptions): Promise<void>
deleteByPathAsync(path: string): Promise<void>
updateAsync(updates: Partial<T>, options?: CookieOptions): Promise<void>
deleteFieldsAsync(fields: Array<keyof T>): Promise<void>
extendAsync(durationSecs: number, options?: CookieOptions): Promise<void>  // duration in seconds
clearAsync(options?: CookieOptions): Promise<void>
hasAsync(pathOrField?: string): Promise<boolean>
```

---

## Security Considerations

1. **Use AES-GCM in production.** RC4 and XOR are legacy ciphers with known weaknesses (RC4 is banned by RFC 7465). They are kept only for backward compatibility. Set `algorithm: 'aes-gcm'` and use the `*Async` methods for any security-sensitive data.

2. **Never hard-code private keys in client bundles.** All encryption happens client-side, so the private key is accessible to JavaScript on the page. Treat it as a per-session secret, not a server secret. Load it from your SSR layer or derive it server-side.

3. **Always use `secure: true` in production.** Combine with `sameSite: 'lax'` or `'strict'` to guard against CSRF and network interception.

4. **`httpOnly` cannot be set via JavaScript.** The `httpOnly` field in `CookieOptions` is silently ignored by browsers when set via `document.cookie`. It can only be applied server-side via the `Set-Cookie` response header. Using it here has no effect and the library will warn you.

5. **Cookies are not a secret store.** Even encrypted, cookies are stored on the user's machine and transmitted with every request. Do not store server-side secrets, raw credentials, or PII beyond what is necessary.

6. **Cookie size limit is 4KB.** The library warns when this is exceeded. Encrypted and base64-encoded values are larger than the original — keep stored objects small.

---

## Migration Notes

### v1.0.x → v1.1.0

**Breaking changes:**

- `getAllCookies(domain?)` — the `domain` parameter has been removed. `document.cookie` does not expose cookie attributes, so domain filtering was silently broken and always returned all cookies regardless. Call `getAllCookies()` with no arguments.

- **Empty `storageKey` or `privateKey` now throws** at construction time instead of silently failing.

- **`Math.random()` salt fallback removed.** If `crypto.getRandomValues` is not available, the library now throws instead of using an insecure fallback. This only affects extremely old or non-standard environments.

**Behavioral fixes (non-breaking but observable):**

- `update()` / `updateByPath()` now fire `'update'` events instead of `'set'`.
- `deleteFields()` / `deleteByPath()` now fire `'delete'` events instead of `'set'`.
- A corrupt cookie now only removes the single affected cookie. Previously it called `clearAll()` which deleted every cookie on the domain.
- `expires` as a number in `CookieOptions` is consistently treated as **milliseconds** everywhere (`set`, `setAsync`, `clear`, `clearAsync`). Previously `clear()` incorrectly treated it as seconds.
- Cookie names and values are now `encodeURIComponent`-encoded on write and decoded on read.
- `SameSite` attribute casing fixed to `SameSite` (was lowercase `samesite`).

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
