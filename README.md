# js-cookie-encrypt

[![npm version](https://img.shields.io/npm/v/js-cookie-encrypt.svg?style=flat-square)](https://www.npmjs.com/package/js-cookie-encrypt)
[![npm downloads](https://img.shields.io/npm/dm/js-cookie-encrypt.svg?style=flat-square)](https://www.npmjs.com/package/js-cookie-encrypt)
[![license](https://img.shields.io/npm/l/js-cookie-encrypt.svg?style=flat-square)](https://github.com/abfahimb/js-cookie-encrypt/blob/main/LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-ready-blue?style=flat-square)](https://www.typescriptlang.org/)

**The only actively maintained, client-side encrypted cookie library for browsers.**

`js-cookie` is the gold standard for cookie management — but it has zero encryption. `crypto-js` has encryption — but it's abandoned and bloated. `js-cookie-encrypt` fills that gap: the familiar simplicity of `js-cookie` combined with native **AES-GCM 256-bit** encryption via the browser's built-in `SubtleCrypto` API. Zero dependencies.

```bash
npm install js-cookie-encrypt
```

```
// What your cookies look like in the browser — not readable without your key:
gcm:aGVsbG8td29ybGQtdGhpcy1pcy1lbmNyeXB0ZWQ...
```

---

## Why js-cookie-encrypt?

| Feature | js-cookie | universal-cookie | crypto-js | **js-cookie-encrypt** |
|---|:---:|:---:|:---:|:---:|
| Browser cookies | ✅ | ✅ | ❌ | ✅ |
| AES-GCM 256-bit encryption | ❌ | ❌ | ✅ | ✅ |
| Native Web Crypto API | ❌ | ❌ | ❌ | ✅ |
| Zero dependencies | ✅ | ❌ | ❌ | ✅ |
| TypeScript types | ✅ | ✅ | ✅ | ✅ |
| Key rotation | ❌ | ❌ | ❌ | ✅ |
| Deep path operations | ❌ | ❌ | ❌ | ✅ |
| Change events | ❌ | ❌ | ❌ | ✅ |
| SSR / Next.js safe | ⚠️ | ✅ | ❌ | ✅ |
| Actively maintained | ✅ | ✅ | ❌ | ✅ |

---

## Installation

```bash
npm install js-cookie-encrypt
# or
yarn add js-cookie-encrypt
# or
pnpm add js-cookie-encrypt
```

**CDN (browser):**
```html
<script src="https://cdn.jsdelivr.net/npm/js-cookie-encrypt/dist/js-cookie-encrypt.min.js"></script>
```

---

## Quick Start

```typescript
import JsCookieEncrypt from 'js-cookie-encrypt';

const store = new JsCookieEncrypt({
  storageKey: 'session',
  cryptoConfig: {
    privateKey: 'your-secret-key',
    algorithm: 'aes-gcm',           // AES-GCM 256-bit — recommended
  }
});

// Write — stored as unreadable ciphertext in the browser
await store.setAsync({ userId: 42, role: 'admin', theme: 'dark' });

// Read — decrypted automatically
const session = await store.getAsync();
console.log(session?.role); // 'admin'

// Update a field
await store.updateAsync({ theme: 'light' });

// Deep nested access
await store.setByPathAsync('preferences.notifications', true);
const theme = await store.getByPathAsync('preferences.theme');

// Delete
await store.clearAsync();
```

---

## Table of Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Algorithms](#algorithms)
- [Key Rotation](#key-rotation)
- [Change Events](#change-events)
- [Deep Path Operations](#deep-path-operations)
- [SSR & Next.js](#ssr--nextjs)
- [Framework Examples](#framework-examples)
- [API Reference](#api-reference)
- [Security Considerations](#security-considerations)
- [Migration from 1.0.x](#migration-from-10x)
- [License](#license)

---

## Features

- **AES-GCM 256-bit encryption** via the browser's native `SubtleCrypto` API — no external crypto library needed
- **Zero dependencies** — ships only what it needs
- **TypeScript-first** — full generic type inference including deep nested path types
- **Key rotation** — pass multiple keys; old cookies are transparently re-encrypted on read
- **All four change events** — `set`, `update`, `delete`, `clear` fire with old and new values
- **Deep path API** — get, set, update, delete nested values with dot-notation (`user.address.city`)
- **SSR safe** — falls back to in-memory storage when `document.cookie` is unavailable (Next.js, Nuxt, Remix)
- **Cookie size warnings** — warns automatically when payload approaches the 4KB browser limit
- **Regex-injection safe** — cookie names are escaped before use in `RegExp`
- **URL-encoded storage** — names and values are `encodeURIComponent`-encoded on write

---

## Algorithms

| Algorithm | API | Security | Use case |
|-----------|-----|----------|----------|
| `aes-gcm` | `*Async` methods | **Production** — authenticated encryption, tamper-proof | All new projects |
| `rc4` | sync methods | Legacy — weak, logs a warning | Migrating old data only |
| `xor` | sync methods | Legacy — very weak, logs a warning | Backward compat only |

> **Always use `aes-gcm` for new projects.** RC4 and XOR are retained only for migrating cookies set by older versions of this library.

```typescript
// Production — AES-GCM via SubtleCrypto
const store = new JsCookieEncrypt({
  storageKey: 'app',
  cryptoConfig: { privateKey: 'secret', algorithm: 'aes-gcm' }
});
await store.setAsync({ token: 'abc' });
const data = await store.getAsync();
```

---

## Key Rotation

Rotate your encryption keys without invalidating existing user sessions. Pass an array in `privateKey` — index `0` is the active key, the rest are legacy fallbacks. When an old cookie is decrypted with a fallback key it is automatically re-encrypted with the new primary key on the next read.

```typescript
const store = new JsCookieEncrypt({
  storageKey: 'session',
  cryptoConfig: {
    privateKey: ['new-key-2026', 'old-key-2025'],  // first = current, rest = fallbacks
    algorithm: 'aes-gcm'
  }
});

// Automatically re-encrypts old cookies with 'new-key-2026' on read
const session = await store.getAsync();
```

---

## Change Events

Subscribe to cookie changes in real-time. Each operation fires the correct event type with both old and new values.

```typescript
const store = new JsCookieEncrypt({
  storageKey: 'cart',
  cryptoConfig: { privateKey: 'secret', algorithm: 'aes-gcm' }
});

const unsubscribe = store.subscribe((event) => {
  switch (event.type) {
    case 'set':    console.log('Created:', event.newValue); break;
    case 'update': console.log('Updated:', event.oldValue, '→', event.newValue); break;
    case 'delete': console.log('Deleted fields, was:', event.oldValue); break;
    case 'clear':  console.log('Cleared, was:', event.oldValue); break;
  }
});

await store.setAsync({ items: [] });          // fires 'set'
await store.updateAsync({ items: [1, 2] });   // fires 'update'
await store.deleteFieldsAsync(['items']);      // fires 'delete'
await store.clearAsync();                     // fires 'clear'

unsubscribe(); // stop listening
```

---

## Deep Path Operations

Work with nested data structures using dot-notation paths. TypeScript infers the exact type at each path.

```typescript
interface AppState {
  user: {
    name: string;
    address: { city: string; country: string };
    preferences: { theme: 'dark' | 'light'; notifications: boolean };
  };
}

const store = new JsCookieEncrypt<AppState>({
  storageKey: 'app',
  cryptoConfig: { privateKey: 'secret', algorithm: 'aes-gcm' }
});

await store.setAsync({
  user: {
    name: 'Alice',
    address: { city: 'London', country: 'UK' },
    preferences: { theme: 'dark', notifications: true }
  }
});

// Get — typed as string
const city = await store.getByPathAsync('user.address.city'); // 'London'

// Set
await store.setByPathAsync('user.address.city', 'Paris');

// Deep merge
await store.updateByPathAsync('user.preferences', { theme: 'light' });

// Check existence
const exists = await store.hasAsync('user.address.city'); // true

// Delete one field
await store.deleteByPathAsync('user.address.country');
```

---

## SSR & Next.js

Safe to instantiate at module level. When `document.cookie` is unavailable the library falls back to an in-memory Map automatically — no crashes, no code changes.

```typescript
// pages/_app.tsx or app/layout.tsx — safe at module level
import JsCookieEncrypt from 'js-cookie-encrypt';

export const sessionStore = new JsCookieEncrypt({
  storageKey: 'session',
  cryptoConfig: { privateKey: process.env.COOKIE_SECRET!, algorithm: 'aes-gcm' }
});

// In a component or server action:
if (JsCookieEncrypt.isSupported()) {
  await sessionStore.setAsync({ userId: 1 });
}
```

---

## Framework Examples

### React

```typescript
import { useEffect, useState } from 'react';
import JsCookieEncrypt from 'js-cookie-encrypt';

const store = new JsCookieEncrypt({
  storageKey: 'prefs',
  cryptoConfig: { privateKey: 'secret', algorithm: 'aes-gcm' }
});

function usePreferences() {
  const [prefs, setPrefs] = useState<{ theme: string } | null>(null);

  useEffect(() => {
    store.getAsync().then(setPrefs);
    return store.subscribe(e => {
      if (e.type === 'set' || e.type === 'update') setPrefs(e.newValue ?? null);
      if (e.type === 'clear') setPrefs(null);
    });
  }, []);

  const save = (updates: Partial<{ theme: string }>) => store.updateAsync(updates);

  return { prefs, save };
}
```

### Vue 3

```typescript
import { ref, onMounted, onUnmounted } from 'vue';
import JsCookieEncrypt from 'js-cookie-encrypt';

const store = new JsCookieEncrypt({
  storageKey: 'user',
  cryptoConfig: { privateKey: 'secret', algorithm: 'aes-gcm' }
});

export function useUser() {
  const user = ref<{ name: string } | null>(null);
  let unsubscribe: () => void;

  onMounted(async () => {
    user.value = await store.getAsync() as any;
    unsubscribe = store.subscribe(e => { user.value = e.newValue ?? null; });
  });
  onUnmounted(() => unsubscribe?.());

  return { user };
}
```

### Next.js (App Router)

```typescript
// lib/session.ts
import JsCookieEncrypt from 'js-cookie-encrypt';

interface Session { userId: number; role: string }

export const session = new JsCookieEncrypt<Session>({
  storageKey: 'session',
  cryptoConfig: {
    privateKey: process.env.NEXT_PUBLIC_COOKIE_KEY!,
    algorithm: 'aes-gcm',
  },
  defaultOptions: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
  }
});
```

---

## API Reference

### Constructor

```typescript
new JsCookieEncrypt<T>(config: StorageConfig)
```

Throws if `storageKey` is empty or any `privateKey` value is an empty string.

```typescript
interface StorageConfig {
  storageKey: string;              // cookie name — must be non-empty
  cryptoConfig: {
    privateKey: string | string[]; // encryption key(s) — must be non-empty
    algorithm?: 'aes-gcm' | 'rc4' | 'xor'; // default: 'rc4' (use 'aes-gcm')
    saltLength?: number;           // default: 16
    encryptByDefault?: boolean;    // default: true
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
// Returns true if document.cookie is writable in the current environment
JsCookieEncrypt.isSupported(): boolean

// Returns all cookies as a decoded name→value map
JsCookieEncrypt.getAllCookies(): Record<string, string>

// Deletes all cookies for the given path/domain
JsCookieEncrypt.clearAll(domain?: string, path?: string, clearSubDomain?: boolean): void
```

---

### Async Methods (AES-GCM — recommended)

```typescript
setAsync(value: T, options?: CookieOptions, helpers?: { encrypt?: boolean; merge?: boolean }): Promise<void>
getAsync(field?: keyof T): Promise<T | T[keyof T] | null>
getByPathAsync(path: string): Promise<PathValue | null>
setByPathAsync(path: string, value: any, options?: CookieOptions): Promise<void>
updateByPathAsync(path: string, value: any, options?: CookieOptions): Promise<void>
deleteByPathAsync(path: string): Promise<void>
updateAsync(updates: Partial<T>, options?: CookieOptions): Promise<void>
deleteFieldsAsync(fields: Array<keyof T>): Promise<void>
extendAsync(durationSecs: number, options?: CookieOptions): Promise<void>
clearAsync(options?: CookieOptions): Promise<void>
hasAsync(pathOrField?: string): Promise<boolean>
subscribe(listener: (event: CookieEvent<T>) => void): () => void
```

---

### Sync Methods (RC4/XOR legacy)

```typescript
set(value: T, options?: CookieOptions, helpers?: { encrypt?: boolean; merge?: boolean }): void
get(field?: keyof T): T | T[keyof T] | null
getByPath(path: string): PathValue | null
setByPath(path: string, value: any, options?: CookieOptions): void
updateByPath(path: string, value: any, options?: CookieOptions): void
deleteByPath(path: string): void
update(updates: Partial<T>, options?: CookieOptions): void
deleteFields(fields: Array<keyof T>): void
extend(durationSecs: number, options?: CookieOptions): void
clear(options?: CookieOptions): void
has(pathOrField?: string): boolean
```

---

## Security Considerations

### 1. Use AES-GCM — it's the only strong option here

RC4 is banned by [RFC 7465](https://datatracker.ietf.org/doc/html/rfc7465). XOR is trivially broken. Both are retained only for migrating legacy cookies. Set `algorithm: 'aes-gcm'` and use `*Async` methods for all new work.

### 2. Client-side keys are not secrets

This library encrypts cookies against **casual inspection** — someone looking at DevTools, logs, or intercepted network traffic won't see plaintext values. It does **not** protect against an attacker who has JavaScript execution on the page, because the key is accessible to JS. Do not store server-side secrets or session tokens that bypass server auth in cookies.

### 3. Always set `secure` and `sameSite` in production

```typescript
defaultOptions: {
  secure: true,          // HTTPS only
  sameSite: 'lax',       // CSRF protection
  path: '/',
}
```

### 4. `httpOnly` cannot be set via JavaScript

The `httpOnly` field in `CookieOptions` is a no-op — browsers silently ignore it when set via `document.cookie`. Set it server-side via the `Set-Cookie` response header. The library logs a warning if you include it.

### 5. 4KB cookie limit

Browsers enforce a ~4KB limit per cookie. Encrypted + base64-encoded payloads are larger than raw data. The library warns you when this is exceeded. Keep stored objects small — reference IDs, not full datasets.

---

## Migration from 1.0.x

**Breaking changes in v1.1.0:**

- `getAllCookies(domain?)` — `domain` parameter removed. It was silently non-functional (browsers don't expose cookie attributes via `document.cookie`). Call `getAllCookies()` with no arguments.
- Empty `storageKey` or `privateKey` now **throws at construction time** instead of silently failing.
- `Math.random()` fallback for salt generation removed — throws if `crypto.getRandomValues` is unavailable.

**Behavioral fixes (observable but non-breaking):**

- `update()` fires `'update'` events (was `'set'`)
- `deleteFields()` / `deleteByPath()` fire `'delete'` events (was `'set'`)
- A corrupt/unreadable cookie now removes **only that cookie**. Previously it called `clearAll()` and wiped every cookie on the domain.
- `expires` as a number in `CookieOptions` is now consistently **milliseconds** in all methods. Previously `clear()` incorrectly treated it as seconds.
- Cookie names and values are `encodeURIComponent`-encoded — cookies set by v1.0.x will be re-set on first write.
- `SameSite` attribute casing corrected to `SameSite` (was `samesite`).

---

## License

MIT © [Abdullah Al Fahim](https://github.com/abfahimb)
