/*! js-cookie-encrypt v1.1.0 | MIT (c) 2026 Abdullah Al Fahim | https://github.com/abfahimb/js-cookie-encrypt */

export interface CookieOptions {
  path?: string;
  expires?: number | Date; // number = milliseconds from now
  secure?: boolean;
  domain?: string;
  sameSite?: 'strict' | 'lax' | 'none';
  // Note: httpOnly cannot be set via JavaScript — server-only via Set-Cookie header
  httpOnly?: boolean;
}

export interface CryptoConfig {
  privateKey: string | string[];
  saltLength?: number;
  encryptByDefault?: boolean;
  algorithm?: 'xor' | 'rc4' | 'aes-gcm';
}

export interface StorageConfig {
  storageKey: string;
  cryptoConfig: CryptoConfig;
  defaultOptions?: CookieOptions;
}

export type CookieEventType = 'set' | 'update' | 'delete' | 'clear';

export interface CookieEvent<T = any> {
  type: CookieEventType;
  storageKey: string;
  newValue?: T | null;
  oldValue?: T | null;
}

export type CookieListener<T = any> = (event: CookieEvent<T>) => void;

type PathImpl<T, K extends keyof T> = K extends string
  ? T[K] extends Record<string, any>
    ? T[K] extends ArrayLike<any>
      ? K | `${K}.${PathImpl<T[K], Exclude<keyof T[K], keyof any[]>>}`
      : K | `${K}.${PathImpl<T[K], keyof T[K]>}`
    : K
  : never;

export type Path<T> = PathImpl<T, keyof T> | keyof T;

export type PathValue<T, P extends string> = P extends `${infer K}.${infer R}`
  ? K extends keyof T
    ? PathValue<T[K], R>
    : any
  : P extends keyof T
    ? T[P]
    : any;

const inMemoryStorage = new Map<string, string>();

function isDocumentCookieAvailable(): boolean {
  if (typeof document === 'undefined') return false;
  try {
    const testKey = '__js_cookie_encrypt_test__';
    document.cookie = `${testKey}=1; path=/; SameSite=lax`;
    const available = document.cookie.indexOf(testKey) !== -1;
    document.cookie = `${testKey}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; SameSite=lax`;
    return available;
  } catch {
    return false;
  }
}

function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// AES-GCM 256-bit via Web Cryptography API
class AsyncCookieCrypto {
  private keyCache = new Map<string, CryptoKey>();

  private getCrypto(): Crypto {
    if (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle) {
      return globalThis.crypto;
    }
    if (typeof window !== 'undefined' && window.crypto?.subtle) {
      return window.crypto;
    }
    // SSR / Node.js — use new Function instead of eval to avoid CSP violations
    try {
      // eslint-disable-next-line no-new-func
      const requireFn = new Function('return require') as () => (id: string) => any;
      const nodeCrypto = requireFn()('crypto') as any;
      if (nodeCrypto.webcrypto) return nodeCrypto.webcrypto;
    } catch { /* fall through */ }
    throw new Error('[js-cookie-encrypt] Web Cryptography API (SubtleCrypto) is not available in this environment.');
  }

  private async getCryptoKey(privateKey: string): Promise<CryptoKey> {
    if (this.keyCache.has(privateKey)) {
      return this.keyCache.get(privateKey)!;
    }
    const cryptoInstance = this.getCrypto();
    const hash = await cryptoInstance.subtle.digest('SHA-256', new TextEncoder().encode(privateKey));
    const cryptoKey = await cryptoInstance.subtle.importKey(
      'raw', hash, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
    );
    this.keyCache.set(privateKey, cryptoKey);
    return cryptoKey;
  }

  async encrypt(data: string, privateKey: string): Promise<string> {
    const cryptoInstance = this.getCrypto();
    const key = await this.getCryptoKey(privateKey);
    const iv = cryptoInstance.getRandomValues(new Uint8Array(12));
    const ciphertext = await cryptoInstance.subtle.encrypt(
      { name: 'AES-GCM', iv }, key, new TextEncoder().encode(data)
    );
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);
    // Avoid spread operator — stack overflow on large payloads
    let binaryStr = '';
    for (let i = 0; i < combined.length; i++) binaryStr += String.fromCharCode(combined[i]);
    return btoa(binaryStr);
  }

  async decrypt(encryptedData: string, privateKey: string): Promise<string> {
    const cryptoInstance = this.getCrypto();
    const key = await this.getCryptoKey(privateKey);
    const binaryStr = atob(encryptedData);
    const combined = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) combined[i] = binaryStr.charCodeAt(i);
    if (combined.length < 12) throw new Error('[js-cookie-encrypt] Invalid encrypted data: too short');
    const decrypted = await cryptoInstance.subtle.decrypt(
      { name: 'AES-GCM', iv: combined.slice(0, 12) }, key, combined.slice(12)
    );
    return new TextDecoder().decode(decrypted);
  }
}

// Synchronous legacy ciphers (RC4, XOR)
// WARNING: RC4 and XOR are not suitable for high-security scenarios. Use AES-GCM (*Async methods) in production.
class CookieCrypto {
  private privateKeys: string[];
  private saltLength: number;
  private algorithm: 'xor' | 'rc4' | 'aes-gcm';
  private asyncCrypto: AsyncCookieCrypto;

  constructor(config: CryptoConfig) {
    const keys = config.privateKey;
    this.privateKeys = Array.isArray(keys) ? keys : [keys];
    this.saltLength = config.saltLength || 16;
    this.algorithm = config.algorithm || 'rc4';
    this.asyncCrypto = new AsyncCookieCrypto();

    if (this.algorithm === 'rc4' || this.algorithm === 'xor') {
      console.warn('[js-cookie-encrypt] RC4 and XOR are legacy ciphers with known weaknesses. Use algorithm: "aes-gcm" with *Async methods for production security.');
    }
  }

  private generateRandomSalt(): string {
    const randomBytes = new Uint8Array(this.saltLength);
    const cryptoObj = (typeof globalThis !== 'undefined' && globalThis.crypto)
      ? globalThis.crypto
      : (typeof window !== 'undefined' ? window.crypto : null);
    if (!cryptoObj?.getRandomValues) {
      throw new Error('[js-cookie-encrypt] Cryptographically secure random number generator not available. Cannot generate salt safely.');
    }
    cryptoObj.getRandomValues(randomBytes);
    return Array.from(randomBytes, b => String.fromCharCode(b)).join('');
  }

  // Keyed FNV-1a — NOT a MAC; provides basic tamper detection only when key is kept secret.
  // For cryptographic integrity guarantees, use AES-GCM which provides authenticated encryption.
  private calculateChecksum(data: string, key: string): string {
    let hash = 0x811c9dc5;
    const combined = key + data + key; // key-wrap reduces length-extension risk
    for (let i = 0; i < combined.length; i++) {
      hash ^= combined.charCodeAt(i);
      hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
    }
    return (hash >>> 0).toString(16);
  }

  private expandKey(key: string, salt: string): string {
    const maxLen = Math.max(key.length, salt.length);
    const out: string[] = [];
    for (let i = 0; i < maxLen; i++) {
      out.push(String.fromCharCode(
        key.charCodeAt(i % key.length) ^ salt.charCodeAt(i % salt.length)
      ));
    }
    return out.join('');
  }

  private xorEncrypt(data: string, key: string): string {
    const salt = this.generateRandomSalt();
    const expandedKey = this.expandKey(key, salt);
    let result = '';
    for (let i = 0; i < data.length; i++) {
      result += String.fromCharCode(data.charCodeAt(i) ^ expandedKey.charCodeAt(i % expandedKey.length));
    }
    const bytes = new TextEncoder().encode(salt + result);
    let binaryStr = '';
    for (let i = 0; i < bytes.length; i++) binaryStr += String.fromCharCode(bytes[i]);
    return btoa(binaryStr);
  }

  private xorDecrypt(encryptedData: string, key: string): string {
    const binaryStr = atob(encryptedData);
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);
    const decoded = new TextDecoder().decode(bytes);
    const salt = decoded.substring(0, this.saltLength);
    const encryptedMessage = decoded.substring(this.saltLength);
    const expandedKey = this.expandKey(key, salt);
    let result = '';
    for (let i = 0; i < encryptedMessage.length; i++) {
      result += String.fromCharCode(encryptedMessage.charCodeAt(i) ^ expandedKey.charCodeAt(i % expandedKey.length));
    }
    return result;
  }

  private rc4Encrypt(data: string, key: string): string {
    const salt = this.generateRandomSalt();
    const derivedKey = key + salt;
    const binBytes = new TextEncoder().encode(data);
    let binData = '';
    for (let i = 0; i < binBytes.length; i++) binData += String.fromCharCode(binBytes[i]);
    const encrypted = this.rc4(binData, derivedKey);
    const checksum = this.calculateChecksum(binData, key);
    return btoa(salt + ':' + checksum + ':' + encrypted);
  }

  private rc4Decrypt(encryptedData: string, key: string): string {
    const packet = atob(encryptedData);
    const firstColon = packet.indexOf(':');
    const secondColon = packet.indexOf(':', firstColon + 1);
    if (firstColon === -1 || secondColon === -1) {
      throw new Error('[js-cookie-encrypt] Invalid RC4 packet format');
    }
    const salt = packet.substring(0, firstColon);
    const storedChecksum = packet.substring(firstColon + 1, secondColon);
    const encryptedMessage = packet.substring(secondColon + 1);
    const binData = this.rc4(encryptedMessage, key + salt);
    if (this.calculateChecksum(binData, key) !== storedChecksum) {
      throw new Error('[js-cookie-encrypt] Integrity check failed: data may be tampered');
    }
    const bytes = new Uint8Array(binData.length);
    for (let i = 0; i < binData.length; i++) bytes[i] = binData.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  }

  private rc4(data: string, key: string): string {
    const s = new Uint8Array(256);
    for (let i = 0; i < 256; i++) s[i] = i;
    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + s[i] + key.charCodeAt(i % key.length)) % 256;
      const tmp = s[i]; s[i] = s[j]; s[j] = tmp;
    }
    let i = 0; j = 0;
    let result = '';
    for (let k = 0; k < data.length; k++) {
      i = (i + 1) % 256;
      j = (j + s[i]) % 256;
      const tmp = s[i]; s[i] = s[j]; s[j] = tmp;
      result += String.fromCharCode(data.charCodeAt(k) ^ s[(s[i] + s[j]) % 256]);
    }
    return result;
  }

  encrypt(data: string): string {
    if (this.algorithm === 'aes-gcm') {
      throw new Error('[js-cookie-encrypt] AES-GCM requires the async API (*Async methods).');
    }
    const key = this.privateKeys[0];
    return this.algorithm === 'rc4'
      ? 'rc4:' + this.rc4Encrypt(data, key)
      : this.xorEncrypt(data, key);
  }

  decrypt(encryptedData: string): { decrypted: string; wasKeyRotated: boolean } {
    if (encryptedData.startsWith('gcm:')) {
      throw new Error('[js-cookie-encrypt] AES-GCM cookies require the async API (*Async methods).');
    }
    const isRc4 = encryptedData.startsWith('rc4:');
    const payload = isRc4 ? encryptedData.substring(4) : encryptedData;

    for (let idx = 0; idx < this.privateKeys.length; idx++) {
      const key = this.privateKeys[idx];
      try {
        const decrypted = isRc4 ? this.rc4Decrypt(payload, key) : this.xorDecrypt(payload, key);
        JSON.parse(decrypted);
        return { decrypted, wasKeyRotated: idx > 0 };
      } catch {
        if (idx === this.privateKeys.length - 1) {
          try {
            JSON.parse(encryptedData);
            return { decrypted: encryptedData, wasKeyRotated: false };
          } catch {
            throw new Error('[js-cookie-encrypt] Failed to decrypt data with any available key');
          }
        }
      }
    }
    throw new Error('[js-cookie-encrypt] Failed to decrypt data with any available key');
  }

  async encryptAsync(data: string): Promise<string> {
    const key = this.privateKeys[0];
    if (this.algorithm === 'aes-gcm') {
      return 'gcm:' + await this.asyncCrypto.encrypt(data, key);
    }
    return this.algorithm === 'rc4'
      ? 'rc4:' + this.rc4Encrypt(data, key)
      : this.xorEncrypt(data, key);
  }

  async decryptAsync(encryptedData: string): Promise<{ decrypted: string; wasKeyRotated: boolean }> {
    const isGcm = encryptedData.startsWith('gcm:');
    const isRc4 = encryptedData.startsWith('rc4:');
    const payload = (isGcm || isRc4) ? encryptedData.substring(4) : encryptedData;

    for (let idx = 0; idx < this.privateKeys.length; idx++) {
      const key = this.privateKeys[idx];
      try {
        let decrypted: string;
        if (isGcm) {
          decrypted = await this.asyncCrypto.decrypt(payload, key);
        } else if (isRc4) {
          decrypted = this.rc4Decrypt(payload, key);
        } else {
          decrypted = this.xorDecrypt(payload, key);
        }
        JSON.parse(decrypted);
        return { decrypted, wasKeyRotated: idx > 0 };
      } catch {
        if (idx === this.privateKeys.length - 1) {
          try {
            JSON.parse(encryptedData);
            return { decrypted: encryptedData, wasKeyRotated: false };
          } catch {
            throw new Error('[js-cookie-encrypt] Failed to decrypt data with any available key');
          }
        }
      }
    }
    throw new Error('[js-cookie-encrypt] Failed to decrypt data with any available key');
  }
}

export class JsCookieEncrypt<T extends Record<string, any>> {
  private storageKey: string;
  private crypto: CookieCrypto;
  private defaultOptions: CookieOptions;
  private encryptByDefault: boolean;
  private listeners = new Set<CookieListener<T>>();

  constructor(config: StorageConfig) {
    if (!config.storageKey || typeof config.storageKey !== 'string') {
      throw new Error('[js-cookie-encrypt] storageKey must be a non-empty string.');
    }
    const keys = Array.isArray(config.cryptoConfig.privateKey)
      ? config.cryptoConfig.privateKey
      : [config.cryptoConfig.privateKey];
    if (keys.length === 0 || keys.some(k => !k || typeof k !== 'string')) {
      throw new Error('[js-cookie-encrypt] privateKey must be a non-empty string or array of non-empty strings.');
    }
    this.storageKey = config.storageKey;
    this.crypto = new CookieCrypto(config.cryptoConfig);
    this.defaultOptions = config.defaultOptions || {};
    this.encryptByDefault = config.cryptoConfig.encryptByDefault ?? true;
  }

  static isSupported(): boolean {
    return isDocumentCookieAvailable();
  }

  subscribe(listener: CookieListener<T>): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notify(event: CookieEvent<T>): void {
    this.listeners.forEach(listener => {
      try { listener(event); } catch (e) {
        console.error('[js-cookie-encrypt] Error in event listener:', e);
      }
    });
  }

  private buildOptionsStr(options: CookieOptions): string {
    let str = '';
    if (options.path) str += `; path=${options.path}`;
    if (options.expires) {
      // expires as number = milliseconds from now
      const date = typeof options.expires === 'number'
        ? new Date(Date.now() + options.expires)
        : options.expires;
      str += `; expires=${date.toUTCString()}`;
    }
    if (options.domain) str += `; domain=${options.domain}`;
    if (options.secure) str += '; Secure';
    if (options.sameSite) str += `; SameSite=${options.sameSite}`;
    if (options.httpOnly) {
      console.warn('[js-cookie-encrypt] httpOnly cannot be set via JavaScript. Use the server Set-Cookie response header.');
    }
    return str;
  }

  private writeCookie(name: string, value: string, optionsStr: string): void {
    const encodedName = encodeURIComponent(name);
    const encodedValue = encodeURIComponent(value);
    const fullCookie = `${encodedName}=${encodedValue}${optionsStr}`;
    if (fullCookie.length > 4096) {
      console.warn(`[js-cookie-encrypt] Cookie "${name}" is ${fullCookie.length} bytes, exceeding the 4KB browser limit. It may be silently rejected.`);
    }
    if (isDocumentCookieAvailable()) {
      document.cookie = fullCookie;
    } else {
      inMemoryStorage.set(name, value);
    }
  }

  private readCookie(name: string): string | null {
    if (isDocumentCookieAvailable()) {
      // Escape both the encoded name and its regex special chars to prevent regex injection
      const encodedName = escapeRegExp(encodeURIComponent(name));
      const match = document.cookie.match(new RegExp('(^| )' + encodedName + '=([^;]+)'));
      return match ? decodeURIComponent(match[2]) : null;
    }
    return inMemoryStorage.get(name) ?? null;
  }

  private removeCookie(name: string, optionsStr: string): void {
    if (isDocumentCookieAvailable()) {
      const encodedName = encodeURIComponent(name);
      document.cookie = `${encodedName}=; expires=Thu, 01 Jan 1970 00:00:00 GMT${optionsStr}`;
    } else {
      inMemoryStorage.delete(name);
    }
  }

  // Internal write — used by all mutation methods to avoid duplicating encode/write logic
  private _writeValue(data: T, options: CookieOptions, eventType: CookieEventType, oldValue: T | null, encrypt?: boolean): void {
    const shouldEncrypt = encrypt ?? this.encryptByDefault;
    const encodedData = shouldEncrypt ? this.crypto.encrypt(JSON.stringify(data)) : JSON.stringify(data);
    const optionsStr = this.buildOptionsStr({ ...this.defaultOptions, ...options });
    this.writeCookie(this.storageKey, encodedData, optionsStr);
    this.notify({ type: eventType, storageKey: this.storageKey, newValue: data, oldValue });
  }

  private async _writeValueAsync(data: T, options: CookieOptions, eventType: CookieEventType, oldValue: T | null, encrypt?: boolean): Promise<void> {
    const shouldEncrypt = encrypt ?? this.encryptByDefault;
    const encodedData = shouldEncrypt ? await this.crypto.encryptAsync(JSON.stringify(data)) : JSON.stringify(data);
    const optionsStr = this.buildOptionsStr({ ...this.defaultOptions, ...options });
    this.writeCookie(this.storageKey, encodedData, optionsStr);
    this.notify({ type: eventType, storageKey: this.storageKey, newValue: data, oldValue });
  }

  set(value: T, options: CookieOptions = {}, { encrypt, merge }: { encrypt?: boolean; merge?: boolean } = {}): void {
    let finalValue = value;
    if (merge) {
      const current = this.get(undefined, true) || {} as T;
      finalValue = { ...current, ...value };
    }
    const oldValue = this.get(undefined, true);
    this._writeValue(finalValue, options, 'set', oldValue, encrypt);
  }

  async setAsync(value: T, options: CookieOptions = {}, { encrypt, merge }: { encrypt?: boolean; merge?: boolean } = {}): Promise<void> {
    let finalValue = value;
    if (merge) {
      const current = await this.getAsync(undefined, true) || {} as T;
      finalValue = { ...current, ...value };
    }
    const oldValue = await this.getAsync(undefined, true);
    await this._writeValueAsync(finalValue, options, 'set', oldValue, encrypt);
  }

  get<K extends keyof T>(field?: K, skipReencrypt = false): T | T[K] | null {
    try {
      const encodedData = this.readCookie(this.storageKey);
      if (!encodedData) return null;
      let parsedData: T;
      if (this.encryptByDefault) {
        const { decrypted, wasKeyRotated } = this.crypto.decrypt(encodedData);
        parsedData = JSON.parse(decrypted) as T;
        if (wasKeyRotated && !skipReencrypt) this.set(parsedData);
      } else {
        parsedData = JSON.parse(encodedData) as T;
      }
      if (field !== undefined && parsedData && field in parsedData) {
        return parsedData[field] ?? null;
      }
      return parsedData;
    } catch (error) {
      console.error('[js-cookie-encrypt] Failed to retrieve or decrypt cookie:', error);
      // Only remove own cookie — never wipe unrelated cookies
      this.removeCookie(this.storageKey, this.buildOptionsStr(this.defaultOptions));
      return null;
    }
  }

  async getAsync<K extends keyof T>(field?: K, skipReencrypt = false): Promise<T | T[K] | null> {
    try {
      const encodedData = this.readCookie(this.storageKey);
      if (!encodedData) return null;
      let parsedData: T;
      if (this.encryptByDefault) {
        const { decrypted, wasKeyRotated } = await this.crypto.decryptAsync(encodedData);
        parsedData = JSON.parse(decrypted) as T;
        if (wasKeyRotated && !skipReencrypt) await this.setAsync(parsedData);
      } else {
        parsedData = JSON.parse(encodedData) as T;
      }
      if (field !== undefined && parsedData && field in parsedData) {
        return parsedData[field] ?? null;
      }
      return parsedData;
    } catch (error) {
      console.error('[js-cookie-encrypt] Failed to retrieve or decrypt cookie:', error);
      this.removeCookie(this.storageKey, this.buildOptionsStr(this.defaultOptions));
      return null;
    }
  }

  getByPath<K extends Path<T> & string>(path: K): PathValue<T, K> | null {
    const data = this.get();
    if (!data) return null;
    const result = path.split('.').reduce((obj: any, key: string) => (obj != null ? obj[key] : undefined), data);
    return result !== undefined ? result as PathValue<T, K> : null;
  }

  async getByPathAsync<K extends Path<T> & string>(path: K): Promise<PathValue<T, K> | null> {
    const data = await this.getAsync();
    if (!data) return null;
    const result = path.split('.').reduce((obj: any, key: string) => (obj != null ? obj[key] : undefined), data);
    return result !== undefined ? result as PathValue<T, K> : null;
  }

  setByPath<K extends Path<T> & string>(path: K, value: PathValue<T, K>, options: CookieOptions = {}): void {
    const data = this.get(undefined, true) || {} as T;
    const parts = path.split('.');
    let current: any = data;
    for (let i = 0; i < parts.length - 1; i++) {
      if (!(parts[i] in current)) current[parts[i]] = {};
      current = current[parts[i]];
    }
    current[parts[parts.length - 1]] = value;
    this._writeValue(data, options, 'set', this.get(undefined, true));
  }

  async setByPathAsync<K extends Path<T> & string>(path: K, value: PathValue<T, K>, options: CookieOptions = {}): Promise<void> {
    const oldValue = await this.getAsync(undefined, true);
    const data = oldValue || {} as T;
    const parts = path.split('.');
    let current: any = data;
    for (let i = 0; i < parts.length - 1; i++) {
      if (!(parts[i] in current)) current[parts[i]] = {};
      current = current[parts[i]];
    }
    current[parts[parts.length - 1]] = value;
    await this._writeValueAsync(data, options, 'set', oldValue);
  }

  updateByPath<K extends Path<T> & string>(path: K, value: Partial<PathValue<T, K>>, options: CookieOptions = {}): void {
    const data = this.get(undefined, true) || {} as T;
    const parts = path.split('.');
    let current: any = data;
    for (let i = 0; i < parts.length - 1; i++) {
      if (!(parts[i] in current)) current[parts[i]] = {};
      current = current[parts[i]];
    }
    const key = parts[parts.length - 1];
    current[key] = (key in current && typeof current[key] === 'object' && typeof value === 'object')
      ? { ...current[key], ...value }
      : value;
    this._writeValue(data, options, 'update', this.get(undefined, true));
  }

  async updateByPathAsync<K extends Path<T> & string>(path: K, value: Partial<PathValue<T, K>>, options: CookieOptions = {}): Promise<void> {
    const oldValue = await this.getAsync(undefined, true);
    const data = oldValue || {} as T;
    const parts = path.split('.');
    let current: any = data;
    for (let i = 0; i < parts.length - 1; i++) {
      if (!(parts[i] in current)) current[parts[i]] = {};
      current = current[parts[i]];
    }
    const key = parts[parts.length - 1];
    current[key] = (key in current && typeof current[key] === 'object' && typeof value === 'object')
      ? { ...current[key], ...value }
      : value;
    await this._writeValueAsync(data, options, 'update', oldValue);
  }

  deleteByPath<K extends Path<T> & string>(path: K): void {
    const data = this.get(undefined, true) || {} as T;
    const oldValue = JSON.parse(JSON.stringify(data)) as T;
    const parts = path.split('.');
    let current: any = data;
    for (let i = 0; i < parts.length - 1; i++) {
      if (!(parts[i] in current)) return;
      current = current[parts[i]];
    }
    const lastKey = parts[parts.length - 1];
    if (lastKey in current) {
      delete current[lastKey];
      this._writeValue(data, {}, 'delete', oldValue);
    }
  }

  async deleteByPathAsync<K extends Path<T> & string>(path: K): Promise<void> {
    const data = await this.getAsync(undefined, true) || {} as T;
    const oldValue = JSON.parse(JSON.stringify(data)) as T;
    const parts = path.split('.');
    let current: any = data;
    for (let i = 0; i < parts.length - 1; i++) {
      if (!(parts[i] in current)) return;
      current = current[parts[i]];
    }
    const lastKey = parts[parts.length - 1];
    if (lastKey in current) {
      delete current[lastKey];
      await this._writeValueAsync(data, {}, 'delete', oldValue);
    }
  }

  // duration in seconds
  extend(durationSecs: number, options: CookieOptions = {}): void {
    const data = this.get(undefined, true);
    if (data) this._writeValue(data, { ...options, expires: new Date(Date.now() + durationSecs * 1000) }, 'set', data);
  }

  // duration in seconds
  async extendAsync(durationSecs: number, options: CookieOptions = {}): Promise<void> {
    const data = await this.getAsync(undefined, true);
    if (data) await this._writeValueAsync(data, { ...options, expires: new Date(Date.now() + durationSecs * 1000) }, 'set', data);
  }

  static getAllCookies(): Record<string, string> {
    const cookies: Record<string, string> = {};
    if (isDocumentCookieAvailable()) {
      document.cookie.split(';').forEach(cookie => {
        const eqIdx = cookie.indexOf('=');
        if (eqIdx === -1) return;
        const name = decodeURIComponent(cookie.substring(0, eqIdx).trim());
        const value = decodeURIComponent(cookie.substring(eqIdx + 1).trim());
        if (name) cookies[name] = value;
      });
    } else {
      inMemoryStorage.forEach((value, name) => { cookies[name] = value; });
    }
    return cookies;
  }

  static clearAll(domain?: string, path: string = '/', clearSubDomain: boolean = false): void {
    if (isDocumentCookieAvailable()) {
      const cookies = JsCookieEncrypt.getAllCookies();
      Object.keys(cookies).forEach(name => {
        const encodedName = encodeURIComponent(name);
        let str = `${encodedName}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=${path}`;
        if (domain) str += `; domain=${domain}`;
        document.cookie = str;
      });

      if (clearSubDomain && typeof location !== 'undefined') {
        const hostnameParts = location.hostname.split('.');
        const isLocalhost = hostnameParts.length === 1 && hostnameParts[0] === 'localhost';
        const subDomain = (!isLocalhost && hostnameParts.length > 1)
          ? hostnameParts.slice(1).join('.')
          : '';
        if (subDomain) {
          Object.keys(cookies).forEach(name => {
            const encodedName = encodeURIComponent(name);
            document.cookie = `${encodedName}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=${path}; domain=${subDomain}`;
          });
        }
      }
    } else {
      inMemoryStorage.clear();
    }
  }

  has<K extends Path<T> & string>(pathOrField?: K): boolean {
    const data = this.get(undefined, true);
    if (!data) return false;
    if (!pathOrField) return true;
    let current: any = data;
    for (const part of pathOrField.split('.')) {
      if (current === null || typeof current !== 'object' || !(part in current)) return false;
      current = current[part];
    }
    return true;
  }

  async hasAsync<K extends Path<T> & string>(pathOrField?: K): Promise<boolean> {
    const data = await this.getAsync(undefined, true);
    if (!data) return false;
    if (!pathOrField) return true;
    let current: any = data;
    for (const part of pathOrField.split('.')) {
      if (current === null || typeof current !== 'object' || !(part in current)) return false;
      current = current[part];
    }
    return true;
  }

  update(updates: Partial<T>, options: CookieOptions = {}): void {
    const currentData = this.get(undefined, true) || {} as T;
    const updatedData = { ...currentData, ...updates };
    this._writeValue(updatedData, options, 'update', currentData);
  }

  async updateAsync(updates: Partial<T>, options: CookieOptions = {}): Promise<void> {
    const currentData = await this.getAsync(undefined, true) || {} as T;
    const updatedData = { ...currentData, ...updates };
    await this._writeValueAsync(updatedData, options, 'update', currentData);
  }

  deleteFields(fields: Array<keyof T>): void {
    const currentData = this.get(undefined, true) || {} as T;
    const oldValue = { ...currentData };
    fields.forEach(field => delete currentData[field]);
    this._writeValue(currentData, {}, 'delete', oldValue as T);
  }

  async deleteFieldsAsync(fields: Array<keyof T>): Promise<void> {
    const currentData = await this.getAsync(undefined, true) || {} as T;
    const oldValue = { ...currentData };
    fields.forEach(field => delete currentData[field]);
    await this._writeValueAsync(currentData, {}, 'delete', oldValue as T);
  }

  clear(options: CookieOptions = {}): void {
    const mergedOptions = { ...this.defaultOptions, ...options };
    const oldValue = this.get(undefined, true);
    this.removeCookie(this.storageKey, this.buildOptionsStr(mergedOptions));
    this.notify({ type: 'clear', storageKey: this.storageKey, oldValue });
  }

  async clearAsync(options: CookieOptions = {}): Promise<void> {
    const mergedOptions = { ...this.defaultOptions, ...options };
    const oldValue = await this.getAsync(undefined, true);
    this.removeCookie(this.storageKey, this.buildOptionsStr(mergedOptions));
    this.notify({ type: 'clear', storageKey: this.storageKey, oldValue });
  }
}

export default JsCookieEncrypt;
