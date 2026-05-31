"use strict";
/*! js-cookie-encrypt v1.1.0 | MIT (c) 2026 Abdullah Al Fahim | https://github.com/abfahimb/js-cookie-encrypt */
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.JsCookieEncrypt = void 0;
const inMemoryStorage = new Map();
function isDocumentCookieAvailable() {
    if (typeof document === 'undefined')
        return false;
    try {
        const testKey = '__js_cookie_encrypt_test__';
        document.cookie = `${testKey}=1; path=/; SameSite=lax`;
        const available = document.cookie.indexOf(testKey) !== -1;
        document.cookie = `${testKey}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; SameSite=lax`;
        return available;
    }
    catch (_a) {
        return false;
    }
}
function escapeRegExp(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
// AES-GCM 256-bit via Web Cryptography API
class AsyncCookieCrypto {
    constructor() {
        this.keyCache = new Map();
    }
    getCrypto() {
        var _a, _b;
        if (typeof globalThis !== 'undefined' && ((_a = globalThis.crypto) === null || _a === void 0 ? void 0 : _a.subtle)) {
            return globalThis.crypto;
        }
        if (typeof window !== 'undefined' && ((_b = window.crypto) === null || _b === void 0 ? void 0 : _b.subtle)) {
            return window.crypto;
        }
        // SSR / Node.js — use new Function instead of eval to avoid CSP violations
        try {
            // eslint-disable-next-line no-new-func
            const requireFn = new Function('return require');
            const nodeCrypto = requireFn()('crypto');
            if (nodeCrypto.webcrypto)
                return nodeCrypto.webcrypto;
        }
        catch ( /* fall through */_c) { /* fall through */ }
        throw new Error('[js-cookie-encrypt] Web Cryptography API (SubtleCrypto) is not available in this environment.');
    }
    getCryptoKey(privateKey) {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.keyCache.has(privateKey)) {
                return this.keyCache.get(privateKey);
            }
            const cryptoInstance = this.getCrypto();
            const hash = yield cryptoInstance.subtle.digest('SHA-256', new TextEncoder().encode(privateKey));
            const cryptoKey = yield cryptoInstance.subtle.importKey('raw', hash, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
            this.keyCache.set(privateKey, cryptoKey);
            return cryptoKey;
        });
    }
    encrypt(data, privateKey) {
        return __awaiter(this, void 0, void 0, function* () {
            const cryptoInstance = this.getCrypto();
            const key = yield this.getCryptoKey(privateKey);
            const iv = cryptoInstance.getRandomValues(new Uint8Array(12));
            const ciphertext = yield cryptoInstance.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(data));
            const combined = new Uint8Array(iv.length + ciphertext.byteLength);
            combined.set(iv, 0);
            combined.set(new Uint8Array(ciphertext), iv.length);
            // Avoid spread operator — stack overflow on large payloads
            let binaryStr = '';
            for (let i = 0; i < combined.length; i++)
                binaryStr += String.fromCharCode(combined[i]);
            return btoa(binaryStr);
        });
    }
    decrypt(encryptedData, privateKey) {
        return __awaiter(this, void 0, void 0, function* () {
            const cryptoInstance = this.getCrypto();
            const key = yield this.getCryptoKey(privateKey);
            const binaryStr = atob(encryptedData);
            const combined = new Uint8Array(binaryStr.length);
            for (let i = 0; i < binaryStr.length; i++)
                combined[i] = binaryStr.charCodeAt(i);
            if (combined.length < 12)
                throw new Error('[js-cookie-encrypt] Invalid encrypted data: too short');
            const decrypted = yield cryptoInstance.subtle.decrypt({ name: 'AES-GCM', iv: combined.slice(0, 12) }, key, combined.slice(12));
            return new TextDecoder().decode(decrypted);
        });
    }
}
// Synchronous legacy ciphers (RC4, XOR)
// WARNING: RC4 and XOR are not suitable for high-security scenarios. Use AES-GCM (*Async methods) in production.
class CookieCrypto {
    constructor(config) {
        const keys = config.privateKey;
        this.privateKeys = Array.isArray(keys) ? keys : [keys];
        this.saltLength = config.saltLength || 16;
        this.algorithm = config.algorithm || 'rc4';
        this.asyncCrypto = new AsyncCookieCrypto();
        if (this.algorithm === 'rc4' || this.algorithm === 'xor') {
            console.warn('[js-cookie-encrypt] RC4 and XOR are legacy ciphers with known weaknesses. Use algorithm: "aes-gcm" with *Async methods for production security.');
        }
    }
    generateRandomSalt() {
        const randomBytes = new Uint8Array(this.saltLength);
        const cryptoObj = (typeof globalThis !== 'undefined' && globalThis.crypto)
            ? globalThis.crypto
            : (typeof window !== 'undefined' ? window.crypto : null);
        if (!(cryptoObj === null || cryptoObj === void 0 ? void 0 : cryptoObj.getRandomValues)) {
            throw new Error('[js-cookie-encrypt] Cryptographically secure random number generator not available. Cannot generate salt safely.');
        }
        cryptoObj.getRandomValues(randomBytes);
        return Array.from(randomBytes, b => String.fromCharCode(b)).join('');
    }
    // Keyed FNV-1a — NOT a MAC; provides basic tamper detection only when key is kept secret.
    // For cryptographic integrity guarantees, use AES-GCM which provides authenticated encryption.
    calculateChecksum(data, key) {
        let hash = 0x811c9dc5;
        const combined = key + data + key; // key-wrap reduces length-extension risk
        for (let i = 0; i < combined.length; i++) {
            hash ^= combined.charCodeAt(i);
            hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
        }
        return (hash >>> 0).toString(16);
    }
    expandKey(key, salt) {
        const maxLen = Math.max(key.length, salt.length);
        const out = [];
        for (let i = 0; i < maxLen; i++) {
            out.push(String.fromCharCode(key.charCodeAt(i % key.length) ^ salt.charCodeAt(i % salt.length)));
        }
        return out.join('');
    }
    xorEncrypt(data, key) {
        const salt = this.generateRandomSalt();
        const expandedKey = this.expandKey(key, salt);
        let result = '';
        for (let i = 0; i < data.length; i++) {
            result += String.fromCharCode(data.charCodeAt(i) ^ expandedKey.charCodeAt(i % expandedKey.length));
        }
        const bytes = new TextEncoder().encode(salt + result);
        let binaryStr = '';
        for (let i = 0; i < bytes.length; i++)
            binaryStr += String.fromCharCode(bytes[i]);
        return btoa(binaryStr);
    }
    xorDecrypt(encryptedData, key) {
        const binaryStr = atob(encryptedData);
        const bytes = new Uint8Array(binaryStr.length);
        for (let i = 0; i < binaryStr.length; i++)
            bytes[i] = binaryStr.charCodeAt(i);
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
    rc4Encrypt(data, key) {
        const salt = this.generateRandomSalt();
        const derivedKey = key + salt;
        const binBytes = new TextEncoder().encode(data);
        let binData = '';
        for (let i = 0; i < binBytes.length; i++)
            binData += String.fromCharCode(binBytes[i]);
        const encrypted = this.rc4(binData, derivedKey);
        const checksum = this.calculateChecksum(binData, key);
        return btoa(salt + ':' + checksum + ':' + encrypted);
    }
    rc4Decrypt(encryptedData, key) {
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
        for (let i = 0; i < binData.length; i++)
            bytes[i] = binData.charCodeAt(i);
        return new TextDecoder().decode(bytes);
    }
    rc4(data, key) {
        const s = new Uint8Array(256);
        for (let i = 0; i < 256; i++)
            s[i] = i;
        let j = 0;
        for (let i = 0; i < 256; i++) {
            j = (j + s[i] + key.charCodeAt(i % key.length)) % 256;
            const tmp = s[i];
            s[i] = s[j];
            s[j] = tmp;
        }
        let i = 0;
        j = 0;
        let result = '';
        for (let k = 0; k < data.length; k++) {
            i = (i + 1) % 256;
            j = (j + s[i]) % 256;
            const tmp = s[i];
            s[i] = s[j];
            s[j] = tmp;
            result += String.fromCharCode(data.charCodeAt(k) ^ s[(s[i] + s[j]) % 256]);
        }
        return result;
    }
    encrypt(data) {
        if (this.algorithm === 'aes-gcm') {
            throw new Error('[js-cookie-encrypt] AES-GCM requires the async API (*Async methods).');
        }
        const key = this.privateKeys[0];
        return this.algorithm === 'rc4'
            ? 'rc4:' + this.rc4Encrypt(data, key)
            : this.xorEncrypt(data, key);
    }
    decrypt(encryptedData) {
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
            }
            catch (_a) {
                if (idx === this.privateKeys.length - 1) {
                    try {
                        JSON.parse(encryptedData);
                        return { decrypted: encryptedData, wasKeyRotated: false };
                    }
                    catch (_b) {
                        throw new Error('[js-cookie-encrypt] Failed to decrypt data with any available key');
                    }
                }
            }
        }
        throw new Error('[js-cookie-encrypt] Failed to decrypt data with any available key');
    }
    encryptAsync(data) {
        return __awaiter(this, void 0, void 0, function* () {
            const key = this.privateKeys[0];
            if (this.algorithm === 'aes-gcm') {
                return 'gcm:' + (yield this.asyncCrypto.encrypt(data, key));
            }
            return this.algorithm === 'rc4'
                ? 'rc4:' + this.rc4Encrypt(data, key)
                : this.xorEncrypt(data, key);
        });
    }
    decryptAsync(encryptedData) {
        return __awaiter(this, void 0, void 0, function* () {
            const isGcm = encryptedData.startsWith('gcm:');
            const isRc4 = encryptedData.startsWith('rc4:');
            const payload = (isGcm || isRc4) ? encryptedData.substring(4) : encryptedData;
            for (let idx = 0; idx < this.privateKeys.length; idx++) {
                const key = this.privateKeys[idx];
                try {
                    let decrypted;
                    if (isGcm) {
                        decrypted = yield this.asyncCrypto.decrypt(payload, key);
                    }
                    else if (isRc4) {
                        decrypted = this.rc4Decrypt(payload, key);
                    }
                    else {
                        decrypted = this.xorDecrypt(payload, key);
                    }
                    JSON.parse(decrypted);
                    return { decrypted, wasKeyRotated: idx > 0 };
                }
                catch (_a) {
                    if (idx === this.privateKeys.length - 1) {
                        try {
                            JSON.parse(encryptedData);
                            return { decrypted: encryptedData, wasKeyRotated: false };
                        }
                        catch (_b) {
                            throw new Error('[js-cookie-encrypt] Failed to decrypt data with any available key');
                        }
                    }
                }
            }
            throw new Error('[js-cookie-encrypt] Failed to decrypt data with any available key');
        });
    }
}
class JsCookieEncrypt {
    constructor(config) {
        var _a;
        this.listeners = new Set();
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
        this.encryptByDefault = (_a = config.cryptoConfig.encryptByDefault) !== null && _a !== void 0 ? _a : true;
    }
    static isSupported() {
        return isDocumentCookieAvailable();
    }
    subscribe(listener) {
        this.listeners.add(listener);
        return () => this.listeners.delete(listener);
    }
    notify(event) {
        this.listeners.forEach(listener => {
            try {
                listener(event);
            }
            catch (e) {
                console.error('[js-cookie-encrypt] Error in event listener:', e);
            }
        });
    }
    buildOptionsStr(options) {
        let str = '';
        if (options.path)
            str += `; path=${options.path}`;
        if (options.expires) {
            // expires as number = milliseconds from now
            const date = typeof options.expires === 'number'
                ? new Date(Date.now() + options.expires)
                : options.expires;
            str += `; expires=${date.toUTCString()}`;
        }
        if (options.domain)
            str += `; domain=${options.domain}`;
        if (options.secure)
            str += '; Secure';
        if (options.sameSite)
            str += `; SameSite=${options.sameSite}`;
        if (options.httpOnly) {
            console.warn('[js-cookie-encrypt] httpOnly cannot be set via JavaScript. Use the server Set-Cookie response header.');
        }
        return str;
    }
    writeCookie(name, value, optionsStr) {
        const encodedName = encodeURIComponent(name);
        const encodedValue = encodeURIComponent(value);
        const fullCookie = `${encodedName}=${encodedValue}${optionsStr}`;
        if (fullCookie.length > 4096) {
            console.warn(`[js-cookie-encrypt] Cookie "${name}" is ${fullCookie.length} bytes, exceeding the 4KB browser limit. It may be silently rejected.`);
        }
        if (isDocumentCookieAvailable()) {
            document.cookie = fullCookie;
        }
        else {
            inMemoryStorage.set(name, value);
        }
    }
    readCookie(name) {
        var _a;
        if (isDocumentCookieAvailable()) {
            // Escape both the encoded name and its regex special chars to prevent regex injection
            const encodedName = escapeRegExp(encodeURIComponent(name));
            const match = document.cookie.match(new RegExp('(^| )' + encodedName + '=([^;]+)'));
            return match ? decodeURIComponent(match[2]) : null;
        }
        return (_a = inMemoryStorage.get(name)) !== null && _a !== void 0 ? _a : null;
    }
    removeCookie(name, optionsStr) {
        if (isDocumentCookieAvailable()) {
            const encodedName = encodeURIComponent(name);
            document.cookie = `${encodedName}=; expires=Thu, 01 Jan 1970 00:00:00 GMT${optionsStr}`;
        }
        else {
            inMemoryStorage.delete(name);
        }
    }
    // Internal write — used by all mutation methods to avoid duplicating encode/write logic
    _writeValue(data, options, eventType, oldValue, encrypt) {
        const shouldEncrypt = encrypt !== null && encrypt !== void 0 ? encrypt : this.encryptByDefault;
        const encodedData = shouldEncrypt ? this.crypto.encrypt(JSON.stringify(data)) : JSON.stringify(data);
        const optionsStr = this.buildOptionsStr(Object.assign(Object.assign({}, this.defaultOptions), options));
        this.writeCookie(this.storageKey, encodedData, optionsStr);
        this.notify({ type: eventType, storageKey: this.storageKey, newValue: data, oldValue });
    }
    _writeValueAsync(data, options, eventType, oldValue, encrypt) {
        return __awaiter(this, void 0, void 0, function* () {
            const shouldEncrypt = encrypt !== null && encrypt !== void 0 ? encrypt : this.encryptByDefault;
            const encodedData = shouldEncrypt ? yield this.crypto.encryptAsync(JSON.stringify(data)) : JSON.stringify(data);
            const optionsStr = this.buildOptionsStr(Object.assign(Object.assign({}, this.defaultOptions), options));
            this.writeCookie(this.storageKey, encodedData, optionsStr);
            this.notify({ type: eventType, storageKey: this.storageKey, newValue: data, oldValue });
        });
    }
    set(value, options = {}, { encrypt, merge } = {}) {
        let finalValue = value;
        if (merge) {
            const current = this.get(undefined, true) || {};
            finalValue = Object.assign(Object.assign({}, current), value);
        }
        const oldValue = this.get(undefined, true);
        this._writeValue(finalValue, options, 'set', oldValue, encrypt);
    }
    setAsync(value, options = {}, { encrypt, merge } = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            let finalValue = value;
            if (merge) {
                const current = (yield this.getAsync(undefined, true)) || {};
                finalValue = Object.assign(Object.assign({}, current), value);
            }
            const oldValue = yield this.getAsync(undefined, true);
            yield this._writeValueAsync(finalValue, options, 'set', oldValue, encrypt);
        });
    }
    get(field, skipReencrypt = false) {
        var _a;
        try {
            const encodedData = this.readCookie(this.storageKey);
            if (!encodedData)
                return null;
            let parsedData;
            if (this.encryptByDefault) {
                const { decrypted, wasKeyRotated } = this.crypto.decrypt(encodedData);
                parsedData = JSON.parse(decrypted);
                if (wasKeyRotated && !skipReencrypt)
                    this.set(parsedData);
            }
            else {
                parsedData = JSON.parse(encodedData);
            }
            if (field !== undefined && parsedData && field in parsedData) {
                return (_a = parsedData[field]) !== null && _a !== void 0 ? _a : null;
            }
            return parsedData;
        }
        catch (error) {
            console.error('[js-cookie-encrypt] Failed to retrieve or decrypt cookie:', error);
            // Only remove own cookie — never wipe unrelated cookies
            this.removeCookie(this.storageKey, this.buildOptionsStr(this.defaultOptions));
            return null;
        }
    }
    getAsync(field, skipReencrypt = false) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const encodedData = this.readCookie(this.storageKey);
                if (!encodedData)
                    return null;
                let parsedData;
                if (this.encryptByDefault) {
                    const { decrypted, wasKeyRotated } = yield this.crypto.decryptAsync(encodedData);
                    parsedData = JSON.parse(decrypted);
                    if (wasKeyRotated && !skipReencrypt)
                        yield this.setAsync(parsedData);
                }
                else {
                    parsedData = JSON.parse(encodedData);
                }
                if (field !== undefined && parsedData && field in parsedData) {
                    return (_a = parsedData[field]) !== null && _a !== void 0 ? _a : null;
                }
                return parsedData;
            }
            catch (error) {
                console.error('[js-cookie-encrypt] Failed to retrieve or decrypt cookie:', error);
                this.removeCookie(this.storageKey, this.buildOptionsStr(this.defaultOptions));
                return null;
            }
        });
    }
    getByPath(path) {
        const data = this.get();
        if (!data)
            return null;
        const result = path.split('.').reduce((obj, key) => (obj != null ? obj[key] : undefined), data);
        return result !== undefined ? result : null;
    }
    getByPathAsync(path) {
        return __awaiter(this, void 0, void 0, function* () {
            const data = yield this.getAsync();
            if (!data)
                return null;
            const result = path.split('.').reduce((obj, key) => (obj != null ? obj[key] : undefined), data);
            return result !== undefined ? result : null;
        });
    }
    setByPath(path, value, options = {}) {
        const data = this.get(undefined, true) || {};
        const parts = path.split('.');
        let current = data;
        for (let i = 0; i < parts.length - 1; i++) {
            if (!(parts[i] in current))
                current[parts[i]] = {};
            current = current[parts[i]];
        }
        current[parts[parts.length - 1]] = value;
        this._writeValue(data, options, 'set', this.get(undefined, true));
    }
    setByPathAsync(path, value, options = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const oldValue = yield this.getAsync(undefined, true);
            const data = oldValue || {};
            const parts = path.split('.');
            let current = data;
            for (let i = 0; i < parts.length - 1; i++) {
                if (!(parts[i] in current))
                    current[parts[i]] = {};
                current = current[parts[i]];
            }
            current[parts[parts.length - 1]] = value;
            yield this._writeValueAsync(data, options, 'set', oldValue);
        });
    }
    updateByPath(path, value, options = {}) {
        const data = this.get(undefined, true) || {};
        const parts = path.split('.');
        let current = data;
        for (let i = 0; i < parts.length - 1; i++) {
            if (!(parts[i] in current))
                current[parts[i]] = {};
            current = current[parts[i]];
        }
        const key = parts[parts.length - 1];
        current[key] = (key in current && typeof current[key] === 'object' && typeof value === 'object')
            ? Object.assign(Object.assign({}, current[key]), value) : value;
        this._writeValue(data, options, 'update', this.get(undefined, true));
    }
    updateByPathAsync(path, value, options = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const oldValue = yield this.getAsync(undefined, true);
            const data = oldValue || {};
            const parts = path.split('.');
            let current = data;
            for (let i = 0; i < parts.length - 1; i++) {
                if (!(parts[i] in current))
                    current[parts[i]] = {};
                current = current[parts[i]];
            }
            const key = parts[parts.length - 1];
            current[key] = (key in current && typeof current[key] === 'object' && typeof value === 'object')
                ? Object.assign(Object.assign({}, current[key]), value) : value;
            yield this._writeValueAsync(data, options, 'update', oldValue);
        });
    }
    deleteByPath(path) {
        const data = this.get(undefined, true) || {};
        const oldValue = JSON.parse(JSON.stringify(data));
        const parts = path.split('.');
        let current = data;
        for (let i = 0; i < parts.length - 1; i++) {
            if (!(parts[i] in current))
                return;
            current = current[parts[i]];
        }
        const lastKey = parts[parts.length - 1];
        if (lastKey in current) {
            delete current[lastKey];
            this._writeValue(data, {}, 'delete', oldValue);
        }
    }
    deleteByPathAsync(path) {
        return __awaiter(this, void 0, void 0, function* () {
            const data = (yield this.getAsync(undefined, true)) || {};
            const oldValue = JSON.parse(JSON.stringify(data));
            const parts = path.split('.');
            let current = data;
            for (let i = 0; i < parts.length - 1; i++) {
                if (!(parts[i] in current))
                    return;
                current = current[parts[i]];
            }
            const lastKey = parts[parts.length - 1];
            if (lastKey in current) {
                delete current[lastKey];
                yield this._writeValueAsync(data, {}, 'delete', oldValue);
            }
        });
    }
    // duration in seconds
    extend(durationSecs, options = {}) {
        const data = this.get(undefined, true);
        if (data)
            this._writeValue(data, Object.assign(Object.assign({}, options), { expires: new Date(Date.now() + durationSecs * 1000) }), 'set', data);
    }
    // duration in seconds
    extendAsync(durationSecs, options = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const data = yield this.getAsync(undefined, true);
            if (data)
                yield this._writeValueAsync(data, Object.assign(Object.assign({}, options), { expires: new Date(Date.now() + durationSecs * 1000) }), 'set', data);
        });
    }
    static getAllCookies() {
        const cookies = {};
        if (isDocumentCookieAvailable()) {
            document.cookie.split(';').forEach(cookie => {
                const eqIdx = cookie.indexOf('=');
                if (eqIdx === -1)
                    return;
                const name = decodeURIComponent(cookie.substring(0, eqIdx).trim());
                const value = decodeURIComponent(cookie.substring(eqIdx + 1).trim());
                if (name)
                    cookies[name] = value;
            });
        }
        else {
            inMemoryStorage.forEach((value, name) => { cookies[name] = value; });
        }
        return cookies;
    }
    static clearAll(domain, path = '/', clearSubDomain = false) {
        if (isDocumentCookieAvailable()) {
            const cookies = JsCookieEncrypt.getAllCookies();
            Object.keys(cookies).forEach(name => {
                const encodedName = encodeURIComponent(name);
                let str = `${encodedName}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=${path}`;
                if (domain)
                    str += `; domain=${domain}`;
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
        }
        else {
            inMemoryStorage.clear();
        }
    }
    has(pathOrField) {
        const data = this.get(undefined, true);
        if (!data)
            return false;
        if (!pathOrField)
            return true;
        let current = data;
        for (const part of pathOrField.split('.')) {
            if (current === null || typeof current !== 'object' || !(part in current))
                return false;
            current = current[part];
        }
        return true;
    }
    hasAsync(pathOrField) {
        return __awaiter(this, void 0, void 0, function* () {
            const data = yield this.getAsync(undefined, true);
            if (!data)
                return false;
            if (!pathOrField)
                return true;
            let current = data;
            for (const part of pathOrField.split('.')) {
                if (current === null || typeof current !== 'object' || !(part in current))
                    return false;
                current = current[part];
            }
            return true;
        });
    }
    update(updates, options = {}) {
        const currentData = this.get(undefined, true) || {};
        const updatedData = Object.assign(Object.assign({}, currentData), updates);
        this._writeValue(updatedData, options, 'update', currentData);
    }
    updateAsync(updates, options = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const currentData = (yield this.getAsync(undefined, true)) || {};
            const updatedData = Object.assign(Object.assign({}, currentData), updates);
            yield this._writeValueAsync(updatedData, options, 'update', currentData);
        });
    }
    deleteFields(fields) {
        const currentData = this.get(undefined, true) || {};
        const oldValue = Object.assign({}, currentData);
        fields.forEach(field => delete currentData[field]);
        this._writeValue(currentData, {}, 'delete', oldValue);
    }
    deleteFieldsAsync(fields) {
        return __awaiter(this, void 0, void 0, function* () {
            const currentData = (yield this.getAsync(undefined, true)) || {};
            const oldValue = Object.assign({}, currentData);
            fields.forEach(field => delete currentData[field]);
            yield this._writeValueAsync(currentData, {}, 'delete', oldValue);
        });
    }
    clear(options = {}) {
        const mergedOptions = Object.assign(Object.assign({}, this.defaultOptions), options);
        const oldValue = this.get(undefined, true);
        this.removeCookie(this.storageKey, this.buildOptionsStr(mergedOptions));
        this.notify({ type: 'clear', storageKey: this.storageKey, oldValue });
    }
    clearAsync(options = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const mergedOptions = Object.assign(Object.assign({}, this.defaultOptions), options);
            const oldValue = yield this.getAsync(undefined, true);
            this.removeCookie(this.storageKey, this.buildOptionsStr(mergedOptions));
            this.notify({ type: 'clear', storageKey: this.storageKey, oldValue });
        });
    }
}
exports.JsCookieEncrypt = JsCookieEncrypt;
exports.default = JsCookieEncrypt;
//# sourceMappingURL=js-cookie-encrypt.js.map