"use strict";
/*! encrypt-cookiejs v1.0.2 | MIT (c) 2024 Abdullah Al Fahim | https://github.com/abfahimb/encrypt-cookieJS */
Object.defineProperty(exports, "__esModule", { value: true });
exports.EncryptCookie = void 0;
// Enhanced CookieCrypto class
class CookieCrypto {
    constructor(config) {
        this.privateKey = config.privateKey;
        this.saltLength = config.saltLength || 16;
    }
    generateRandomSalt() {
        const randomBytes = new Uint8Array(this.saltLength);
        window.crypto.getRandomValues(randomBytes);
        return Array.from(randomBytes, (byte) => String.fromCharCode(byte)).join('');
    }
    expandKey(key, salt) {
        const expandedKey = [];
        for (let i = 0; i < Math.max(key === null || key === void 0 ? void 0 : key.length, salt === null || salt === void 0 ? void 0 : salt.length); i++) {
            const keyChar = key.charCodeAt(i % (key === null || key === void 0 ? void 0 : key.length));
            const saltChar = salt.charCodeAt(i % (salt === null || salt === void 0 ? void 0 : salt.length));
            expandedKey.push(String.fromCharCode(keyChar ^ saltChar));
        }
        return expandedKey.join('');
    }
    xorEncryptDecrypt(data, key) {
        const salt = this.generateRandomSalt();
        const expandedKey = this.expandKey(key, salt);
        let result = '';
        for (let i = 0; i < (data === null || data === void 0 ? void 0 : data.length); i++) {
            result += String.fromCharCode(data.charCodeAt(i) ^ expandedKey.charCodeAt(i % (expandedKey === null || expandedKey === void 0 ? void 0 : expandedKey.length)));
        }
        return this.encodeToBase64(salt + result);
    }
    encodeToBase64(data) {
        return btoa(unescape(encodeURIComponent(data)));
    }
    decodeFromBase64(data) {
        return decodeURIComponent(escape(atob(data)));
    }
    encrypt(data) {
        return this.xorEncryptDecrypt(data, this.privateKey);
    }
    decrypt(encryptedData) {
        const decoded = this.decodeFromBase64(encryptedData);
        const salt = decoded.substring(0, this.saltLength);
        const encryptedMessage = decoded.substring(this.saltLength);
        const expandedKey = this.expandKey(this.privateKey, salt);
        let result = '';
        for (let i = 0; i < (encryptedMessage === null || encryptedMessage === void 0 ? void 0 : encryptedMessage.length); i++) {
            result += String.fromCharCode(encryptedMessage.charCodeAt(i) ^ expandedKey.charCodeAt(i % (expandedKey === null || expandedKey === void 0 ? void 0 : expandedKey.length)));
        }
        return result;
    }
}
// Main EncryptCookie class with enhanced features
class EncryptCookie {
    constructor(config) {
        var _a;
        this.storageKey = config.storageKey;
        this.crypto = new CookieCrypto(config.cryptoConfig);
        this.defaultOptions = config.defaultOptions || {};
        this.encryptByDefault = (_a = config.cryptoConfig.encryptByDefault) !== null && _a !== void 0 ? _a : true;
    }
    set(value, options = {}, { encrypt, merge } = {}) {
        if (typeof document === 'undefined')
            return;
        let finalValue = value;
        if (merge) {
            const currentValue = this.get() || {};
            finalValue = Object.assign(Object.assign({}, currentValue), value);
        }
        const shouldEncrypt = encrypt !== null && encrypt !== void 0 ? encrypt : this.encryptByDefault;
        const mergedOptions = Object.assign(Object.assign({}, this.defaultOptions), options);
        const encodedData = shouldEncrypt
            ? this.crypto.encrypt(JSON.stringify(finalValue))
            : JSON.stringify(finalValue);
        let cookieString = `${this.storageKey}=${encodedData}`;
        // Append cookie options in the same way as in the provided snippet
        if (mergedOptions.path) {
            cookieString += `; path=${mergedOptions.path}`;
        }
        if (mergedOptions.expires) {
            const expiresDate = typeof mergedOptions.expires === 'number'
                ? new Date(Date.now() + mergedOptions.expires)
                : mergedOptions.expires;
            cookieString += `; expires=${expiresDate.toUTCString()}`;
        }
        if (mergedOptions.domain) {
            cookieString += `; domain=${mergedOptions.domain}`;
        }
        if (mergedOptions.secure) {
            cookieString += '; secure';
        }
        if (mergedOptions.sameSite) {
            cookieString += `; samesite=${mergedOptions.sameSite}`;
        }
        if (mergedOptions.httpOnly) {
            cookieString += '; httponly';
        }
        // Set the cookie
        document.cookie = cookieString;
    }
    // Get value by nested path
    getByPath(path) {
        const data = this.get();
        if (!data)
            return null;
        return path.toString().split('.').reduce((obj, key) => {
            return obj && obj[key];
        }, data);
    }
    // Set value by nested path
    setByPath(path, value, options = {}) {
        const data = this.get() || {};
        const pathParts = path.toString().split('.');
        let current = data;
        for (let i = 0; i < (pathParts === null || pathParts === void 0 ? void 0 : pathParts.length) - 1; i++) {
            const key = pathParts[i];
            if (!(key in current)) {
                current[key] = {};
            }
            current = current[key];
        }
        current[pathParts[(pathParts === null || pathParts === void 0 ? void 0 : pathParts.length) - 1]] = value;
        this.set(data, options);
    }
    updateByPath(path, value, options = {}) {
        const data = this.get() || {};
        const pathParts = path.toString().split('.');
        let current = data;
        for (let i = 0; i < (pathParts === null || pathParts === void 0 ? void 0 : pathParts.length) - 1; i++) {
            const key = pathParts[i];
            if (!(key in current)) {
                current[key] = {};
            }
            current = current[key];
        }
        const key = pathParts[(pathParts === null || pathParts === void 0 ? void 0 : pathParts.length) - 1];
        if (key in current && typeof current[key] === 'object' && typeof value === 'object') {
            // Merge the objects if the key exists and both are objects
            current[key] = Object.assign(Object.assign({}, current[key]), value);
        }
        else {
            // Otherwise, just set the value
            current[key] = value;
        }
        this.set(data, options);
    }
    deleteByPath(path) {
        if (typeof document === 'undefined')
            return;
        const data = this.get() || {};
        const pathParts = path.toString().split('.');
        let current = data;
        // Traverse the path to get to the parent object
        for (let i = 0; i < pathParts.length - 1; i++) {
            const key = pathParts[i];
            if (!(key in current)) {
                return; // Path does not exist, nothing to delete
            }
            current = current[key];
        }
        const lastKey = pathParts[pathParts.length - 1];
        if (lastKey in current) {
            delete current[lastKey]; // Delete the field at the path
            this.set(data); // Update the stored data
        }
    }
    // Check if cookie exists
    has(field) {
        const data = this.get();
        if (!data)
            return false;
        if (field) {
            // Type guard to ensure `data` is an object
            if (typeof data === 'object' && data !== null) {
                return field in data;
            }
            return false;
        }
        return true;
    }
    // Extend cookie expiration
    extend(duration, options = {}) {
        const data = this.get();
        if (data) {
            this.set(data, Object.assign(Object.assign({}, options), { expires: new Date(Date.now() + duration * 1000) }));
        }
    }
    // Get all cookies with same domain
    static getAllCookies(domain) {
        const cookies = {};
        if (typeof document === 'undefined')
            return cookies;
        document.cookie.split(';').forEach(cookie => {
            const [name, value] = cookie.split('=').map(c => c.trim());
            if (!domain || cookie.includes(`domain=${domain}`)) {
                cookies[name] = value;
            }
        });
        return cookies;
    }
    // Clear all cookies with same domain
    static clearAll(domain, path = '/') {
        const cookies = EncryptCookie.getAllCookies(domain);
        Object.keys(cookies).forEach(name => {
            let cookieString = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=${path}`;
            if (domain)
                cookieString += `; domain=${domain}`;
            document.cookie = cookieString;
        });
    }
    // Original methods with some enhancements
    get(field) {
        try {
            if (typeof document === 'undefined')
                return null;
            const match = document.cookie.match(new RegExp('(^| )' + this.storageKey + '=([^;]+)'));
            const encodedData = match ? match[2] : null;
            if (!encodedData)
                return null;
            let parsedData;
            if (this.encryptByDefault) {
                parsedData = JSON.parse(this.crypto.decrypt(encodedData));
            }
            else {
                parsedData = JSON.parse(encodedData);
            }
            if (field && parsedData && field in parsedData) {
                return parsedData[field] || null;
            }
            return parsedData;
        }
        catch (error) {
            console.error('Failed to retrieve or parse cookie data:', error);
            this.clear();
            return null;
        }
    }
    update(updates, options = {}) {
        if (typeof document === 'undefined')
            return;
        const currentData = this.get() || {};
        const updatedData = Object.assign(Object.assign({}, currentData), updates);
        this.set(updatedData, options);
    }
    deleteFields(fields) {
        if (typeof document === 'undefined')
            return;
        const currentData = this.get() || {};
        fields.forEach((field) => delete currentData[field]);
        this.set(currentData);
    }
    clear(options = {}) {
        const mergedOptions = Object.assign(Object.assign({}, this.defaultOptions), options);
        let cookieString = `${encodeURIComponent(this.storageKey)}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=${mergedOptions.path || '/'}`;
        this.appendCookieOptions(cookieString, mergedOptions);
        document.cookie = cookieString;
    }
    // Utility methods
    appendCookieOptions(cookieString, options) {
        if (options.expires) {
            const expiresDate = typeof options.expires === 'number'
                ? new Date(Date.now() + options.expires * 1000)
                : options.expires;
            cookieString += `; expires=${expiresDate.toUTCString()}`;
        }
        if (options.path)
            cookieString += `; path=${options.path}`;
        if (options.domain)
            cookieString += `; domain=${options.domain}`;
        if (options.secure)
            cookieString += '; secure';
        if (options.sameSite)
            cookieString += `; samesite=${options.sameSite}`;
        if (options.httpOnly)
            cookieString += '; httponly';
        return cookieString;
    }
}
exports.EncryptCookie = EncryptCookie;
exports.default = EncryptCookie;
//# sourceMappingURL=encrypt-cookie.js.map