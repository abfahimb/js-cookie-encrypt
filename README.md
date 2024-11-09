# JS-cookie-encrypt (Protected by Secret Key)

**JS-cookie-encrypt** is a lightweight JavaScript package designed to securely manage data in browser cookies using advanced encryption techniques. This package ensures that sensitive data stored in cookies is encrypted, providing a higher level of security for client-side storage. It allows for flexible and customizable cookie management with support for various cookie attributes such as path, domain, expires, sameSite, and secure.

Your cookie data will be securely stored in an encrypted format, ensuring that sensitive information remains protected and accessible only to you.

## Protecting Your Cookie Data

Your Cookie Will be some thing like this only you can read / access it.
```Cookie
UHzDpCrDicOQd1XCssKMw5F0w60OLsK3WDvDqTnDgcOBBQ7Do8Kew4R/w6oGMcKzSznDpjTCjMOCRlzCqMKSwoQ3wr0DM8K0TDvCvXrDiMOMRl/CoMOdwoo5w7oHPMK7TzvCvXrDjcOGQVXCqcKWw4tbw7gHPMK7TzfDpDfDgcKGWg==
```

## Key Features

- 🔐 Built-in encryption support
- 📦 Type-safe cookie storage
- 🛣️ Nested path operations
- 🔄 Automatic serialization/deserialization
- 🌐 Cross-browser compatibility
- 🔧 Configurable options
- 🚀 SSR-friendly


## Table of Contents

- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Advanced Usage](#advanced-usage)
- [API Reference](#api-reference)
- [Security Considerations](#security-considerations)
- [Best Practices](#best-practices)
- [What Not To Do](#what-not-to-do)
- [License](#license)

## Installation

```bash
npm install js-cookie-encrypt
# or
yarn add js-cookie-encrypt
# or
pnpm add js-cookie-encrypt
```

## Basic Usage

### 1. Define Your Data Structure (Creating an Instance)

```bash
import JsCookieEncrypt from 'js-cookie-encrypt'

// Configuration for encryption and cookie handling
const config = {
  storageKey: 'myAppData', // Custom key for the cookie storage
  cryptoConfig: {
    privateKey: 'your-private-key', // Your secret encryption key
    encryptByDefault: true // Whether to encrypt data by default
  }
}

// Create a new instance of JsCookieEncrypt
const cookie = new JsCookieEncrypt(config);
```

```bash
// Set data
cookie.set({
  id: '123',
  name: 'John Doe',
  email: 'john@example.com',
  preferences: {
    theme: 'light',
    notifications: true
  }
});

// Get all data
const userData = cookie.get();

// Get specific field
const userName = cookie.get('name');

// Update data
cookie.update({
  preferences: {
    theme: 'dark'
  }
});

// Delete fields
cookie.deleteFields(['email']);

// Clear all data
cookie.clear();
```

### Cookie Options

```base
  path: '/',
    expires: 60, (as sec, it will 1 min)
    domain: 'example.com',
    secure: true,
    sameSite: 'Lax',
    httpOnly: true
```

## Advanced Usage

### Use Path
```bash
// Initialize the cookie manager
const cookie = new JsCookieEncrypt({ storageKey: 'myAppData' });

// Set some initial data
cookie.set({ user: { name: 'John Doe', address: { city: 'Los Angeles' } } });

// Get a nested value by path
const userCity = cookie.getByPath('user.address.city');
console.log(userCity); // 'Los Angeles'

// Set a new value at a nested path
cookie.setByPath('user.address.city', 'San Francisco');

// Update an existing nested value (merge objects)
cookie.updateByPath('user.address', { country: 'USA' });

// Get the updated data
const updatedAddress = cookie.getByPath('user.address');
console.log(updatedAddress); // { city: 'San Francisco', country: 'USA' }

// Delete a nested value
cookie.deleteByPath('user.address.city');

// Verify deletion
const addressAfterDelete = cookie.getByPath('user.address');
console.log(addressAfterDelete); // { country: 'USA' }

```

### Cookie validation

```base
// Example usage of has method

// Check if the cookie contains any data
const hasData = cookie.has();
console.log(hasData); // true if data exists, false if cookie is empty

// Check if a specific field exists within the cookie data
const hasUserField = cookie.has('user');
console.log(hasUserField); // true if 'user' field exists, false otherwise

const hasEmailField = cookie.has('email');
console.log(hasEmailField); // true if 'email' field exists within the stored data, false otherwise

```

### Cookie Expiration

```base 
 cookie.extend(3600);

// Extend the expiration with additional options (e.g., secure or specific path)
cookie.extend(3600, { secure: true, path: '/' });
```

### Retrieve All Cookies 

The getAllCookies method retrieves all cookies available in the document, optionally filtering by a specified domain. It returns an object with cookie names as keys and their respective values.

If no domain is provided, it will retrieve all cookies.
If a domain is specified, it will return only the cookies associated with that domain.

```base
// Retrieve all cookies
const allCookies = JsCookieEncrypt.getAllCookies();
console.log(allCookies); 
// Output: { "cookie1": "value1", "cookie2": "value2", ... }

// Retrieve cookies specific to a domain
const domainCookies = JsCookieEncrypt.getAllCookies('example.com');
console.log(domainCookies); 
// Output: { "cookie1": "value1", "cookie2": "value2", ... } for cookies on example.com

```

### Clear All Cookies (clearAll)

The clearAll method deletes all cookies associated with the current document, optionally within a specific domain and path.

Parameters:
domain (optional): The domain where cookies will be cleared. If not specified, it clears cookies for the current document domain.
path (default: /): The path for the cookies. The default is /, which clears cookies site-wide.

```base 
// Clear all cookies for the current domain
JsCookieEncrypt.clearAll();

// Clear all cookies for a specific domain
JsCookieEncrypt.clearAll('example.com');

// Clear all cookies for a specific domain and path
JsCookieEncrypt.clearAll('example.com', '/specific-path');

```

## API Reference

### Constructor Options

```typescript
interface StorageConfig {
  storageKey: string;
  cryptoConfig: {
    privateKey: string;
    saltLength?: number;
    encryptByDefault?: boolean;
  };
  defaultOptions?: {
    path?: string;
    expires?: number | Date;
    secure?: boolean;
    domain?: string;
    sameSite?: 'strict' | 'lax' | 'none';
    httpOnly?: boolean;
  };
}
```

### Methods

- `set(value, options?, { encrypt?, merge? })`
- `get(field?)`
- `getByPath(path)`
- `setByPath(path, value, options?)`
- `updateByPath(path, updates)`
- `deleteByPath(path)`
- `update(updates, options?)`
- `deleteFields(fields)`
- `clear(options?)`
- `has(field?)`
- `extend(duration, options?)`


## Security Considerations

1. **Private Key Storage**
   - Never expose your private key in client-side code
   - Use environment variables
   - Rotate keys periodically

2. **Cookie Options**
   - Always use `secure: true` in production
   - Set appropriate `sameSite` policy
   - Use `httpOnly` when possible

3. **Data Sensitivity**
   - Don't store sensitive data in cookies
   - Minimize stored data
   - Regularly clear unnecessary data

## Best Practices

✅ **Do:**
- Use TypeScript interfaces for type safety
- Implement proper error handling
- Set appropriate cookie expiration
- Use batch operations for multiple updates
- Regularly clear expired cookies
- Use path-specific operations
- Implement proper access controls

## What Not To Do

❌ **Don't:**
```typescript
// DON'T store sensitive information
cookieStore.set({
  creditCard: '1234-5678-9012-3456',
  ssn: '123-45-6789'
});

// DON'T use without encryption
cookieStore.set(data, {}, { encrypt: false });

// DON'T store large amounts of data
cookieStore.set({
  hugeDataObject: /* large object */
});

// DON'T use without proper type definitions
const unsafeStore = new SecureCookieStore<any>({...});

// DON'T expose private keys
const store = new SecureCookieStore({
  cryptoConfig: {
    privateKey: 'hardcoded-key' // WRONG!
  }
});

// DON'T use in security-critical applications
// This library is for general-purpose storage only
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---