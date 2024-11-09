/*! js-cookie-encrypt v1.0.2 | MIT (c) 2024 Abdullah Al Fahim | https://github.com/abfahimb/js-cookie-encrypt */

export interface CookieOptions {
    path?: string
    expires?: number | Date
    secure?: boolean
    domain?: string
    sameSite?: 'strict' | 'lax' | 'none'
    httpOnly?: boolean
  }
  
  export interface CryptoConfig {
    privateKey: string
    saltLength?: number
    encryptByDefault?: boolean
  }
  
  export interface StorageConfig {
    storageKey: string
    cryptoConfig: CryptoConfig
    defaultOptions?: CookieOptions
  }
  
  type PathImpl<T, K extends keyof T> = K extends string
    ? T[K] extends Record<string, any>
      ? T[K] extends ArrayLike<any>
        ? K | `${K}.${PathImpl<T[K], Exclude<keyof T[K], keyof any[]>>}`
        : K | `${K}.${PathImpl<T[K], keyof T[K]>}`
      : K
    : never;
  
  type Path<T> = PathImpl<T, keyof T> | keyof T;
  
  class CookieCrypto {
    private privateKey: string
    private saltLength: number
  
    constructor(config: CryptoConfig) {
      this.privateKey = config.privateKey
      this.saltLength = config.saltLength || 16
    }
  
    private generateRandomSalt(): string {
      const randomBytes = new Uint8Array(this.saltLength)
      window.crypto.getRandomValues(randomBytes)
      return Array.from(randomBytes, (byte) => String.fromCharCode(byte)).join('')
    }
  
    private expandKey(key: string, salt: string): string {
      const expandedKey = []
      for (let i = 0; i < Math.max(key?.length, salt?.length); i++) {
        const keyChar = key.charCodeAt(i % key?.length)
        const saltChar = salt.charCodeAt(i % salt?.length)
        expandedKey.push(String.fromCharCode(keyChar ^ saltChar))
      }
      return expandedKey.join('')
    }
  
    private xorEncryptDecrypt(data: string, key: string): string {
      const salt = this.generateRandomSalt()
      const expandedKey = this.expandKey(key, salt)
      let result = ''
  
      for (let i = 0; i < data?.length; i++) {
        result += String.fromCharCode(
          data.charCodeAt(i) ^ expandedKey.charCodeAt(i % expandedKey?.length)
        )
      }
  
      return this.encodeToBase64(salt + result)
    }
  
    private encodeToBase64(data: string): string {
      return btoa(unescape(encodeURIComponent(data)))
    }
  
    private decodeFromBase64(data: string): string {
      return decodeURIComponent(escape(atob(data)))
    }
  
    encrypt(data: string): string {
      return this.xorEncryptDecrypt(data, this.privateKey)
    }
  
    decrypt(encryptedData: string): string {
      const decoded = this.decodeFromBase64(encryptedData)
      const salt = decoded.substring(0, this.saltLength)
      const encryptedMessage = decoded.substring(this.saltLength)
      const expandedKey = this.expandKey(this.privateKey, salt)
      let result = ''
  
      for (let i = 0; i < encryptedMessage?.length; i++) {
        result += String.fromCharCode(
          encryptedMessage.charCodeAt(i) ^ expandedKey.charCodeAt(i % expandedKey?.length)
        )
      }
  
      return result
    }
  }
  
  export class JsCookieEncrypt<T extends Record<string, any>> {
    private storageKey: string
    private crypto: CookieCrypto
    private defaultOptions: CookieOptions
    private encryptByDefault: boolean
  
    constructor(config: StorageConfig) {
      this.storageKey = config.storageKey
      this.crypto = new CookieCrypto(config.cryptoConfig)
      this.defaultOptions = config.defaultOptions || {}
      this.encryptByDefault = config.cryptoConfig.encryptByDefault ?? true
    }

    set(
        value: T,
        options: CookieOptions = {},
        { encrypt, merge }: { encrypt?: boolean; merge?: boolean } = {}
    ): void {
      if (typeof document === 'undefined') return;

      let finalValue = value;
      if (merge) {
        const currentValue = this.get() || {} as T;
        finalValue = { ...currentValue, ...value };
      }

      const shouldEncrypt = encrypt ?? this.encryptByDefault;
      const mergedOptions = { ...this.defaultOptions, ...options };
      const encodedData = shouldEncrypt
          ? this.crypto.encrypt(JSON.stringify(finalValue))
          : JSON.stringify(finalValue);

      let cookieString = `${this.storageKey}=${encodedData}`;

      if (mergedOptions.path) {
        cookieString += `; path=${mergedOptions.path}`;
      }
      if (mergedOptions.expires) {
        const expiresDate =
            typeof mergedOptions.expires === 'number'
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

      document.cookie = cookieString;
    }
  
    getByPath<K extends Path<T>>(path: K): any {
      const data = this.get()
      if (!data) return null
  
      return path.toString().split('.').reduce((obj: any, key: string) => {
        return obj && obj[key]
      }, data)
    }
  
    setByPath<K extends Path<T>>(path: K, value: any, options: CookieOptions = {}): void {
      const data = this.get() || {} as T
      const pathParts = path.toString().split('.')
      let current: any = data
  
      for (let i = 0; i < pathParts?.length - 1; i++) {
        const key = pathParts[i]
        if (!(key in current)) {
          current[key] = {}
        }
        current = current[key]
      }
  
      current[pathParts[pathParts?.length - 1]] = value
      this.set(data, options)
    }

    updateByPath<K extends Path<T>>(path: K, value: any, options: CookieOptions = {}): void {
      const data = this.get() || {} as T
      const pathParts = path.toString().split('.')
      let current: any = data

      for (let i = 0; i < pathParts?.length - 1; i++) {
        const key = pathParts[i]
        if (!(key in current)) {
          current[key] = {}
        }
        current = current[key]
      }

      const key = pathParts[pathParts?.length - 1]
      if (key in current && typeof current[key] === 'object' && typeof value === 'object') {
        current[key] = { ...current[key], ...value }
      } else {
        current[key] = value
      }

      this.set(data, options)
    }
    deleteByPath<K extends Path<T>>(path: K): void {
      if (typeof document === 'undefined') return

      const data = this.get() || {} as T
      const pathParts = path.toString().split('.')
      let current: any = data


      for (let i = 0; i < pathParts.length - 1; i++) {
        const key = pathParts[i]
        if (!(key in current)) {
          return
        }
        current = current[key]
      }

      const lastKey = pathParts[pathParts.length - 1]
      if (lastKey in current) {
        delete current[lastKey]
        this.set(data)
      }
    }

    extend(duration: number, options: CookieOptions = {}): void {
      const data = this.get()
      if (data) {
        this.set(data, {
          ...options,
          expires: new Date(Date.now() + duration * 1000)
        })
      }
    }
  
    static getAllCookies(domain?: string): Record<string, string> {
      const cookies: Record<string, string> = {}
      if (typeof document === 'undefined') return cookies

      document.cookie.split(';').forEach(cookie => {
        const [name, value] = cookie.split('=').map(c => c.trim())
        if (!domain || cookie.includes(`domain=${domain}`)) {
          cookies[name] = value
        }
      })

      return cookies
    }
  

    static clearAll(domain?: string, path: string = '/', clearSubDomain: boolean = false): void {
      const hostnameParts = location.hostname.split('.');
      const isLocalhost = hostnameParts.length === 1 && hostnameParts[0] === 'localhost';
      const subDomain = isLocalhost
          ? ''
          : hostnameParts.length > 1
              ? hostnameParts.slice(1).join('.')
              : location.hostname;


      const cookies = JsCookieEncrypt.getAllCookies(domain)
      Object.keys(cookies).forEach(name => {
        let cookieString = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=${path}`
        if (domain) cookieString += `; domain=${domain}`
        document.cookie = cookieString
      })

    if(clearSubDomain){
      const subDomainCookies = JsCookieEncrypt.getAllCookies(subDomain)
      Object.keys(subDomainCookies).forEach(name => {
        let cookieString = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=${path}`
        if (domain) cookieString += `; domain=${subDomain}`
        document.cookie = cookieString
      })
    }
    }

    get<K extends keyof T>(field?: K): T | T[K] | null {
      try {
        if (typeof document === 'undefined') return null;

        const match = document.cookie.match(new RegExp('(^| )' + this.storageKey + '=([^;]+)'));
        const encodedData = match ? match[2] : null;

        if (!encodedData) return null;

        let parsedData: T;
        if (this.encryptByDefault) {
          parsedData = JSON.parse(this.crypto.decrypt(encodedData)) as T;
        } else {
          parsedData = JSON.parse(encodedData) as T;
        }

        if (field && parsedData && field in parsedData) {
          return parsedData[field] || null;
        }

        return parsedData;
      } catch (error) {
        console.error('Failed to retrieve or parse cookie data:', error);
        JsCookieEncrypt.clearAll(undefined,'/',true)
        return null;
      }
    }
  
    update(updates: Partial<T>, options: CookieOptions = {}): void {
      if (typeof document === 'undefined') return
      
      const currentData = this.get() || {} as T
      const updatedData = { ...currentData, ...updates }
      this.set(updatedData, options)
    }
  
    deleteFields(fields: Array<keyof T>): void {
      if (typeof document === 'undefined') return
      
      const currentData = this.get() || {} as T
      fields.forEach((field) => delete currentData[field])
      this.set(currentData)
    }
  
    clear(options: CookieOptions = {}): void {
      const mergedOptions = { ...this.defaultOptions, ...options }
      let cookieString = `${encodeURIComponent(this.storageKey)}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=${mergedOptions.path || '/'}`
  
      this.appendCookieOptions(cookieString, mergedOptions)
      document.cookie = cookieString
    }

    private appendCookieOptions(cookieString: string, options: CookieOptions): string {
      if (options.expires) {
        const expiresDate = typeof options.expires === 'number'
          ? new Date(Date.now() + options.expires * 1000)
          : options.expires
        cookieString += `; expires=${expiresDate.toUTCString()}`
      }
      if (options.path) cookieString += `; path=${options.path}`
      if (options.domain) cookieString += `; domain=${options.domain}`
      if (options.secure) cookieString += '; secure'
      if (options.sameSite) cookieString += `; samesite=${options.sameSite}`
      if (options.httpOnly) cookieString += '; httponly'
      
      return cookieString
    }
  }

  export default JsCookieEncrypt;