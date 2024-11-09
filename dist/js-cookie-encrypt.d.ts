/*! js-cookie-encrypt v1.0.2 | MIT (c) 2024 Abdullah Al Fahim | https://github.com/abfahimb/js-cookie-encrypt */
export interface CookieOptions {
    path?: string;
    expires?: number | Date;
    secure?: boolean;
    domain?: string;
    sameSite?: 'strict' | 'lax' | 'none';
    httpOnly?: boolean;
}
export interface CryptoConfig {
    privateKey: string;
    saltLength?: number;
    encryptByDefault?: boolean;
}
export interface StorageConfig {
    storageKey: string;
    cryptoConfig: CryptoConfig;
    defaultOptions?: CookieOptions;
}
type PathImpl<T, K extends keyof T> = K extends string ? T[K] extends Record<string, any> ? T[K] extends ArrayLike<any> ? K | `${K}.${PathImpl<T[K], Exclude<keyof T[K], keyof any[]>>}` : K | `${K}.${PathImpl<T[K], keyof T[K]>}` : K : never;
type Path<T> = PathImpl<T, keyof T> | keyof T;
export declare class JsCookieEncrypt<T extends Record<string, any>> {
    private storageKey;
    private crypto;
    private defaultOptions;
    private encryptByDefault;
    constructor(config: StorageConfig);
    set(value: T, options?: CookieOptions, { encrypt, merge }?: {
        encrypt?: boolean;
        merge?: boolean;
    }): void;
    getByPath<K extends Path<T>>(path: K): any;
    setByPath<K extends Path<T>>(path: K, value: any, options?: CookieOptions): void;
    updateByPath<K extends Path<T>>(path: K, value: any, options?: CookieOptions): void;
    deleteByPath<K extends Path<T>>(path: K): void;
    has(field?: keyof T): boolean;
    extend(duration: number, options?: CookieOptions): void;
    static getAllCookies(domain?: string): Record<string, string>;
    static clearAll(domain?: string, path?: string): void;
    get<K extends keyof T>(field?: K): T | T[K] | null;
    update(updates: Partial<T>, options?: CookieOptions): void;
    deleteFields(fields: Array<keyof T>): void;
    clear(options?: CookieOptions): void;
    private appendCookieOptions;
}
export default JsCookieEncrypt;
