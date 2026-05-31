/*! js-cookie-encrypt v1.1.0 | MIT (c) 2026 Abdullah Al Fahim | https://github.com/abfahimb/js-cookie-encrypt */
export interface CookieOptions {
    path?: string;
    expires?: number | Date;
    secure?: boolean;
    domain?: string;
    sameSite?: 'strict' | 'lax' | 'none';
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
type PathImpl<T, K extends keyof T> = K extends string ? T[K] extends Record<string, any> ? T[K] extends ArrayLike<any> ? K | `${K}.${PathImpl<T[K], Exclude<keyof T[K], keyof any[]>>}` : K | `${K}.${PathImpl<T[K], keyof T[K]>}` : K : never;
export type Path<T> = PathImpl<T, keyof T> | keyof T;
export type PathValue<T, P extends string> = P extends `${infer K}.${infer R}` ? K extends keyof T ? PathValue<T[K], R> : any : P extends keyof T ? T[P] : any;
export declare class JsCookieEncrypt<T extends Record<string, any>> {
    private storageKey;
    private crypto;
    private defaultOptions;
    private encryptByDefault;
    private listeners;
    constructor(config: StorageConfig);
    static isSupported(): boolean;
    subscribe(listener: CookieListener<T>): () => void;
    private notify;
    private buildOptionsStr;
    private writeCookie;
    private readCookie;
    private removeCookie;
    private _writeValue;
    private _writeValueAsync;
    set(value: T, options?: CookieOptions, { encrypt, merge }?: {
        encrypt?: boolean;
        merge?: boolean;
    }): void;
    setAsync(value: T, options?: CookieOptions, { encrypt, merge }?: {
        encrypt?: boolean;
        merge?: boolean;
    }): Promise<void>;
    get<K extends keyof T>(field?: K, skipReencrypt?: boolean): T | T[K] | null;
    getAsync<K extends keyof T>(field?: K, skipReencrypt?: boolean): Promise<T | T[K] | null>;
    getByPath<K extends Path<T> & string>(path: K): PathValue<T, K> | null;
    getByPathAsync<K extends Path<T> & string>(path: K): Promise<PathValue<T, K> | null>;
    setByPath<K extends Path<T> & string>(path: K, value: PathValue<T, K>, options?: CookieOptions): void;
    setByPathAsync<K extends Path<T> & string>(path: K, value: PathValue<T, K>, options?: CookieOptions): Promise<void>;
    updateByPath<K extends Path<T> & string>(path: K, value: Partial<PathValue<T, K>>, options?: CookieOptions): void;
    updateByPathAsync<K extends Path<T> & string>(path: K, value: Partial<PathValue<T, K>>, options?: CookieOptions): Promise<void>;
    deleteByPath<K extends Path<T> & string>(path: K): void;
    deleteByPathAsync<K extends Path<T> & string>(path: K): Promise<void>;
    extend(durationSecs: number, options?: CookieOptions): void;
    extendAsync(durationSecs: number, options?: CookieOptions): Promise<void>;
    static getAllCookies(): Record<string, string>;
    static clearAll(domain?: string, path?: string, clearSubDomain?: boolean): void;
    has<K extends Path<T> & string>(pathOrField?: K): boolean;
    hasAsync<K extends Path<T> & string>(pathOrField?: K): Promise<boolean>;
    update(updates: Partial<T>, options?: CookieOptions): void;
    updateAsync(updates: Partial<T>, options?: CookieOptions): Promise<void>;
    deleteFields(fields: Array<keyof T>): void;
    deleteFieldsAsync(fields: Array<keyof T>): Promise<void>;
    clear(options?: CookieOptions): void;
    clearAsync(options?: CookieOptions): Promise<void>;
}
export default JsCookieEncrypt;
