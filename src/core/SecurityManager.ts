import { IsomorphicCrypto } from '../utils/crypto';

/**
 * SecurityManager — provides AES-256-GCM authenticated encryption.
 * Browser-safe and isomorphic via WebCrypto.
 */
export class SecurityManager {
    private key: CryptoKey | null = null;
    private static readonly IV_LENGTH = 12;
    private static readonly AUTH_TAG_BIT_LENGTH = 128;

    constructor(private secret?: string) { }

    /**
     * Initialize the key from the secret.
     */
    async init(): Promise<void> {
        if (!this.secret) return;

        const raw = new TextEncoder().encode(this.secret);
        const hash = await globalThis.crypto.subtle.digest('SHA-256', raw);

        this.key = await globalThis.crypto.subtle.importKey(
            'raw',
            hash,
            { name: 'AES-GCM' },
            false,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Encrypt a Uint8Array payload using AES-256-GCM + Timestamp.
     */
    async encrypt(data: Uint8Array): Promise<Uint8Array> {
        if (!this.key) return data;

        // Add 8-byte timestamp for replay protection
        const timestamp = new Uint8Array(8);
        new DataView(timestamp.buffer).setBigUint64(0, BigInt(Date.now()));
        
        const payload = new Uint8Array(timestamp.length + data.length);
        payload.set(timestamp);
        payload.set(data, timestamp.length);

        const iv = globalThis.crypto.getRandomValues(new Uint8Array(SecurityManager.IV_LENGTH));
        const encrypted = await globalThis.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            this.key,
            payload
        );

        const result = new Uint8Array(iv.length + encrypted.byteLength);
        result.set(iv);
        result.set(new Uint8Array(encrypted), iv.length);
        
        return result;
    }

    /**
     * Decrypt a Uint8Array payload and check replay protection.
     */
    async decrypt(data: Uint8Array): Promise<Uint8Array> {
        if (!this.key) return data;

        const iv = data.subarray(0, SecurityManager.IV_LENGTH);
        const encrypted = data.subarray(SecurityManager.IV_LENGTH);

        const decrypted = await globalThis.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            this.key,
            encrypted
        );

        const decryptedArray = new Uint8Array(decrypted);
        const timestamp = new DataView(decryptedArray.buffer, decryptedArray.byteOffset, 8).getBigUint64(0);
        
        const now = BigInt(Date.now());
        const diff = now > timestamp ? now - timestamp : timestamp - now;

        if (diff > 30000n) {
            throw new Error('Possible replay attack or severe clock skew.');
        }

        return decryptedArray.subarray(8);
    }
}
