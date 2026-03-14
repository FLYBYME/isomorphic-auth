// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type CryptoKey = any; // Fallback for environments where it is not globally defined.

export interface CryptoKeyPair {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
}

/**
 * WebCrypto-based cryptographic utilities (Isomorphic/Browser-safe).
 */
export class IsomorphicCrypto {
    private static crypto = typeof globalThis !== 'undefined' && globalThis.crypto 
        ? globalThis.crypto 
        : null;

    /** Generate a random ID string */
    static randomID(len = 16): string {
        const bytes = new Uint8Array(len / 2);
        if (this.crypto) {
            this.crypto.getRandomValues(bytes);
        } else {
            for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
        }
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    /** Generate a new Ed25519 key pair */
    static async generateKeyPair(): Promise<{ publicKey: string; privateKey: string }> {
        if (!this.crypto) throw new Error('WebCrypto not available');
        const keyPair = (await this.crypto.subtle.generateKey(
            { name: 'Ed25519' },
            true,
            ['sign', 'verify']
        )) as CryptoKeyPair;

        const pubKeyBuf = await this.crypto.subtle.exportKey('spki', keyPair.publicKey);
        const privKeyBuf = await this.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

        return {
            publicKey: this.toBase64(new Uint8Array(pubKeyBuf)),
            privateKey: this.toBase64(new Uint8Array(privKeyBuf))
        };
    }

    /** Compute SHA-256 hash of a string or buffer */
    static async sha256(data: string | Uint8Array): Promise<string> {
        if (!this.crypto) throw new Error('WebCrypto not available');
        const msgUint8 = typeof data === 'string' ? new TextEncoder().encode(data) : new Uint8Array(data);
        
        const hashBuffer = await this.crypto.subtle.digest('SHA-256', msgUint8);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    /** Sign data using Ed25519 private key (Base64) */
    static async signEd25519(payload: string | Uint8Array, privateKeyB64: string): Promise<string> {
        if (!this.crypto) throw new Error('WebCrypto not available');
        
        const privKeyBuf = new Uint8Array(this.fromBase64(privateKeyB64));
        const key = await this.crypto.subtle.importKey(
            'pkcs8',
            privKeyBuf,
            { name: 'Ed25519' },
            false,
            ['sign']
        );

        const data = typeof payload === 'string' ? new TextEncoder().encode(payload) : new Uint8Array(payload);
        const signature = await this.crypto.subtle.sign(
            { name: 'Ed25519' },
            key,
            data
        );

        return this.toBase64(new Uint8Array(signature));
    }

    /** Verify Ed25519 signature */
    static async verifyEd25519(signatureB64: string, payload: string | Uint8Array, publicKeyB64: string): Promise<boolean> {
        if (!this.crypto) throw new Error('WebCrypto not available');

        try {
            const pubKeyBuf = new Uint8Array(this.fromBase64(publicKeyB64));
            const key = await this.crypto.subtle.importKey(
                'spki',
                pubKeyBuf,
                { name: 'Ed25519' },
                false,
                ['verify']
            );

            const data = typeof payload === 'string' ? new TextEncoder().encode(payload) : new Uint8Array(payload);
            const signature = new Uint8Array(this.fromBase64(signatureB64));

            return await this.crypto.subtle.verify(
                { name: 'Ed25519' },
                key,
                signature,
                data
            );
        } catch (err) {
            return false;
        }
    }

    /** Helper: bytes to Base64 (isomorphic) */
    static toBase64(bytes: Uint8Array): string {
        const binString = Array.from(bytes).map(x => String.fromCharCode(x)).join('');
        return globalThis.btoa(binString);
    }

    /** Helper: Base64 to Uint8Array (isomorphic) */
    static fromBase64(b64: string): Uint8Array {
        if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(b64, 'base64'));
        const binString = globalThis.atob(b64);
        return Uint8Array.from(binString, (m) => m.charCodeAt(0));
    }

    /** Securely hash a password using PBKDF2 */
    static async hashPassword(password: string, saltB64?: string): Promise<{ hash: string, salt: string }> {
        if (!this.crypto) throw new Error('WebCrypto not available');

        const salt = saltB64 ? this.fromBase64(saltB64) : this.crypto.getRandomValues(new Uint8Array(16));
        const iterations = 100000;
        
        const baseKey = await this.crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(password),
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        const derivedBits = await this.crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: salt as any,
                iterations: iterations,
                hash: 'SHA-256'
            },
            baseKey,
            256
        );

        return {
            hash: this.toBase64(new Uint8Array(derivedBits)),
            salt: this.toBase64(salt)
        };
    }

    /** Verify a password against a PBKDF2 hash */
    static async verifyPassword(password: string, hash: string, salt: string): Promise<boolean> {
        const result = await this.hashPassword(password, salt);
        return result.hash === hash;
    }
}
