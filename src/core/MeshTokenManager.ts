import { IsomorphicCrypto } from '../utils/crypto';
import { TokenPayload } from '../types/auth.schema';

export interface TokenKeys {
    privateKey?: string;
    publicKey?: string;
}

/**
 * MeshTokenManager — handles creation and verification of signed mesh tokens.
 * 
 * NOTE: This is NOT a standard RFC 7519 JWT implementation. It uses a 
 * custom envelope optimized for decentralized mesh performance and 
 * Ed25519 binary signatures.
 */
export class MeshTokenManager {
    private privateKey: string | undefined;
    private publicKey: string | undefined;
    private defaultTTL: number;
    private issuer: string;

    constructor(issuer: string, keys?: TokenKeys, defaultTTL = 3600) {
        this.privateKey = keys?.privateKey;
        this.publicKey = keys?.publicKey;
        this.defaultTTL = defaultTTL;
        this.issuer = issuer;
    }

    /** Create a signed token */
    async sign(payload: Omit<TokenPayload, 'iss' | 'iat' | 'exp' | 'jti'>, ttl?: number): Promise<string> {
        if (!this.privateKey) throw new Error('No private key available for signing');

        const fullPayload: TokenPayload = {
            ...payload,
            iss: this.issuer,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + (ttl ?? this.defaultTTL),
            jti: IsomorphicCrypto.randomID(16)
        } as TokenPayload;

        const json = JSON.stringify(fullPayload);
        const signature = await IsomorphicCrypto.signEd25519(json, this.privateKey);

        const envelope = JSON.stringify({
            p: fullPayload,
            s: signature
        });

        const bytes = new TextEncoder().encode(envelope);
        return IsomorphicCrypto.toBase64(bytes);
    }

    /** Verify a signed token */
    async verify(ticket: string, overridePublicKey?: string): Promise<TokenPayload | null> {
        try {
            const pubKey = overridePublicKey || this.publicKey;
            if (!pubKey) throw new Error('No public key available for verification');

            const bytes = IsomorphicCrypto.fromBase64(ticket);
            const envelopeStr = new TextDecoder().decode(bytes);
            const envelope = JSON.parse(envelopeStr) as { p: TokenPayload, s: string };
            const { p, s } = envelope;

            const json = JSON.stringify(p);
            const isValid = await IsomorphicCrypto.verifyEd25519(s, json, pubKey);
            if (!isValid) return null;

            if (p.exp && p.exp < Math.floor(Date.now() / 1000)) return null;

            return p;
        } catch (err) {
            return null;
        }
    }

    /** Decode a token without verification */
    decode(ticket: string): TokenPayload | null {
        try {
            const bytes = IsomorphicCrypto.fromBase64(ticket);
            const envelopeStr = new TextDecoder().decode(bytes);
            const envelope = JSON.parse(envelopeStr);
            return envelope.p as TokenPayload;
        } catch {
            return null;
        }
    }
}
