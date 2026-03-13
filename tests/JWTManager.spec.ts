import { MeshTokenManager } from '../src/core/MeshTokenManager';
import { IsomorphicCrypto } from '../src/utils/crypto';

describe('MeshTokenManager (Browser-Safe)', () => {
    let tokenManager: MeshTokenManager;
    let keys: { publicKey: string, privateKey: string };

    beforeAll(async () => {
        // Generate a test keypair
        const keyPair = await globalThis.crypto.subtle.generateKey(
            { name: 'Ed25519' },
            true,
            ['sign', 'verify']
        );
        const pub = await globalThis.crypto.subtle.exportKey('spki', keyPair.publicKey);
        const priv = await globalThis.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        
        keys = {
            publicKey: IsomorphicCrypto.toBase64(new Uint8Array(pub)),
            privateKey: IsomorphicCrypto.toBase64(new Uint8Array(priv))
        };
    });

    beforeEach(() => {
        tokenManager = new MeshTokenManager('test-issuer', keys);
    });

    test('should sign and verify a ticket', async () => {
        const payload = {
            type: 'TGT' as const,
            sub: 'node-1',
            capabilities: ['mesh:member']
        };

        const ticket = await tokenManager.sign(payload);
        expect(ticket).toBeDefined();

        const decoded = await tokenManager.verify(ticket);
        expect(decoded).toMatchObject(payload);
        expect(decoded?.iss).toBe('test-issuer');
    });

    test('should return null for invalid signature', async () => {
        const ticket = await tokenManager.sign({ type: 'TGT' as const, sub: 'node-1' });
        const tampered = ticket.substring(0, ticket.length - 5) + 'AAAAA';
        
        const decoded = await tokenManager.verify(tampered);
        expect(decoded).toBeNull();
    });

    test('should return null for expired ticket', async () => {
        const ticket = await tokenManager.sign({ type: 'TGT' as const, sub: 'node-1' }, -100);
        const decoded = await tokenManager.verify(ticket);
        expect(decoded).toBeNull();
    });

    test('should decode without verification', async () => {
        const payload = { type: 'ST' as const, sub: 'node-1', aud: 'node-2' };
        const ticket = await tokenManager.sign(payload);
        
        const decoded = tokenManager.decode(ticket);
        expect(decoded).toMatchObject(payload);
    });
});
