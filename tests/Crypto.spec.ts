import { IsomorphicCrypto } from '../src/utils/crypto';

describe('IsomorphicCrypto Extended', () => {
    test('should generate Ed25519 key pair', async () => {
        const keys = await IsomorphicCrypto.generateKeyPair();
        expect(keys.publicKey).toBeDefined();
        expect(keys.privateKey).toBeDefined();
        expect(typeof keys.publicKey).toBe('string');
        expect(typeof keys.privateKey).toBe('string');
    });

    test('should hash and verify password using PBKDF2', async () => {
        const password = 'my-secure-password';
        const { hash, salt } = await IsomorphicCrypto.hashPassword(password);
        
        expect(hash).toBeDefined();
        expect(salt).toBeDefined();
        
        const isValid = await IsomorphicCrypto.verifyPassword(password, hash, salt);
        expect(isValid).toBe(true);
        
        const isInvalid = await IsomorphicCrypto.verifyPassword('wrong-password', hash, salt);
        expect(isInvalid).toBe(false);
    });

    test('should sign and verify using Ed25519', async () => {
        const { publicKey, privateKey } = await IsomorphicCrypto.generateKeyPair();
        const payload = 'hello mesh';
        
        const signature = await IsomorphicCrypto.signEd25519(payload, privateKey);
        expect(signature).toBeDefined();
        
        const isValid = await IsomorphicCrypto.verifyEd25519(signature, payload, publicKey);
        expect(isValid).toBe(true);
        
        const isInvalid = await IsomorphicCrypto.verifyEd25519(signature, 'modified payload', publicKey);
        expect(isInvalid).toBe(false);
    });
});
