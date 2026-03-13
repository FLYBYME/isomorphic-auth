import { PolicyEngine, AccessDeniedError } from '../src/core/PolicyEngine';

describe('PolicyEngine', () => {
    let engine: PolicyEngine;

    beforeEach(() => {
        engine = new PolicyEngine();
    });

    test('1. should deny by default', () => {
        const ctx = { meta: { user: { id: 'u1' } } };
        expect(engine.can('read', ctx)).toBe(false);
    });

    test('2. should allow explicit user permission', () => {
        const ctx = { meta: { user: { id: 'u1', permissions: ['read'] } } };
        expect(engine.can('read', ctx)).toBe(true);
    });

    test('3. should allow group permission', () => {
        engine.defineGroup('Users', ['read']);
        const ctx = { meta: { user: { id: 'u1', groups: ['Users'] } } };
        expect(engine.can('read', ctx)).toBe(true);
    });

    test('4. should handle hierarchical groups', () => {
        engine.defineGroup('Users', ['read']);
        engine.defineGroup('Admins', ['write'], ['Users']);
        
        const ctx = { meta: { user: { id: 'u1', groups: ['Admins'] } } };
        expect(engine.can('read', ctx)).toBe(true);
        expect(engine.can('write', ctx)).toBe(true);
        expect(engine.can('delete', ctx)).toBe(false);
    });

    test('5. should support wildcard permission', () => {
        engine.defineGroup('SuperUsers', ['*']);
        const ctx = { meta: { user: { id: 'u1', groups: ['SuperUsers'] } } };
        expect(engine.can('any.thing', ctx)).toBe(true);
    });

    test('6. should handle circular inheritance', () => {
        engine.defineGroup('A', ['permA'], ['B']);
        engine.defineGroup('B', ['permB'], ['A']);
        
        const ctx = { meta: { user: { id: 'u1', groups: ['A'] } } };
        expect(engine.can('permA', ctx)).toBe(true);
        expect(engine.can('permB', ctx)).toBe(true);
    });

    test('7. should throw AccessDeniedError on require failure', () => {
        const ctx = { meta: { user: { id: 'u1' } } };
        expect(() => engine.require('write', ctx, 'testAction')).toThrow(AccessDeniedError);
    });

    test('8. should use assignedGroups from meta', () => {
        engine.defineGroup('Admins', ['*']);
        const ctx = { meta: { assignedGroups: ['Admins'] } };
        expect(engine.can('anything', ctx)).toBe(true);
    });

    test('9. should clear cache when group defined', () => {
        const ctx = { meta: { user: { id: 'u1', groups: ['G1'] } } };
        engine.defineGroup('G1', ['p1']);
        expect(engine.can('p1', ctx)).toBe(true);
        
        engine.defineGroup('G1', ['p2']); // Invalidate cache
        expect(engine.can('p1', ctx)).toBe(false);
        expect(engine.can('p2', ctx)).toBe(true);
    });

    test('10. should list all groups', () => {
        engine.defineGroup('G1', []);
        engine.defineGroup('G2', []);
        expect(engine.listGroups()).toEqual(['G1', 'G2']);
    });
});
