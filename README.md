# isomorphic-auth

A standalone, browser-safe, and isomorphic authentication library for decentralized mesh networks. This library provides core primitives for identity bootstrapping, ticket issuance (TGT/ST), hierarchical policies (RBAC), and authenticated encryption (AES-256-GCM).

## Features

- **Isomorphic**: Works seamlessly in both Node.js (>= 18) and modern browsers using standard Web APIs.
- **Browser-Safe**: Zero dependencies on Node.js built-ins. Uses `globalThis.crypto.subtle` (WebCrypto) for all cryptographic operations.
- **Zero-Trust Identity**: Implements a Kerberos-style Mesh Key Distribution Center (mKDC) logic using Ed25519 signatures.
- **Hierarchical RBAC**: Flexible policy engine for permission management with group inheritance and wildcards.
- **Authenticated Encryption**: Built-in SecurityManager for AES-256-GCM encryption with replay protection (nonce caching + timestamp).
- **Strictly Typed**: Zero `any` usage, providing full type safety for all auth primitives.

## Installation

```bash
npm install isomorphic-auth
```

## Quick Start

### Identity Bootstrap (Client)

```typescript
import { TicketManager, MeshTokenManager, ILogger } from 'isomorphic-auth';

const logger: ILogger = { ... };
const tokenManager = new MeshTokenManager('gateway-issuer', { publicKey: '...' });

const ticketManager = new TicketManager(
    'my-node-id',
    tokenManager,
    async (action, params) => { /* RPC call to KDC */ },
    logger,
    'my-private-key'
);

await ticketManager.bootstrapIdentity();
const st = await ticketManager.getTicketFor('target-node-id');
```

### Policy Evaluation

```typescript
import { PolicyEngine } from 'isomorphic-auth';

const engine = new PolicyEngine();
engine.defineGroup('Users', ['posts.read']);
engine.defineGroup('Admins', ['*'], ['Users']);

const ctx = { meta: { user: { id: 'u1', groups: ['Admins'] } } };
if (engine.can('any.action', ctx)) {
    // Access granted
}
```

## Core Components

- `MeshTokenManager`: Handles creation and verification of signed mesh tokens (TGT/ST).
- `mKDC`: Core logic for the Key Distribution Center.
- `PolicyEngine`: hierarchical permission evaluator.
- `SecurityManager`: AES-GCM encryption wrapper with replay protection.
- `TicketManager`: Edge-side ticket lifecycle and renewal daemon.

## License

MIT
