export class AccessDeniedError extends Error {
    constructor(public permission: string, public actionName?: string) {
        super(
            `Access denied: permission "${permission}" is required`
            + (actionName ? ` to call "${actionName}"` : '')
        );
        this.name = 'AccessDeniedError';
    }
}

export interface IAuthContext {
    meta?: {
        user?: {
            id?: string;
            groups?: string[];
            permissions?: string[];
        };
        assignedGroups?: string[];
    };
}

interface GroupDefinition {
    permissions: string[];
    extends: string[];
}

/**
 * PolicyEngine — evaluates hierarchical permissions.
 */
export class PolicyEngine {
    private groups = new Map<string, GroupDefinition>();
    private cache = new Map<string, Set<string>>();

    /**
     * Register a group with its direct permissions and optional parent groups.
     */
    defineGroup(name: string, permissions: string[], inherits: string[] = []): void {
        this.groups.set(name, { permissions, extends: inherits });
        this.cache.clear();
    }

    /**
     * Resolve the complete permission set for a group.
     */
    resolveGroup(groupName: string, visited = new Set<string>()): Set<string> {
        if (visited.has(groupName)) return new Set();
        visited.add(groupName);

        const def = this.groups.get(groupName);
        if (!def) return new Set();

        const resolved = new Set<string>(def.permissions);

        for (const parent of def.extends) {
            for (const perm of this.resolveGroup(parent, visited)) {
                resolved.add(perm);
            }
        }

        return resolved;
    }

    /**
     * Resolve all permissions for the current context user.
     */
    resolvePermissions(ctx: IAuthContext): Set<string> {
        const userID = ctx.meta?.user?.id ?? '__anonymous__';
        if (this.cache.has(userID)) {
            return this.cache.get(userID)!;
        }

        const resolved = new Set<string>();

        const groups: string[] = [
            ...(ctx.meta?.assignedGroups ?? []),
            ...(ctx.meta?.user?.groups ?? []),
        ];
        for (const group of groups) {
            for (const perm of this.resolveGroup(group)) {
                resolved.add(perm);
            }
        }

        for (const perm of ctx.meta?.user?.permissions ?? []) {
            resolved.add(perm);
        }

        this.cache.set(userID, resolved);
        return resolved;
    }

    /**
     * Check whether the current user has a given permission.
     */
    can(permission: string, ctx: IAuthContext): boolean {
        const perms = this.resolvePermissions(ctx);
        return perms.has('*') || perms.has(permission);
    }

    /**
     * Assert that the current user has a given permission.
     */
    require(permission: string, ctx: IAuthContext, actionName?: string): void {
        if (!this.can(permission, ctx)) {
            throw new AccessDeniedError(permission, actionName);
        }
    }

    clearCache(): void {
        this.cache.clear();
    }

    listGroups(): string[] {
        return Array.from(this.groups.keys());
    }
}
