import { IAuthContext } from './PolicyEngine';

export interface RBACOptions {
    roles: string[];
    matchAny?: boolean;
}

/**
 * RBAC Utility — enforces Role-Based Access Control.
 */
export class RBAC {
    /**
     * Check if the context user has the required roles.
     */
    static check(ctx: IAuthContext, options: RBACOptions): boolean {
        const requiredRoles = options.roles;
        if (!requiredRoles || requiredRoles.length === 0) return true;

        const userRoles = ctx.meta?.user?.groups || [];
        
        if (options.matchAny) {
            return requiredRoles.some(role => userRoles.includes(role));
        } else {
            return requiredRoles.every(role => userRoles.includes(role));
        }
    }

    /**
     * Assert that the context user has the required roles.
     */
    static authorize(ctx: IAuthContext, options: RBACOptions): void {
        if (!this.check(ctx, options)) {
            throw new Error(`Unauthorized: missing required roles [${options.roles.join(', ')}]`);
        }
    }
}
