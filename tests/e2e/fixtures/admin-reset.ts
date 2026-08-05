import { execSync } from 'node:child_process';

/**
 * Reset the stack admin user's accumulated 2FA nag/enforcement state.
 *
 * The Docker stacks are long-lived, so the `admin` login counter for the
 * 2FA reminder grows with every suite run and the enforcement grace clock
 * keeps ticking; once the onboarding snooze expires, the hard-block
 * redirect hijacks the first wp-admin navigation and unrelated smoke specs
 * fail. Run this in `beforeAll` of any spec that drives `admin` through
 * wp-admin without enrolling 2FA. Backed by `admin-reset.php`.
 */

function resolveWorkspaceRoot(): string {
    return new URL('../../../../', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
}

export function resetAdminBaseline(composeFile = 'docker-compose.yml', service = 'wordpress'): void {
    const out = execSync(
        `docker compose -f ${composeFile} exec -T ${service} wp --allow-root eval-file ` +
            'wp-content/plugins/reportedip-hive/tests/e2e/fixtures/admin-reset.php',
        { cwd: resolveWorkspaceRoot(), encoding: 'utf8' }
    ).toString();
    if (!out.includes('Admin 2FA baseline reset')) {
        throw new Error(`admin-reset.php did not report success. Output:\n${out}`);
    }
}
