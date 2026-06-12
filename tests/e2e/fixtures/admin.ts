import { test as base, expect, Page } from '@playwright/test';

/**
 * Authentication fixture.
 *
 * Default credentials match the docker stacks (admin/admin). Overridden
 * via env vars when CI uses a different identity.
 */
export const ADMIN_USER = process.env.RIP_E2E_ADMIN_USER ?? 'admin';
export const ADMIN_PASS = process.env.RIP_E2E_ADMIN_PASS ?? 'admin';

/**
 * Logs into wp-admin via wp-login.php. Works on both single-site and
 * subdir-multisite installs because the login URL is `/wp-login.php`
 * relative to the project's `baseURL`.
 */
export async function loginAsAdmin(page: Page, loginPath = '/wp-login.php'): Promise<void> {
    await page.goto(loginPath);
    await page.fill('#user_login', ADMIN_USER);
    await page.fill('#user_pass', ADMIN_PASS);
    await page.click('#wp-submit');
    await page.waitForURL((url) => url.pathname.includes('/wp-admin/'));

    const skipOnboarding = page.locator('a:has-text("Set up later"), a:has-text("Skip"):not([href="#"])').first();
    if ((await skipOnboarding.count()) > 0 && (await skipOnboarding.isVisible().catch(() => false))) {
        await skipOnboarding.click({ timeout: 5_000 }).catch(() => undefined);
        await page.waitForLoadState('networkidle', { timeout: 10_000 }).catch(() => undefined);
    }
}

/**
 * Convenience export: a `test` instance pre-wired with the helper above.
 * Specs that need additional fixtures can extend this further.
 */
export const test = base.extend({});
export { expect };
