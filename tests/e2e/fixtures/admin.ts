import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test as base, expect, Cookie, Page } from '@playwright/test';

/**
 * Authentication fixture.
 *
 * Default credentials match the docker stacks (admin/admin). Overridden
 * via env vars when CI uses a different identity.
 */
export const ADMIN_USER = process.env.RIP_E2E_ADMIN_USER ?? 'admin';
export const ADMIN_PASS = process.env.RIP_E2E_ADMIN_PASS ?? 'admin';

/**
 * Where the reusable admin session is kept between tests.
 *
 * Signing in through the form costs about fifteen seconds, because the
 * browser pulls the whole wp-admin asset tree over the bind mount, and the
 * suite does it more than eighty times. The cookies are the same every
 * time, so the first sign-in of a run is kept and handed to every later
 * test. The file lives outside the repo and is keyed by stack, so the
 * single-site and multisite projects never share a session.
 */
function sessionFile(): string {
    const stack = String(base.info().project.use.baseURL ?? 'http://localhost');
    const key = createHash('sha1').update(stack).digest('hex').slice(0, 10);
    const dir = join(tmpdir(), 'rip-e2e-auth');

    mkdirSync(dir, { recursive: true });

    return join(dir, `${key}.json`);
}

/** The stored cookies for this stack, or none when nothing is stored yet. */
function storedCookies(file: string): Cookie[] {
    try {
        const parsed = JSON.parse(readFileSync(file, 'utf8'));

        return Array.isArray(parsed) ? (parsed as Cookie[]) : [];
    } catch {
        return [];
    }
}

/**
 * Whether this context can open wp-admin right now.
 *
 * The request goes through the context, so it carries its cookies, but it
 * never renders anything: a signed-in admin gets 200 with the dashboard
 * HTML, everyone else a redirect to the login form. A stored session that
 * a test has since destroyed is caught here and replaced by a real
 * sign-in.
 */
async function sessionIsLive(page: Page, adminPath: string): Promise<boolean> {
    try {
        const response = await page.request.get(adminPath, {
            maxRedirects: 0,
            failOnStatusCode: false,
            timeout: 30_000,
        });

        return 200 === response.status();
    } catch {
        return false;
    }
}

/**
 * Makes sure this browser context is signed in as the administrator.
 *
 * The page is deliberately left wherever it was: every caller navigates
 * straight afterwards, and loading wp-admin twice is what made this slow.
 * Works on both single-site and subdir-multisite installs because both
 * paths are relative to the project's `baseURL`.
 */
export async function loginAsAdmin(page: Page, loginPath = '/wp-login.php'): Promise<void> {
    const adminPath = loginPath.replace(/wp-login\.php.*$/, 'wp-admin/');
    const context = page.context();
    const file = sessionFile();
    const stored = storedCookies(file);

    if (stored.length > 0 && 0 === (await context.cookies()).length) {
        await context.addCookies(stored);
    }

    if (await sessionIsLive(page, adminPath)) {
        return;
    }

    await context.clearCookies();
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

    try {
        writeFileSync(file, JSON.stringify(await context.cookies()), 'utf8');
    } catch {
        /* A session that cannot be stored only costs the next test its own sign-in. */
    }
}

/**
 * Convenience export: a `test` instance pre-wired with the helper above.
 * Specs that need additional fixtures can extend this further.
 */
export const test = base.extend({});
export { expect };
