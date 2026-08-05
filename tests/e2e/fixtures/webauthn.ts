import { execSync } from 'node:child_process';
import type { CDPSession, Page } from '@playwright/test';

/**
 * Helpers for the WebAuthn / security-key E2E specs.
 *
 * The specs drive the real registration + assertion ceremonies through the
 * Chromium DevTools virtual authenticator (CDP `WebAuthn` domain), which
 * behaves like a CTAP2 USB security key with automatic presence simulation
 * — the closest an automated test can get to a YubiKey tap.
 *
 * The PHP baseline lives in `webauthn-setup.php` / `webauthn-teardown.php`
 * and is executed inside the WordPress container via `wp eval-file`, same
 * pattern as the reset-flow fixtures.
 */

export const WEBAUTHN_USER = 'e2e-webauthn-user';
export const WEBAUTHN_PASS = 'E2eWebauthnPass!42';

/**
 * Run a `docker compose exec` command against a stack's WordPress
 * container. The compose file and its service name are parameters (not
 * env vars) because the single-site and multisite specs live in one
 * Playwright run directory but target different stacks — single-site
 * names the service `wordpress`, multisite names it `wordpress-ms`.
 */
function execInWordpress(composeFile: string, service: string, cmd: string): string {
    const fullCmd = `docker compose -f ${composeFile} exec -T ${service} ${cmd}`;
    return execSync(fullCmd, {
        cwd: resolveWorkspaceRoot(),
        encoding: 'utf8',
    }).toString();
}

function resolveWorkspaceRoot(): string {
    return new URL('../../../../', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
}

/**
 * Provision the webauthn E2E baseline (test user without credentials +
 * webauthn in the allowed methods).
 *
 * @param composeFile Compose file of the target stack.
 * @param service     Compose service name of the WordPress container.
 */
export function setupWebauthnBaseline(composeFile = 'docker-compose.yml', service = 'wordpress'): void {
    const out = execInWordpress(
        composeFile,
        service,
        'wp --allow-root eval-file ' +
            'wp-content/plugins/reportedip-hive/tests/e2e/fixtures/webauthn-setup.php'
    );
    if (!out.includes('WebAuthn E2E baseline ready')) {
        throw new Error(`webauthn-setup.php did not report success. Output:\n${out}`);
    }
}

/**
 * Reverse `setupWebauthnBaseline()`.
 *
 * @param composeFile Compose file of the target stack.
 * @param service     Compose service name of the WordPress container.
 */
export function teardownWebauthnBaseline(composeFile = 'docker-compose.yml', service = 'wordpress'): void {
    const out = execInWordpress(
        composeFile,
        service,
        'wp --allow-root eval-file ' +
            'wp-content/plugins/reportedip-hive/tests/e2e/fixtures/webauthn-teardown.php'
    );
    if (!out.includes('WebAuthn E2E baseline torn down')) {
        throw new Error(`webauthn-teardown.php did not report success. Output:\n${out}`);
    }
}

/**
 * Attach a CTAP2 USB virtual authenticator to the page's CDP session.
 * `automaticPresenceSimulation: true` answers every create()/get() prompt
 * as if the user touched the key immediately.
 *
 * Returns the session plus the authenticator id so callers can remove or
 * swap authenticators mid-test (e.g. simulate a second, separate key —
 * two authenticators attached at once race on excludeCredentials).
 */
export async function attachVirtualAuthenticator(
    page: Page,
    transport: 'usb' | 'nfc' | 'ble' = 'usb'
): Promise<{ cdp: CDPSession; authenticatorId: string }> {
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    const { authenticatorId } = (await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: {
            protocol: 'ctap2',
            transport,
            hasResidentKey: false,
            hasUserVerification: false,
            isUserVerified: false,
            automaticPresenceSimulation: true,
        },
    })) as { authenticatorId: string };
    return { cdp, authenticatorId };
}

/**
 * Log in as the webauthn test user via wp-login.php. Ends on either
 * wp-admin (no 2FA yet) or the 2FA challenge interstitial (once a
 * credential is enrolled) — the caller asserts which.
 */
export async function submitLoginForm(page: Page): Promise<void> {
    await page.goto('/wp-login.php');
    await page.waitForSelector('#user_pass');

    // wp-login.php's wp_attempt_focus() steals focus onto #user_login and
    // select()s it ~200ms after load. A fill() racing that timer can end
    // up typing the password into the username field. Wait the timer out,
    // then verify the fields actually hold what we typed before submitting.
    await page.waitForTimeout(400);
    await page.fill('#user_login', WEBAUTHN_USER);
    await page.fill('#user_pass', WEBAUTHN_PASS);
    if ((await page.inputValue('#user_login')) !== WEBAUTHN_USER
        || (await page.inputValue('#user_pass')) !== WEBAUTHN_PASS) {
        await page.fill('#user_login', WEBAUTHN_USER);
        await page.fill('#user_pass', WEBAUTHN_PASS);
    }
    await page.click('#wp-submit');
}

/**
 * Walk the onboarding wizard up to a completed passkey registration.
 * Precondition: logged in as the test user, virtual authenticator attached.
 */
export async function enrollPasskeyViaOnboarding(page: Page): Promise<void> {
    await page.goto('/wp-admin/admin.php?page=reportedip-hive-2fa-onboarding');

    await page.click('button[data-goto-step="2"]');
    await page.click('.rip-mode-card[data-method="webauthn"]');
    await page.click('#rip-2fa-methods-continue');
    await page.click('#rip-2fa-webauthn-register');

    const status = page.locator('#rip-2fa-webauthn-status');
    await status.waitFor({ state: 'visible' });
    await page.waitForSelector(
        '#rip-2fa-webauthn-status.rip-2fa-inline-status--success',
        { timeout: 20_000 }
    );
}
