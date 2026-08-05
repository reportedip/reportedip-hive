import { test, expect } from '../../fixtures/admin';
import {
    setupWebauthnBaseline,
    teardownWebauthnBaseline,
    attachVirtualAuthenticator,
    submitLoginForm,
    enrollPasskeyViaOnboarding,
    WEBAUTHN_USER,
} from '../../fixtures/webauthn';
import { clearMailbox, getLatestResetLink } from '../../fixtures/reset-flow';

/**
 * End-to-end coverage for the WebAuthn / security-key surfaces using the
 * Chromium virtual authenticator (CTAP2 USB, automatic presence):
 *
 *   1. Enrolment through the onboarding wizard followed by the wp-login
 *      2FA interstitial assertion ceremony.
 *   2. The password-reset gate ceremony — the surface that shipped as a
 *      dead text input before 2.1.33 and locked passkey-only users out.
 *
 * Each spec is self-contained: the virtual authenticator lives inside the
 * test's page, so the credential enrolled in one test does not exist in
 * the next test's authenticator. `beforeEach` therefore resets the server
 * baseline (wipes credentials) and every test runs its own enrolment.
 */

test.describe.serial('webauthn security-key ceremonies', () => {
    test.beforeEach(() => {
        setupWebauthnBaseline();
    });

    test.afterAll(() => {
        teardownWebauthnBaseline();
    });

    /**
     * Fresh page → login (no 2FA yet) → enrol via onboarding → logout.
     * Leaves the server with an enrolled credential matching the page's
     * virtual authenticator.
     */
    async function enrollAndLogout(page: import('@playwright/test').Page): Promise<void> {
        await submitLoginForm(page);
        await page.waitForURL((url) => url.pathname.includes('/wp-admin/'));
        await enrollPasskeyViaOnboarding(page);

        await page.goto('/wp-login.php?action=logout');
        const confirm = page.locator('a:has-text("log out")');
        if (await confirm.count()) {
            await confirm.click();
        }
    }

    test('enrols via onboarding, then wp-login challenge verifies via the key', async ({ page }) => {
        await attachVirtualAuthenticator(page);
        await enrollAndLogout(page);

        await submitLoginForm(page);
        await expect(page).toHaveURL(/action=reportedip_2fa/);
        await expect(page.locator('#rip-2fa-panel-webauthn')).toBeVisible();

        await page.click('#rip-2fa-webauthn-login');
        await page.waitForURL((url) => url.pathname.includes('/wp-admin/'), { timeout: 30_000 });
    });

    test('password-reset gate runs the assertion ceremony end-to-end', async ({ page }) => {
        await attachVirtualAuthenticator(page);
        await enrollAndLogout(page);

        await clearMailbox();
        await page.goto('/wp-login.php?action=lostpassword');
        await page.fill('#user_login', WEBAUTHN_USER);
        await page.click('#wp-submit');

        const resetLink = await getLatestResetLink(WEBAUTHN_USER);
        await page.goto(resetLink);

        await expect(page).toHaveURL(/action=reportedip_2fa_reset/);
        await expect(page.locator('main.rip-2fa-challenge')).toBeVisible();

        await expect(page.locator('#rip-2fa-panel-webauthn')).toBeVisible();
        await expect(page.locator('#rip-2fa-webauthn-login')).toBeVisible();

        await page.click('#rip-2fa-webauthn-login');

        await expect(page).toHaveURL(/action=rp/, { timeout: 30_000 });
        await expect(page.locator('input[name="pass1"]')).toBeVisible();
    });
});
