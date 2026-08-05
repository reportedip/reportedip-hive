import { test, expect } from '../../fixtures/admin';
import {
    setupWebauthnBaseline,
    teardownWebauthnBaseline,
    attachVirtualAuthenticator,
    submitLoginForm,
    enrollPasskeyViaOnboarding,
} from '../../fixtures/webauthn';

/**
 * Multisite mirror of the WebAuthn smoke: enrolment + wp-login assertion
 * on the network's main site. The reset-gate flow is covered on the
 * single-site stack; here the point is that per-blog transients, option
 * routing (sitemeta) and the network-active bootstrap don't break the
 * ceremonies.
 */

const MS_COMPOSE = 'docker-compose.multisite.yml';
const MS_SERVICE = 'wordpress-ms';

test.describe.serial('webauthn security-key ceremonies (multisite)', () => {
    test.beforeEach(() => {
        setupWebauthnBaseline(MS_COMPOSE, MS_SERVICE);
    });

    test.afterAll(() => {
        teardownWebauthnBaseline(MS_COMPOSE, MS_SERVICE);
    });

    test('enrols and signs in via the security key on the main site', async ({ page }) => {
        await attachVirtualAuthenticator(page);

        await submitLoginForm(page);
        await page.waitForURL((url) => url.pathname.includes('/wp-admin/'));
        await enrollPasskeyViaOnboarding(page);

        await page.goto('/wp-login.php?action=logout');
        const confirm = page.locator('a:has-text("log out")');
        if (await confirm.count()) {
            await confirm.click();
        }

        await submitLoginForm(page);
        await expect(page).toHaveURL(/action=reportedip_2fa/);
        await expect(page.locator('#rip-2fa-panel-webauthn')).toBeVisible();

        await page.click('#rip-2fa-webauthn-login');
        await page.waitForURL((url) => url.pathname.includes('/wp-admin/'), { timeout: 30_000 });
    });
});
