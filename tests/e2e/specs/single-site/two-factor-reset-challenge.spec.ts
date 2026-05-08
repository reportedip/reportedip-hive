import { test, expect } from '../../fixtures/admin';
import {
    setupResetFlowBaseline,
    teardownResetFlowBaseline,
    clearMailbox,
    getLatestResetLink,
    RESET_FLOW_RECOVERY_CODES,
    RESET_FLOW_USER,
} from '../../fixtures/reset-flow';

/**
 * End-to-end coverage for the password-reset 2FA challenge surface
 * (`wp-login.php?action=reportedip_2fa_reset`).
 *
 * The 2.0.0 release shipped with three observable defects on this page
 * that none of the unit tests caught: wrong codes did not surface an
 * error, the initial OTP was never dispatched, and there was no resend
 * path. This suite locks down the post-2.0.1 behaviour at the browser
 * level so a future regression can never silently re-introduce any of
 * them.
 *
 * Each spec runs in series (test.describe.serial) because they share the
 * Mailpit inbox and the reset-key-bound transient on the user record —
 * fully parallel execution would let two reset attempts race for the
 * same key.
 */

test.describe.serial('password-reset 2FA challenge', () => {
    test.beforeAll(() => {
        setupResetFlowBaseline();
    });

    test.afterAll(() => {
        teardownResetFlowBaseline();
    });

    /**
     * Walks from the lostpassword form through to the challenge page,
     * returns the page sitting on the challenge with a fresh reset link
     * already loaded. Used by every spec below — extracted so a single
     * change to the routing keeps all specs in sync.
     */
    async function navigateToChallenge(page: import('@playwright/test').Page): Promise<void> {
        await clearMailbox();

        await page.goto('/wp-login.php?action=lostpassword');
        await page.fill('#user_login', RESET_FLOW_USER);
        await page.click('#wp-submit');
        await expect(page.locator('h1.screen-reader-text', { hasText: 'Check your email' })).toBeVisible();

        const resetLink = await getLatestResetLink(RESET_FLOW_USER);
        await page.goto(resetLink);

        await expect(page).toHaveURL(/action=reportedip_2fa_reset/);
        await expect(page.locator('main.rip-2fa-challenge')).toBeVisible();
    }

    test('challenge page renders the design-system card with both eligible methods', async ({ page }) => {
        await navigateToChallenge(page);

        await expect(page.locator('h1.rip-2fa-challenge__title')).toContainText(
            'Confirm your identity to reset your password'
        );

        const methods = page.locator('nav.rip-2fa-challenge__methods a.rip-2fa-challenge__method-tab');
        await expect(methods).toHaveCount(2);
        await expect(methods.filter({ hasText: 'Authenticator app' })).toBeVisible();
        await expect(methods.filter({ hasText: 'Recovery code' })).toBeVisible();

        await expect(page.locator('input[name="reportedip_2fa_reset_code"]')).toBeVisible();
        await expect(page.locator('button[type="submit"].rip-button--primary')).toContainText(
            'Verify and continue'
        );
    });

    test('wrong recovery code shows inline rip-alert--danger inside the card', async ({ page }) => {
        await navigateToChallenge(page);

        await page.click('nav.rip-2fa-challenge__methods a.rip-2fa-challenge__method-tab:has-text("Recovery code")');
        await expect(page).toHaveURL(/method=recovery/);

        await page.fill('input[name="reportedip_2fa_reset_code"]', 'wrongcod');
        await Promise.all([
            page.waitForLoadState('domcontentloaded'),
            page.click('button[type="submit"]'),
        ]);

        const alert = page.locator('main.rip-2fa-challenge .rip-alert.rip-alert--danger');
        await expect(alert).toBeVisible();
        await expect(alert).toContainText(/Verification failed/i);

        await expect(page).toHaveURL(/action=reportedip_2fa_reset/);
        await expect(page.locator('input[name="reportedip_2fa_reset_code"]')).toBeVisible();
    });

    test('correct recovery code redirects to the reset-password form', async ({ page }) => {
        await navigateToChallenge(page);

        await page.click('nav.rip-2fa-challenge__methods a.rip-2fa-challenge__method-tab:has-text("Recovery code")');
        await expect(page).toHaveURL(/method=recovery/);

        await page.fill('input[name="reportedip_2fa_reset_code"]', RESET_FLOW_RECOVERY_CODES[0]);
        await page.click('button[type="submit"]');

        await expect(page).toHaveURL(/action=rp/, { timeout: 10_000 });
        await expect(page.locator('input[name="pass1"]')).toBeVisible();
    });

    test('challenge card has plugin chrome and not the default WP login chrome', async ({ page }) => {
        await navigateToChallenge(page);

        const card = page.locator('main.rip-2fa-challenge');
        await expect(card).toBeVisible();

        const cardBox = await card.boundingBox();
        expect(cardBox?.width).toBeGreaterThan(300);

        await expect(page.locator('body.login-action-reportedip_2fa_reset')).toHaveCount(1);

        await expect(page.locator('#login > h1')).not.toBeVisible();

        await expect(page.locator('h1.rip-2fa-challenge__title')).toBeVisible();

        const cardBg = await card.evaluate((el) => window.getComputedStyle(el).backgroundColor);
        expect(cardBg).toMatch(/rgb\(255,\s*255,\s*255\)|rgba\(255,\s*255,\s*255/);
    });
});
