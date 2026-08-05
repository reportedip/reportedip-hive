import { test, expect } from '../../fixtures/admin';
import {
    setupWebauthnBaseline,
    teardownWebauthnBaseline,
    attachVirtualAuthenticator,
    submitLoginForm,
} from '../../fixtures/webauthn';
import { clearMailbox, MAILPIT_BASE_URL } from '../../fixtures/reset-flow';

/**
 * End-to-end coverage for the profile 2FA method cards
 * (render_user_profile_section + two-factor-admin.js):
 *
 *   1. Method rows render with descriptions for a user without 2FA.
 *   2. First method (passkey) enrols via the embedded key manager and
 *      becomes the default.
 *   3. Email enrols as a SECOND method through the inline flow; the
 *      default method must stay on the passkey (the enable_for_user
 *      clobber fixed in 2.1.36) and no fresh recovery codes may appear.
 *   4. "Make default" switches the default to email and the login
 *      challenge opens with the email panel preselected.
 *   5. "Remove" drops the email method and the default falls back.
 */

async function getLatestEmailCode(timeoutMs = 15_000): Promise<string> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const listRes = await fetch(`${MAILPIT_BASE_URL}/api/v1/messages?limit=1`);
        if (listRes.ok) {
            const list = (await listRes.json()) as { messages?: Array<{ ID: string }> };
            if (list.messages && list.messages.length > 0) {
                const id = list.messages[0].ID;
                const msg = (await (await fetch(`${MAILPIT_BASE_URL}/api/v1/message/${id}`)).json()) as {
                    Text?: string;
                    HTML?: string;
                };
                const match = `${msg.Text ?? ''}\n${msg.HTML ?? ''}`.match(/\b(\d{6})\b/);
                if (match) {
                    return match[1];
                }
            }
        }
        await new Promise((r) => setTimeout(r, 250));
    }
    throw new Error(`No 2FA email code arrived within ${timeoutMs}ms.`);
}

test.describe.serial('profile 2FA method management', () => {
    test.beforeEach(() => {
        setupWebauthnBaseline();
    });

    test.afterAll(() => {
        teardownWebauthnBaseline();
    });

    test('renders method cards with lay descriptions for a fresh user', async ({ page }) => {
        await submitLoginForm(page);
        await page.waitForURL((url) => url.pathname.includes('/wp-admin/'));

        await page.goto('/wp-admin/profile.php');
        const methods = page.locator('.rip-2fa-methods');
        await methods.scrollIntoViewIfNeeded();
        await expect(methods).toBeVisible();

        const totpRow = page.locator('.rip-2fa-method[data-method="totp"]');
        await expect(totpRow).toHaveAttribute('data-active', '0');
        await expect(totpRow).toContainText('Authenticator app');
        await expect(totpRow.locator('[data-action="setup"]')).toBeVisible();

        const emailRow = page.locator('.rip-2fa-method[data-method="email"]');
        await expect(emailRow).toContainText('6-digit code');
        await expect(emailRow.locator('[data-action="setup"]')).toBeVisible();

        const webauthnRow = page.locator('.rip-2fa-method[data-method="webauthn"]');
        await expect(webauthnRow.locator('#rip-webauthn-key-manager')).toBeVisible();
    });

    test('second method keeps the default, switching and removal work', async ({ page }) => {
        page.on('dialog', (dialog) => dialog.accept());
        await attachVirtualAuthenticator(page);

        await submitLoginForm(page);
        await page.waitForURL((url) => url.pathname.includes('/wp-admin/'));

        await clearMailbox();
        await page.goto('/wp-admin/profile.php');
        await page.locator('#rip-webauthn-key-manager').scrollIntoViewIfNeeded();
        await page.click('#rip-webauthn-add-toggle');
        await page.fill('#rip-webauthn-key-name', 'Profile spec key');
        await page.click('.rip-webauthn-add-run[data-hint="security-key"]');
        await expect(page.locator('#rip-webauthn-keys-table tbody tr')).toHaveCount(1, { timeout: 20_000 });

        await page.goto('/wp-admin/profile.php');
        const webauthnRow = page.locator('.rip-2fa-method[data-method="webauthn"]');
        await expect(webauthnRow).toHaveAttribute('data-active', '1');
        await expect(webauthnRow.locator('.rip-badge--info')).toContainText('Default');

        await clearMailbox();
        const emailRow = page.locator('.rip-2fa-method[data-method="email"]');
        await emailRow.locator('[data-action="setup"]').click();
        const emailFlow = emailRow.locator('[data-flow="email"]');
        await expect(emailFlow).toBeVisible();

        const code = await getLatestEmailCode();
        await emailFlow.locator('[data-code]').fill(code);

        await expect(emailRow).toHaveAttribute('data-active', '1', { timeout: 20_000 });
        await expect(
            page.locator('.rip-2fa-method[data-method="webauthn"] .rip-badge--info'),
            'adding a second method must not steal the default from the passkey'
        ).toContainText('Default');
        await expect(page.locator('#rip-2fa-method-recovery')).toBeHidden();

        await page.locator('.rip-2fa-method[data-method="email"] [data-action="make-default"]').click();
        await expect(
            page.locator('.rip-2fa-method[data-method="email"] .rip-badge--info')
        ).toContainText('Default', { timeout: 20_000 });

        await page.goto('/wp-login.php?action=logout');
        const confirm = page.locator('a:has-text("log out")');
        if (await confirm.count()) {
            await confirm.click();
        }

        await submitLoginForm(page);
        await expect(page).toHaveURL(/action=reportedip_2fa/);
        await expect(
            page.locator('.rip-2fa-challenge__panel--active[data-panel="email"]'),
            'the challenge must open with the chosen default method'
        ).toBeVisible();

        await page.click('#rip-2fa-tab-webauthn');
        await expect(page.locator('#rip-2fa-panel-webauthn')).toBeVisible();
        await page.click('#rip-2fa-webauthn-login');
        await page.waitForURL((url) => url.pathname.includes('/wp-admin/'), { timeout: 30_000 });

        await page.goto('/wp-admin/profile.php');
        await page.locator('.rip-2fa-method[data-method="email"] [data-action="remove"]').click();
        await expect(
            page.locator('.rip-2fa-method[data-method="email"]')
        ).toHaveAttribute('data-active', '0', { timeout: 20_000 });
        await expect(
            page.locator('.rip-2fa-method[data-method="webauthn"] .rip-badge--info'),
            'removing the default method must fall back to a remaining method'
        ).toContainText('Default');
    });
});
