import { test, expect } from '../../fixtures/admin';
import {
    setupWebauthnBaseline,
    teardownWebauthnBaseline,
    attachVirtualAuthenticator,
    submitLoginForm,
} from '../../fixtures/webauthn';
import { clearMailbox, MAILPIT_BASE_URL } from '../../fixtures/reset-flow';

/**
 * Multisite mirror of the profile method-management smoke: the method
 * cards read the allowed-method list through Option_Routing (sitemeta on
 * multisite), and the set_primary / disable_method AJAX endpoints must
 * behave identically on a network-active install. Passkey enrolment is
 * covered by the multisite webauthn spec; here email is enrolled first
 * and TOTP added second so the default-preservation path runs without a
 * virtual-authenticator dependency.
 */

const MS_COMPOSE = 'docker-compose.multisite.yml';
const MS_SERVICE = 'wordpress-ms';

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

test.describe.serial('profile 2FA method management (multisite)', () => {
    test.beforeEach(() => {
        setupWebauthnBaseline(MS_COMPOSE, MS_SERVICE);
    });

    test.afterAll(() => {
        teardownWebauthnBaseline(MS_COMPOSE, MS_SERVICE);
    });

    test('email enrols via the inline flow and stays the default when a passkey is added', async ({ page }) => {
        page.on('dialog', (dialog) => dialog.accept());
        await attachVirtualAuthenticator(page);

        await submitLoginForm(page);
        await page.waitForURL((url) => url.pathname.includes('/wp-admin/'));

        await page.goto('/wp-admin/profile.php');
        const methods = page.locator('.rip-2fa-methods');
        await methods.scrollIntoViewIfNeeded();
        await expect(methods).toBeVisible();

        await clearMailbox();
        const emailRow = page.locator('.rip-2fa-method[data-method="email"]');
        await emailRow.locator('[data-action="setup"]').click();
        await expect(emailRow.locator('[data-flow="email"]')).toBeVisible();

        const code = await getLatestEmailCode();
        await emailRow.locator('[data-flow="email"] [data-code]').fill(code);

        const recoveryPanel = page.locator('#rip-2fa-method-recovery');
        await expect(
            recoveryPanel,
            'the first method must present the fresh recovery codes'
        ).toBeVisible({ timeout: 20_000 });
        await expect(recoveryPanel.locator('.rip-2fa-recovery-codes__code').first()).toBeVisible();
        await recoveryPanel.locator('[data-recovery-done]').click();

        await expect(emailRow).toHaveAttribute('data-active', '1', { timeout: 20_000 });
        await expect(emailRow.locator('.rip-badge--info')).toContainText('Default');

        await page.locator('#rip-webauthn-key-manager').scrollIntoViewIfNeeded();
        await page.click('#rip-webauthn-add-toggle');
        await page.fill('#rip-webauthn-key-name', 'MS profile key');
        await page.click('.rip-webauthn-add-run[data-hint="security-key"]');
        await expect(page.locator('#rip-webauthn-keys-table tbody tr')).toHaveCount(1, { timeout: 20_000 });

        await page.goto('/wp-admin/profile.php');
        await expect(page.locator('.rip-2fa-method[data-method="webauthn"]')).toHaveAttribute('data-active', '1');
        await expect(
            page.locator('.rip-2fa-method[data-method="email"] .rip-badge--info'),
            'adding a passkey as a second method must not steal the default from email'
        ).toContainText('Default');

        await page.locator('.rip-2fa-method[data-method="webauthn"] [data-action="make-default"]').click();
        await expect(
            page.locator('.rip-2fa-method[data-method="webauthn"] .rip-badge--info')
        ).toContainText('Default', { timeout: 20_000 });
    });
});
