import { test, expect } from '../../fixtures/admin';
import {
    setupWebauthnBaseline,
    teardownWebauthnBaseline,
    attachVirtualAuthenticator,
    submitLoginForm,
} from '../../fixtures/webauthn';
import { clearMailbox, MAILPIT_BASE_URL } from '../../fixtures/reset-flow';

/**
 * End-to-end coverage for the security-key manager on the user profile
 * (templates/partials/webauthn-key-manager.php + two-factor-keys.js):
 * add via the hardware-key hint, rename inline, enrol a backup key on a
 * second virtual authenticator, delete down to zero (which disables the
 * method), and the "key added" notification mail.
 */

async function subjectArrived(fragment: string, timeoutMs = 15_000): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const res = await fetch(`${MAILPIT_BASE_URL}/api/v1/messages?limit=10`);
        if (res.ok) {
            const list = (await res.json()) as { messages?: Array<{ Subject: string }> };
            if ((list.messages ?? []).some((m) => m.Subject.includes(fragment))) {
                return true;
            }
        }
        await new Promise((r) => setTimeout(r, 250));
    }
    return false;
}

test.describe.serial('webauthn key manager', () => {
    test.beforeEach(() => {
        setupWebauthnBaseline();
    });

    test.afterAll(() => {
        teardownWebauthnBaseline();
    });

    test('add, rename, backup key and delete-to-disable lifecycle', async ({ page }) => {
        page.on('dialog', (dialog) => dialog.accept());
        const { cdp, authenticatorId } = await attachVirtualAuthenticator(page);

        await submitLoginForm(page);
        await page.waitForURL((url) => url.pathname.includes('/wp-admin/'));

        await clearMailbox();
        await page.goto('/wp-admin/profile.php');
        const manager = page.locator('#rip-webauthn-key-manager');
        await manager.scrollIntoViewIfNeeded();
        await expect(manager).toBeVisible();
        await expect(page.locator('#rip-webauthn-keys-empty')).toBeVisible();

        await page.click('#rip-webauthn-add-toggle');
        await page.fill('#rip-webauthn-key-name', 'YubiKey E2E');
        await page.click('.rip-webauthn-add-run[data-hint="security-key"]');

        const rows = page.locator('#rip-webauthn-keys-table tbody tr');
        await expect(rows).toHaveCount(1, { timeout: 20_000 });
        await expect(rows.first()).toContainText('YubiKey E2E');
        await expect(rows.first()).toContainText('Security key');

        expect(await subjectArrived('security key was added')).toBe(true);

        await rows.first().getByRole('button', { name: 'Rename' }).click();
        const renameInput = page.locator('.rip-webauthn-keys__rename-input');
        await renameInput.fill('Renamed key');
        await page.getByRole('button', { name: 'Save' }).click();
        await expect(rows.first()).toContainText('Renamed key', { timeout: 10_000 });

        // Simulate a physically different backup key: detach the first
        // authenticator (its credential lives server-side already) so the
        // create() call cannot race into its excludeCredentials rejection.
        await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
        await cdp.send('WebAuthn.addVirtualAuthenticator', {
            options: {
                protocol: 'ctap2',
                transport: 'usb',
                hasResidentKey: false,
                hasUserVerification: false,
                isUserVerified: false,
                automaticPresenceSimulation: true,
            },
        });
        await page.click('#rip-webauthn-add-toggle');
        await page.fill('#rip-webauthn-key-name', 'Backup key');
        await page.click('.rip-webauthn-add-run[data-hint="security-key"]');
        await expect(rows).toHaveCount(2, { timeout: 20_000 });

        await rows.filter({ hasText: 'Backup key' }).getByRole('button', { name: 'Remove' }).click();
        await expect(rows).toHaveCount(1, { timeout: 10_000 });

        await rows.first().getByRole('button', { name: 'Remove' }).click();
        await expect(rows).toHaveCount(0, { timeout: 10_000 });
        await expect(page.locator('#rip-webauthn-keys-empty')).toBeVisible();
        await expect(page.locator('#rip-webauthn-keys-status')).toContainText(/disabled/i);
    });
});
