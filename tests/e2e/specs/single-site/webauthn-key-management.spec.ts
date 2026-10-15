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
 * (templates/partials/webauthn-key-manager.php + two-factor-keys.js) of the
 * free plugin: add via the hardware-key hint, the add button disappears at
 * the one-key limit, rename inline, delete to zero (which disables the
 * method) and the add button returns. The free plugin sends no
 * key-lifecycle mail; backup keys and those mails are the add-on's spec.
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

    test('one key: add, limit, rename and delete-to-disable', async ({ page }) => {
        test.skip(process.env.RIP_E2E_WITH_PRO === '1', 'with the add-on Business keeps the add button for a backup key (pro suite webauthn-key-management)');
        page.on('dialog', (dialog) => dialog.accept());
        await attachVirtualAuthenticator(page);

        await submitLoginForm(page);
        await page.waitForURL((url) => url.pathname.includes('/wp-admin/'));

        await clearMailbox();
        await page.goto('/wp-admin/profile.php');
        const manager = page.locator('#rip-webauthn-key-manager');
        await manager.scrollIntoViewIfNeeded();
        await expect(manager).toBeVisible();
        await expect(manager).toHaveAttribute('data-can-add', '1');
        await expect(page.locator('#rip-webauthn-upgrade-note')).toHaveCount(0);
        await expect(page.locator('#rip-webauthn-keys-empty')).toBeVisible();

        await page.click('#rip-webauthn-add-toggle');
        await page.fill('#rip-webauthn-key-name', 'YubiKey E2E');
        await page.click('.rip-webauthn-add-run[data-hint="security-key"]');

        const rows = page.locator('#rip-webauthn-keys-table tbody tr');
        await expect(rows).toHaveCount(1, { timeout: 20_000 });
        await expect(rows.first()).toContainText('YubiKey E2E');
        await expect(rows.first()).toContainText('Security key');

        await expect(page.locator('#rip-webauthn-add-toggle')).toBeHidden();
        expect(await subjectArrived('security key was added', 3_000)).toBe(false);

        await page.reload();
        await expect(manager).toHaveAttribute('data-can-add', '0');
        await expect(page.locator('#rip-webauthn-add-toggle')).toBeHidden();

        await rows.first().getByRole('button', { name: 'Rename' }).click();
        const renameInput = page.locator('.rip-webauthn-keys__rename-input');
        await renameInput.fill('Renamed key');
        await page.getByRole('button', { name: 'Save' }).click();
        await expect(rows.first()).toContainText('Renamed key', { timeout: 10_000 });

        await rows.first().getByRole('button', { name: 'Remove' }).click();
        await expect(rows).toHaveCount(0, { timeout: 10_000 });
        await expect(page.locator('#rip-webauthn-keys-empty')).toBeVisible();
        await expect(page.locator('#rip-webauthn-keys-status')).toContainText(/disabled/i);
        await expect(page.locator('#rip-webauthn-add-toggle')).toBeVisible();
    });
});
