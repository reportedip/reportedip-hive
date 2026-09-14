import { execSync } from 'node:child_process';
import type { Page } from '@playwright/test';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';

/**
 * Browser round-trip for the settings that joined the registry with the
 * settings-standard audit, the settings cards only.
 *
 * Every assertion reads the option back out of the database, so a form that
 * renders fine but posts into the void (the way the reminder trio and the
 * service-notice toggles did for years) fails here.
 *
 * Serial and self-restoring: the specs mutate global options on the shared
 * stack, and the Firewall card save is an AJAX write that lands immediately.
 */

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';

function wp(args: string): string {
	return execSync(`docker exec ${WP_CONTAINER} wp --allow-root ${args}`, { encoding: 'utf8' }).toString().trim();
}

function wpOption(name: string): string {
	try {
		return wp(`option get ${name}`);
	} catch {
		return '';
	}
}

async function setToggle(page: Page, inputSelector: string, desired: boolean): Promise<void> {
	const input = page.locator(inputSelector);
	if ((await input.isChecked()) !== desired) {
		await page.locator(`label.rip-toggle:has(${inputSelector})`).click();
	}
}

const RESTORE = [
	'reportedip_hive_promo_enabled',
	'reportedip_hive_quota_notif_enabled',
	'reportedip_hive_tier_change_mail_enabled',
	'reportedip_hive_2fa_reminder_enabled',
	'reportedip_hive_2fa_reminder_hard_threshold',
	'reportedip_hive_2fa_reminder_hard_roles',
	'reportedip_hive_2fa_email_subject',
	'reportedip_hive_waf_dropin_skip_authenticated',
	'reportedip_hive_2fa_enforce_grace_days',
	'reportedip_hive_2fa_max_skips',
	'reportedip_hive_auto_footer_variant',
	'reportedip_hive_auto_footer_align',
	'reportedip_hive_wizard_completed',
	'reportedip_hive_wizard_completed_at',
	'reportedip_hive_wizard_skipped',
];

test.describe.configure({ mode: 'serial' });

test.use({ video: 'on' });


/** Open one protection card so its fields become visible to Playwright. */
async function openSection(page: Page, id: string): Promise<void> {
	await page.locator(`#${id}`).evaluate((el) => {
		(el as HTMLDetailsElement).open = true;
	});
}

test.describe('settings standard — every option has a working form', () => {
	test.beforeAll(() => {
		wp('user meta update admin reportedip_hive_expert_mode 1');
		try {
			wp(`option delete ${RESTORE.join(' ')}`);
		} catch {
			/* already absent */
		}
	});

	test.afterAll(() => {
		try {
			wp('user meta delete admin reportedip_hive_expert_mode');
		} catch {
			/* absent */
		}
		try {
			wp(`option delete ${RESTORE.join(' ')}`);
		} catch {
			/* already absent */
		}
	});

	test('Notifications card: service-notice toggles persist both ways', async ({ page }) => {
		// The apply service skips a value that equals the stored one, and a
		// missing row counts as the default (on). Start the mail switch at off
		// so the round trip to on is an actual write.
		wp('option update reportedip_hive_tier_change_mail_enabled 0');
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await openSection(page, 'notifications');

		await setToggle(page, 'input[type="checkbox"][name="reportedip_hive_promo_enabled"]', false);
		await setToggle(page, 'input[type="checkbox"][name="reportedip_hive_quota_notif_enabled"]', false);
		await setToggle(page, 'input[type="checkbox"][name="reportedip_hive_tier_change_mail_enabled"]', true);
		await page.click('#notifications form button[type="submit"]');
		await page.waitForURL(/page=reportedip-hive-protection#notifications/);

		expect(wpOption('reportedip_hive_promo_enabled')).toBe('0');
		expect(wpOption('reportedip_hive_quota_notif_enabled')).toBe('0');
		expect(wpOption('reportedip_hive_tier_change_mail_enabled')).toBe('1');

		await expect(page.locator('#notifications input[type="checkbox"][name="reportedip_hive_promo_enabled"]')).not.toBeChecked();
		await expect(page.locator('#notifications input[type="checkbox"][name="reportedip_hive_tier_change_mail_enabled"]')).toBeChecked();

		await setToggle(page, 'input[type="checkbox"][name="reportedip_hive_promo_enabled"]', true);
		await page.click('#notifications form button[type="submit"]');
		await page.waitForURL(/page=reportedip-hive-protection#notifications/);
		expect(wpOption('reportedip_hive_promo_enabled')).toBe('1');
	});

	test('2FA card: reminder trio and the e-mail subject go through the registry', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await openSection(page, 'account_security');

		await page.fill('#account_security input[name="reportedip_hive_2fa_reminder_hard_threshold"]', '7');
		await page.locator('#account_security input[name="reportedip_hive_2fa_reminder_hard_roles[]"]').evaluateAll((boxes) => {
			for (const box of boxes) {
				(box as HTMLInputElement).checked = false;
			}
		});
		await page.fill('#account_security input[name="reportedip_hive_2fa_email_subject"]', '[{site_name}] Dein Code');
		await page.click('#account_security form button[type="submit"]');
		await page.waitForURL(/page=reportedip-hive-protection#account_security/);

		expect(wpOption('reportedip_hive_2fa_reminder_hard_threshold')).toBe('7');
		expect(wpOption('reportedip_hive_2fa_reminder_hard_roles')).toBe('[]');
		expect(wpOption('reportedip_hive_2fa_email_subject')).toBe('[{site_name}] Dein Code');
		await expect(page.locator('#account_security input[name="reportedip_hive_2fa_email_subject"]')).toHaveValue('[{site_name}] Dein Code');

		// The browser refuses an out-of-range threshold before the post (the
		// registry clamp behind it is unit-tested); a re-ticked role round-trips.
		await expect(page.locator('#account_security input[name="reportedip_hive_2fa_reminder_hard_threshold"]')).toHaveAttribute('max', '10');
		await page.fill('#account_security input[name="reportedip_hive_2fa_reminder_hard_threshold"]', '99');
		expect(await page.locator('#account_security input[name="reportedip_hive_2fa_reminder_hard_threshold"]').evaluate((el) => (el as HTMLInputElement).checkValidity())).toBe(false);
		await page.fill('#account_security input[name="reportedip_hive_2fa_reminder_hard_threshold"]', '3');
		await page.locator('#account_security input[name="reportedip_hive_2fa_reminder_hard_roles[]"][value="administrator"]').evaluate((box) => {
			(box as HTMLInputElement).checked = true;
		});
		await page.click('#account_security form button[type="submit"]');
		await page.waitForURL(/page=reportedip-hive-protection#account_security/);

		expect(wpOption('reportedip_hive_2fa_reminder_hard_threshold')).toBe('3');
		expect(wpOption('reportedip_hive_2fa_reminder_hard_roles')).toBe('["administrator"]');
	});

	test('Firewall card: the Extended Protection body-inspection switch saves through the registry', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await openSection(page, 'waf');

		const toggle = '#waf input[name="reportedip_hive_waf_dropin_skip_authenticated"]';
		await expect(page.locator(toggle)).toBeChecked();

		await page.locator(`#waf label.rip-toggle:has(input[name="reportedip_hive_waf_dropin_skip_authenticated"])`).click();
		await page.click('#waf form button[type="submit"]');
		await page.waitForURL(/page=reportedip-hive-protection#waf/);
		await expect.poll(() => wpOption('reportedip_hive_waf_dropin_skip_authenticated'), { timeout: 15_000 }).toBe('0');
		await expect(page.locator(toggle)).not.toBeChecked();

		await page.locator(`#waf label.rip-toggle:has(input[name="reportedip_hive_waf_dropin_skip_authenticated"])`).click();
		await page.click('#waf form button[type="submit"]');
		await page.waitForURL(/page=reportedip-hive-protection#waf/);
		await expect.poll(() => wpOption('reportedip_hive_waf_dropin_skip_authenticated'), { timeout: 15_000 }).toBe('1');
	});
});
