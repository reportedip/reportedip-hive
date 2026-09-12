import { execSync } from 'node:child_process';
import type { Page } from '@playwright/test';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';

/**
 * Browser round-trip for the settings that joined the registry with the
 * settings-standard audit, plus the wizard fields that now take their ranges
 * from the registry.
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

test.describe('settings standard — every option has a working form', () => {
	test.beforeAll(() => {
		try {
			wp(`option delete ${RESTORE.join(' ')}`);
		} catch {
			/* already absent */
		}
	});

	test.afterAll(() => {
		try {
			wp(`option delete ${RESTORE.join(' ')}`);
		} catch {
			/* already absent */
		}
	});

	test('Notifications tab: service-notice toggles persist both ways', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-settings&tab=notifications');
		await page.waitForLoadState('networkidle');

		await setToggle(page, 'input[type="checkbox"][name="reportedip_hive_promo_enabled"]', false);
		await setToggle(page, 'input[type="checkbox"][name="reportedip_hive_quota_notif_enabled"]', false);
		await setToggle(page, 'input[type="checkbox"][name="reportedip_hive_tier_change_mail_enabled"]', true);
		await page.click('form:has(input[type="checkbox"][name="reportedip_hive_promo_enabled"]) input[type="submit"]');
		await page.waitForURL(/settings-updated=true/);

		expect(wpOption('reportedip_hive_promo_enabled')).toBe('0');
		expect(wpOption('reportedip_hive_quota_notif_enabled')).toBe('0');
		expect(wpOption('reportedip_hive_tier_change_mail_enabled')).toBe('1');

		await expect(page.locator('input[type="checkbox"][name="reportedip_hive_promo_enabled"]')).not.toBeChecked();
		await expect(page.locator('input[type="checkbox"][name="reportedip_hive_tier_change_mail_enabled"]')).toBeChecked();

		await setToggle(page, 'input[type="checkbox"][name="reportedip_hive_promo_enabled"]', true);
		await page.click('form:has(input[type="checkbox"][name="reportedip_hive_promo_enabled"]) input[type="submit"]');
		await page.waitForURL(/settings-updated=true/);
		expect(wpOption('reportedip_hive_promo_enabled')).toBe('1');
	});

	test('2FA tab: reminder trio and the e-mail subject go through the registry', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-settings&tab=two_factor');
		await page.waitForLoadState('networkidle');

		await page.fill('input[name="reportedip_hive_2fa_reminder_hard_threshold"]', '7');
		// The role list sits inside a section the page may keep collapsed, so
		// the boxes are set directly; the form post is what is under test.
		await page.locator('input[name="reportedip_hive_2fa_reminder_hard_roles[]"]').evaluateAll((boxes) => {
			for (const box of boxes) {
				(box as HTMLInputElement).checked = false;
			}
		});
		await page.fill('input[name="reportedip_hive_2fa_email_subject"]', '[{site_name}] Dein Code');
		await page.click('form:has(input[name="reportedip_hive_2fa_email_subject"]) input[type="submit"]');
		await page.waitForURL(/settings-updated=true/);

		expect(wpOption('reportedip_hive_2fa_reminder_hard_threshold')).toBe('7');
		expect(wpOption('reportedip_hive_2fa_reminder_hard_roles')).toBe('[]');
		expect(wpOption('reportedip_hive_2fa_email_subject')).toBe('[{site_name}] Dein Code');
		await expect(page.locator('input[name="reportedip_hive_2fa_email_subject"]')).toHaveValue('[{site_name}] Dein Code');

		// The browser refuses an out-of-range threshold before the post (the
		// registry clamp behind it is unit-tested); a re-ticked role round-trips.
		await expect(page.locator('input[name="reportedip_hive_2fa_reminder_hard_threshold"]')).toHaveAttribute('max', '10');
		await page.fill('input[name="reportedip_hive_2fa_reminder_hard_threshold"]', '99');
		expect(await page.locator('input[name="reportedip_hive_2fa_reminder_hard_threshold"]').evaluate((el) => (el as HTMLInputElement).checkValidity())).toBe(false);
		await page.fill('input[name="reportedip_hive_2fa_reminder_hard_threshold"]', '3');
		await page.locator('input[name="reportedip_hive_2fa_reminder_hard_roles[]"][value="administrator"]').evaluate((box) => {
			(box as HTMLInputElement).checked = true;
		});
		await page.click('form:has(input[name="reportedip_hive_2fa_email_subject"]) input[type="submit"]');
		await page.waitForLoadState('load');

		expect(wpOption('reportedip_hive_2fa_reminder_hard_threshold')).toBe('3');
		expect(wpOption('reportedip_hive_2fa_reminder_hard_roles')).toBe('["administrator"]');
	});

	test('Firewall page: the Extended Protection body-inspection switch saves through the registry writer', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-firewall&tab=waf');

		const card = page.locator('#rip-waf-dropin');
		const toggle = 'input[data-opt="reportedip_hive_waf_dropin_skip_authenticated"]';
		await expect(card.locator(toggle)).toBeChecked();

		await card.locator(`label.rip-toggle:has(${toggle})`).click();
		await card.locator('button[data-rip-save="reportedip_hive_registry_save"]').click();
		await expect.poll(() => wpOption('reportedip_hive_waf_dropin_skip_authenticated'), { timeout: 15_000 }).toBe('0');

		await page.reload();
		await expect(page.locator(`#rip-waf-dropin ${toggle}`)).not.toBeChecked();

		await page.locator(`#rip-waf-dropin label.rip-toggle:has(${toggle})`).click();
		await page.locator('#rip-waf-dropin button[data-rip-save="reportedip_hive_registry_save"]').click();
		await expect.poll(() => wpOption('reportedip_hive_waf_dropin_skip_authenticated'), { timeout: 15_000 }).toBe('1');
	});

	test('Wizard: ranges and choices come from the registry', async ({ page }) => {
		await loginAsAdmin(page);

		await page.goto('/wp-admin/admin.php?page=reportedip-hive-wizard&step=3');
		await page.locator('label:has(input[name="protection_level"][value="paranoid"])').click();
		await page.click('#rip-step3-next');
		await page.waitForURL((url) => url.searchParams.get('step') === '4');
		expect(wpOption('reportedip_hive_block_threshold')).toBe('25');
		expect(wpOption('reportedip_hive_failed_login_threshold')).toBe('2');

		await page.goto('/wp-admin/admin.php?page=reportedip-hive-wizard&step=5');
		await expect(page.locator('#rip-2fa-grace-days')).toHaveAttribute('max', '60');
		await expect(page.locator('#rip-2fa-max-skips')).toHaveAttribute('max', '20');
		await page.fill('#rip-2fa-grace-days', '99');
		await page.fill('#rip-2fa-max-skips', '5');
		await page.click('#rip-step5-next');
		await page.waitForURL((url) => url.searchParams.get('step') === '6');
		expect(wpOption('reportedip_hive_2fa_enforce_grace_days')).toBe('60');
		expect(wpOption('reportedip_hive_2fa_max_skips')).toBe('5');

		await page.goto('/wp-admin/admin.php?page=reportedip-hive-wizard&step=9');
		await page.locator('label:has(input[name="promote_variant"][value="shield"])').click();
		await page.locator('label:has(input[name="promote_align"][value="right"])').click();
		await page.click('#rip-promote-continue');
		await page.waitForURL((url) => url.searchParams.get('step') === '10');
		expect(wpOption('reportedip_hive_auto_footer_variant')).toBe('shield');
		expect(wpOption('reportedip_hive_auto_footer_align')).toBe('right');
	});
});
