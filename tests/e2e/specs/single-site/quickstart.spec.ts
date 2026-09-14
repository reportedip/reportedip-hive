import { execSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { FORGET_CACHED_TIER_CLI } from '../../fixtures/tier';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * Quickstart: one page, two decisions, recommendation applied through the
 * settings registry. The API mock (docker/mu-plugins/rip-api-mock.php)
 * answers verify-key with a Professional role for any key. The cached
 * service answers (see fixtures/tier.ts) are cleared before every test so
 * the plan is whatever this spec establishes.
 *
 * The test key must be 32 to 64 alphanumeric characters: the registered
 * settings sanitizer keeps the previous value on a format error, and the
 * quickstart reports such a key as not saved.
 *
 * Serial: mutates global plugin options on the shared stack.
 */

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';
const PRO_KEY = 'e2eprofessionalkey0123456789abcdef012345';

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

function resetQuickstart(): void {
	const keys = [
		'reportedip_hive_wizard_completed',
		'reportedip_hive_wizard_completed_at',
		'reportedip_hive_api_key',
		'reportedip_hive_known_tier',
		'reportedip_hive_operation_mode',
		'reportedip_hive_block_tor',
		'reportedip_hive_data_retention_days',
		'reportedip_hive_headers_enabled',
		'reportedip_hive_2fa_enabled_global',
		'reportedip_hive_auto_footer_enabled',
		'reportedip_hive_notify_admin',
	];
	for (const key of keys) {
		try {
			wp(`option delete ${key}`);
		} catch {
			/* already absent */
		}
	}
	for (const cmd of [...FORGET_CACHED_TIER_CLI, 'transient delete reportedip_2fa_onboarding_pending_1']) {
		try {
			wp(cmd);
		} catch {
			/* already absent */
		}
	}
	try {
		wp('option update reportedip_hive_2fa_enforce_super_admins 0');
		wp('user meta delete admin reportedip_hive_expert_mode');
	} catch {
		/* best effort */
	}
}

test.describe.configure({ mode: 'serial' });

test.describe('quickstart', () => {
	test.beforeEach(() => {
		resetAdminBaseline();
		resetQuickstart();
	});

	test.afterAll(() => {
		resetAdminBaseline();
		resetQuickstart();
	});

	test('Community without a checked key stays on the page', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-quickstart');

		await expect(page.locator('.rip-mode-card[data-mode="community"]')).toHaveClass(/rip-mode-card--selected/);
		await page.locator('#rip-quickstart-activate').click();
		await expect(page.locator('#rip-quickstart-note')).not.toHaveClass(/rip-is-hidden/);
		await expect(page.locator('#rip-quickstart-note')).toContainText('Local Shield');
		await expect(page).toHaveURL(/page=reportedip-hive-quickstart/);

		expect(wpOption('reportedip_hive_wizard_completed')).toBe('');
	});

	test('Local Shield without a key applies the free recommendation', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-quickstart');

		await expect(page.locator('.rip-mode-card[data-mode="community"]')).toHaveClass(/rip-mode-card--selected/);
		await expect(page.locator('#rip-quickstart-features li[data-tier="professional"]').first()).toHaveClass(/rip-quickstart__feature--locked/);

		await page.locator('.rip-mode-card[data-mode="local"]').click();
		await expect(page.locator('#rip-api-key-card')).toHaveClass(/rip-is-hidden/);

		await page.locator('label.rip-toggle:has(#rip-quickstart-2fa)').click();
		await page.locator('#rip-quickstart-activate').click();
		await page.waitForURL(/page=reportedip-hive(&|$)/);

		expect(wpOption('reportedip_hive_wizard_completed')).toBe('1');
		expect(wpOption('reportedip_hive_operation_mode')).toBe('local');
		expect(wpOption('reportedip_hive_headers_enabled')).toBe('1');
		expect(wpOption('reportedip_hive_bot_action')).toBe('flag');
		expect(wpOption('reportedip_hive_block_tor')).toBe('0');
		expect(wpOption('reportedip_hive_2fa_enabled_global')).toBe('0');
		expect(wpOption('reportedip_hive_auto_footer_enabled')).toBe('1');
		expect(wpOption('reportedip_hive_notify_admin')).toBe('1');
	});

	test('Community with a Professional key unlocks the Professional recommendation', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-quickstart');

		await page.fill('#rip-api-key', PRO_KEY);
		await page.locator('#rip-validate-key').click();
		await expect(page.locator('#rip-api-key-status .rip-input-status--success')).toContainText('Professional');
		await expect(page.locator('#rip-quickstart-features li[data-tier="professional"]').first()).not.toHaveClass(/rip-quickstart__feature--locked/);
		await expect(page.locator('#rip-quickstart-features li[data-tier="business"]').first()).toHaveClass(/rip-quickstart__feature--locked/);
		await expect(page.locator('#rip-quickstart-teaser')).toHaveCount(0);

		await page.locator('#rip-quickstart-activate').click();
		await page.waitForURL(/page=reportedip-hive-2fa-onboarding/);

		expect(wpOption('reportedip_hive_operation_mode')).toBe('community');
		expect(wpOption('reportedip_hive_known_tier')).toBe('professional');
		expect(wpOption('reportedip_hive_block_tor')).toBe('1');
		expect(wpOption('reportedip_hive_data_retention_days')).toBe('90');
		expect(wpOption('reportedip_hive_2fa_frontend_enabled')).toBe('1');
		expect(wpOption('reportedip_hive_bot_action')).toBe('block');
		expect(wpOption('reportedip_hive_2fa_enabled_global')).toBe('1');
		expect(wpOption('reportedip_hive_2fa_enforce_roles')).toContain('administrator');
	});

	test('expert link applies the recommendation and opens the protection page', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-quickstart');
		await page.locator('.rip-mode-card[data-mode="local"]').click();
		await page.locator('label.rip-toggle:has(#rip-quickstart-2fa)').click();
		await page.locator('#rip-quickstart-expert').click();
		await page.waitForURL(/page=reportedip-hive-protection/);

		expect(wpOption('reportedip_hive_wizard_completed')).toBe('1');
		expect(wp('user meta get admin reportedip_hive_expert_mode')).toBe('1');
	});

	test('expert after a first switch-on lands in the settings, not the 2FA onboarding', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-quickstart');
		const nonce = await page.evaluate(() => (window as any).reportedipQuickstart.nonce as string);
		await page.locator('.rip-mode-card[data-mode="local"]').click();
		await page.locator('#rip-quickstart-activate').click();
		await page.waitForURL(/page=reportedip-hive-2fa-onboarding/);

		// The quickstart tab is still open in the admin's browser; its expert click is exactly this request.
		const response = await page.request.post('/wp-admin/admin-ajax.php', {
			form: { action: 'reportedip_quickstart_activate', nonce, mode: 'local', twofa_admins: '1', expert: '1' },
		});
		expect((await response.json()).success).toBe(true);

		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await expect(page).toHaveURL(/page=reportedip-hive-protection/);
		expect(wp('user meta get admin reportedip_hive_expert_mode')).toBe('1');
		expect(wpOption('reportedip_hive_2fa_enforce_roles')).toContain('administrator');
	});

	test('the old wizard slug lands on the quickstart', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-wizard&step=3');
		await page.waitForURL(/page=reportedip-hive-quickstart/);
		await expect(page.locator('#rip-quickstart-activate')).toBeVisible();
	});
});
