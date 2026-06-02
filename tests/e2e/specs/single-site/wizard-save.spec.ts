import { execSync } from 'node:child_process';
import type { Page } from '@playwright/test';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';

/**
 * End-to-end proof of the setup-wizard per-step save rewrite.
 *
 * The 1.x wizard staged values in sessionStorage and only committed them from
 * a single late step, so the 2FA step could silently persist nothing. The new
 * flow saves each step server-side on navigation via `reportedip_wizard_save_step`.
 * These specs drive the real wizard UI and read the options straight back out
 * of the database to prove the round-trip works — including Back navigation,
 * which now re-renders from the saved state (DB is the single source of truth).
 *
 * Serial: the specs mutate global plugin options on the shared WordPress
 * backend, so they must not interleave. afterAll restores a 2FA-free baseline
 * so unrelated specs running against the same stack are not affected.
 */

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';

/**
 * Run a WP-CLI command inside the single-site WordPress container.
 */
function wp(args: string): string {
	return execSync(`docker exec ${WP_CONTAINER} wp --allow-root ${args}`, { encoding: 'utf8' }).toString().trim();
}

/**
 * Read an option's raw value; empty string when absent or false-valued.
 */
function wpOption(name: string): string {
	try {
		return wp(`option get ${name}`);
	} catch {
		return '';
	}
}

/**
 * Reset the wizard + the fields these specs assert on, so each run starts
 * from a fresh-install baseline. Also pins super-admin 2FA enforcement off so
 * enabling 2FA in a spec never locks out the logged-in admin (which would
 * trigger the onboarding-enforcement redirect mid-navigation).
 */
function resetWizard(): void {
	const keys = [
		'reportedip_hive_wizard_completed',
		'reportedip_hive_wizard_completed_at',
		'reportedip_hive_wizard_skipped',
		'reportedip_hive_2fa_enabled_global',
		'reportedip_hive_2fa_allowed_methods',
		'reportedip_hive_2fa_enforce_roles',
		'reportedip_hive_2fa_frontend_enabled',
		'reportedip_hive_minimal_logging',
		'reportedip_hive_data_retention_days',
	];
	for (const key of keys) {
		try {
			wp(`option delete ${key}`);
		} catch {
			/* already absent */
		}
	}
	try {
		wp('option update reportedip_hive_2fa_enforce_super_admins 0');
	} catch {
		/* best effort */
	}
}

/**
 * The `rip-toggle` checkbox is visually replaced by a CSS slider, so the input
 * itself is not "visible" to Playwright. Drive it by clicking the wrapping
 * label; read state straight off the (hidden) input.
 */
async function setToggle(page: Page, inputSelector: string, desired: boolean): Promise<void> {
	const input = page.locator(inputSelector);
	if ((await input.isChecked()) !== desired) {
		await page.locator(`label.rip-toggle:has(${inputSelector})`).click();
	}
}

test.describe.configure({ mode: 'serial' });

test.describe('setup wizard — per-step server save', () => {
	test.beforeEach(() => {
		resetWizard();
	});

	test.afterAll(() => {
		resetWizard();
	});

	test('Privacy step persists toggles + selects, Back re-renders saved state', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-wizard&step=5');

		await setToggle(page, '#rip-minimal-logging', false);
		await page.selectOption('#rip-data-retention', '90');

		await page.click('#rip-step5-next');
		await page.waitForURL((url) => url.searchParams.get('step') === '6');

		expect(wpOption('reportedip_hive_minimal_logging')).toBe('0');
		expect(wpOption('reportedip_hive_data_retention_days')).toBe('90');

		await page.click('.rip-wizard__actions a[href*="step=5"]');
		await page.waitForURL((url) => url.searchParams.get('step') === '5');

		await expect(page.locator('#rip-data-retention')).toHaveValue('90');
		await expect(page.locator('#rip-minimal-logging')).not.toBeChecked();
	});

	test('2FA step persists the global toggle, methods and enforce-roles', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-wizard&step=4');

		await setToggle(page, '#rip-2fa-enabled', true);

		const totp = page.locator('.rip-method-card[data-method="totp"]');
		const totpClass = (await totp.getAttribute('class')) ?? '';
		if (!totpClass.includes('rip-method-card--selected')) {
			await totp.click();
		}

		await page.click('#rip-step4-next');

		// The save is asserted by polling the DB directly, decoupled from where
		// the page navigates: enabling + enforcing 2FA for the admin can trigger
		// the onboarding-enforcement redirect, but the redirect only fires after
		// the per-step save has committed.
		await expect
			.poll(() => wpOption('reportedip_hive_2fa_enabled_global'), { timeout: 15_000 })
			.toBe('1');
		expect(wpOption('reportedip_hive_2fa_allowed_methods')).toContain('totp');
		// The enforce-roles option is written (a JSON array) rather than silently
		// dropped — the exact role sanitisation is covered by the unit suite.
		expect(wpOption('reportedip_hive_2fa_enforce_roles')).toMatch(/^\[.*\]$/);
	});
});
