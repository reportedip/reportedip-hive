import { execSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * Protection page: one card per registry section, simple/expert depth,
 * search, legacy aliases, tools page reachability.
 */
const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';

function wp(args: string): string {
	return execSync(`docker exec ${WP_CONTAINER} wp --allow-root ${args}`, { encoding: 'utf8' }).toString().trim();
}

function forgetExpert(): void {
	try {
		wp('user meta delete admin reportedip_hive_expert_mode');
	} catch {
		/* absent */
	}
}

test.describe.configure({ mode: 'serial' });

test.describe('protection page', () => {
	test.beforeAll(() => {
		resetAdminBaseline();
		forgetExpert();
		wp('option update reportedip_hive_data_retention_days 30');
	});

	test.afterAll(() => {
		forgetExpert();
	});

	test('simple mode shows the simple keys and hides the expert-only sections behind a note', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await expect(page.locator('#blocking input[name="reportedip_hive_auto_block"]')).toHaveCount(1);
		await expect(page.locator('#blocking input[name="reportedip_hive_block_ladder_minutes"]')).toHaveCount(0);
		await expect(page.locator('#headers form')).toHaveCount(0);
		await expect(page.locator('#headers')).toContainText('Runs on the recommendation');
	});

	test('a section saves through the registry and reports the change', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await page.locator('#privacy_logs summary').click();
		await page.fill('#privacy_logs input[name="reportedip_hive_data_retention_days"]', '45');
		await page.locator('#privacy_logs form button[type="submit"]').click();
		await page.waitForURL(/page=reportedip-hive-protection#privacy_logs/);
		await expect(page.locator('.rip-alert--success')).toContainText('saved');
		expect(wp('option get reportedip_hive_data_retention_days')).toBe('45');
		await expect(page.locator('#privacy_logs .rip-protection__status')).toContainText('45 days');
	});

	test('the preset writes its four values and the status names it', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await page.locator('#detection summary').click();
		await page.locator('#detection input[name="rip_protection_level"][value="high"]').check();
		await page.locator('#detection form button[type="submit"]').click();
		await page.waitForURL(/#detection/);
		expect(wp('option get reportedip_hive_block_threshold')).toBe('60');
		expect(wp('option get reportedip_hive_failed_login_threshold')).toBe('3');
		await expect(page.locator('#detection .rip-protection__status')).toContainText('Strict');
	});

	test('a tier-locked field is disabled in expert mode', async ({ page }) => {
		wp('user meta update admin reportedip_hive_expert_mode 1');
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await page.locator('#blocking summary').click();
		await expect(page.locator('#blocking input[name="reportedip_hive_block_tor"]')).toBeDisabled();
		await expect(page.locator('#blocking .rip-protection__field--locked')).toHaveCount(1);
	});

	test('search finds Tor, opens the card and marks the label', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await page.fill('#rip-protection-search', 'tor');
		await expect(page.locator('#blocking')).toHaveAttribute('open', '');
		await expect(page.locator('#blocking mark').first()).toContainText(/tor/i);
		await expect(page.locator('#notifications')).toHaveClass(/rip-hidden/);
	});

	test('expert mode lists the tools page and the legacy urls land on their new home', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive');
		await expect(page.locator('#adminmenu a[href*="page=reportedip-hive-tools"]')).toHaveCount(1);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-settings&tab=blocking');
		await page.waitForURL(/page=reportedip-hive-protection#blocking/);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-firewall&tab=server');
		await page.waitForURL(/page=reportedip-hive-tools&tab=server/);
		await expect(page.locator('.rip-nav-tabs__tab--active')).toContainText('Server');
		forgetExpert();
		await page.goto('/wp-admin/admin.php?page=reportedip-hive');
		await expect(page.locator('#adminmenu a[href*="page=reportedip-hive-tools"]')).toHaveCount(0);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-tools&tab=rules');
		await expect(page.locator('.rip-nav-tabs__tab--active')).toContainText('Rules');
	});
});
