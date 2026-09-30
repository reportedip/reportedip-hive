import { execFileSync, execSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';
import { FORGET_CACHED_TIER_CLI } from '../../fixtures/tier';

/**
 * Protection page: one card per registry section, simple/expert depth,
 * search, legacy aliases, tools page reachability.
 */
const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';

function wp(args: string): string {
	return execSync(`docker exec ${WP_CONTAINER} wp --allow-root ${args}`, { encoding: 'utf8' }).toString().trim();
}

/**
 * Argument-array variant so a JSON option value survives Windows shell quoting.
 */
function wpArgs(...args: string[]): string {
	return execFileSync('docker', ['exec', WP_CONTAINER, 'wp', '--allow-root', ...args], { encoding: 'utf8' }).toString().trim();
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
	let modeWas = 'local';

	test.beforeAll(() => {
		modeWas = wp('option get reportedip_hive_operation_mode') || 'local';
		/* In Local Shield a Community feature is locked by the mode, not by the plan; the plan rows need Community. */
		wp('option update reportedip_hive_operation_mode community');
		resetAdminBaseline();
		forgetExpert();
		/* The plan assertions need the free plan; forget any cached answer a previous spec left behind. */
		for (const cmd of ['option delete reportedip_hive_known_tier', ...FORGET_CACHED_TIER_CLI]) {
			try {
				wp(cmd);
			} catch {
				/* absent */
			}
		}
		wp('option update reportedip_hive_data_retention_days 30');
		wp('option update reportedip_hive_wizard_completed 1');
	});

	test.afterAll(() => {
		wp(`option update reportedip_hive_operation_mode ${modeWas}`);
		forgetExpert();
	});

	test('five tabs with a status pill each, the first one open', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		const tabs = page.locator('.rip-protection__tabs .rip-nav-tabs__tab');
		await expect(tabs).toHaveCount(5);
		await expect(tabs.first()).toHaveClass(/rip-nav-tabs__tab--active/);
		await expect(page.locator('.rip-protection__panel[data-tab="basics"]')).toBeVisible();
		await expect(page.locator('.rip-protection__panel[data-tab="forms"]')).toBeHidden();
		await expect(page.locator('.rip-protection__tabs .rip-nav-tabs__tab .rip-badge')).toHaveCount(5);
		await expect(page.locator('.rip-status-banner')).toBeVisible();
	});

	test('every key is rendered, the expert keys behind closed details', async ({ page }) => {
		forgetExpert();
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await expect(page.locator('#blocking input[name="reportedip_hive_auto_block"]')).toBeVisible();
		const ladder = page.locator('#blocking input[name="reportedip_hive_block_ladder_minutes"]');
		await expect(ladder).toHaveCount(1);
		await expect(ladder).toBeHidden();
		await expect(page.locator('#blocking .rip-protection__details')).not.toHaveAttribute('open', '');
		await page.locator('#blocking .rip-protection__details > summary').click();
		await expect(ladder).toBeVisible();
	});

	test('expert mode opens the details by default', async ({ page }) => {
		wp('user meta update admin reportedip_hive_expert_mode 1');
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await expect(page.locator('#blocking .rip-protection__details')).toHaveAttribute('open', '');
		await expect(page.locator('#blocking input[name="reportedip_hive_block_ladder_minutes"]')).toBeVisible();
		forgetExpert();
	});

	test('a tab saves through the registry and reports the change', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection&tab=operations');
		await page.locator('#privacy_logs input[name="reportedip_hive_data_retention_days"]').fill('45');
		await page.locator('.rip-protection__panel[data-tab="operations"] button.rip-button--primary').click();
		await page.waitForURL(/tab=operations/);
		await expect(page.locator('.rip-alert--success').filter({ hasText: 'saved' })).toHaveCount(1);
		expect(wp('option get reportedip_hive_data_retention_days')).toBe('45');
		await expect(page.locator('#privacy_logs .rip-protection__status')).toContainText('45 days');
		await expect(page.locator('.rip-protection__panel[data-tab="operations"]')).toBeVisible();
	});

	test('a closed details block still round-trips its values', async ({ page }) => {
		forgetExpert();
		wp('option update reportedip_hive_block_ladder_minutes "5,15,30,1440"');
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await page.locator('.rip-protection__panel[data-tab="basics"] button.rip-button--primary').click();
		await page.waitForURL(/tab=basics/);
		expect(wp('option get reportedip_hive_block_ladder_minutes')).toBe('5,15,30,1440');
	});

	test('the preset writes its four values and the status names it', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await page.locator('#detection input[name="rip_protection_level"][value="high"]').check();
		await page.locator('.rip-protection__panel[data-tab="basics"] button.rip-button--primary').click();
		await page.waitForURL(/tab=basics/);
		expect(wp('option get reportedip_hive_block_threshold')).toBe('60');
		expect(wp('option get reportedip_hive_failed_login_threshold')).toBe('3');
		await expect(page.locator('#detection .rip-protection__status')).toContainText('Strict');
	});

	test('a plan-locked switch shows the plan and a link instead of a control', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		const field = page.locator('#blocking .rip-protection__field[data-key="reportedip_hive_block_tor"]');
		await expect(field).toHaveClass(/rip-protection__field--locked/);
		await expect(field.locator('input')).toHaveCount(0);
		await expect(field.locator('.rip-protection__plan .rip-badge')).toContainText(/professional/i);
		await expect(field.locator('.rip-protection__plan a')).toHaveAttribute('href', /pricing\/#tor_blocking/);
	});

	test('a switched-on plan feature stays editable after a downgrade and a locked value survives a save', async ({ page }) => {
		wp('option update reportedip_hive_block_tor 1');
		wp('option update reportedip_hive_permissions_policy "camera=()"');
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await page.locator('#blocking .rip-protection__details > summary').click();
		await expect(page.locator('#blocking input[name="reportedip_hive_block_tor"]')).toBeEnabled();
		await expect(page.locator('#blocking input[name="reportedip_hive_block_tor"]')).toBeChecked();
		await page.locator('.rip-protection__panel[data-tab="basics"] button.rip-button--primary').click();
		await page.waitForURL(/tab=basics/);
		expect(wp('option get reportedip_hive_block_tor')).toBe('1');

		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection&tab=firewall');
		await page.locator('#headers .rip-protection__details > summary').click();
		await expect(page.locator('#headers input[name="reportedip_hive_permissions_policy"]')).toBeDisabled();
		await page.locator('.rip-protection__panel[data-tab="firewall"] button.rip-button--primary').click();
		await page.waitForURL(/tab=firewall/);
		expect(wp('option get reportedip_hive_permissions_policy')).toBe('camera=()');
		wp('option update reportedip_hive_block_tor 0');
	});

	test('runtime locks and fixed choices render as the old tabs did', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await page.locator('#detection .rip-protection__details > summary').click();
		await expect(page.locator('#detection input[name="reportedip_hive_monitor_woocommerce"]')).toBeDisabled();
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection&tab=firewall');
		await page.locator('#lockdown .rip-protection__details > summary').click();
		const admin = page.locator('#lockdown input[type="checkbox"][name="reportedip_hive_rest_allowed_roles[]"][value="administrator"]');
		await expect(admin).toBeChecked();
		await expect(admin).toBeDisabled();
		await expect(page.locator('#lockdown input[type="hidden"][name="reportedip_hive_rest_allowed_roles[]"][value="administrator"]')).toHaveCount(1);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await page.locator('#account_security .rip-protection__details > summary').click();
		await expect(page.locator('#account_security input[name="reportedip_hive_2fa_allowed_methods[]"][value="sms"]')).toBeDisabled();
	});

	test('a stored role list renders checked and round-trips through save', async ({ page }) => {
		/* Editor, not administrator: an enforced admin without a method is sent to the 2FA onboarding on login. */
		const twoFactorWasOn = wpArgs('option', 'get', 'reportedip_hive_2fa_enabled_global');
		wpArgs('option', 'update', 'reportedip_hive_2fa_enabled_global', '1');
		wpArgs('option', 'update', 'reportedip_hive_2fa_enforce_roles', '["editor"]', '--format=json');
		try {
			await loginAsAdmin(page);
			await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
			const card = page.locator('#account_security');
			await expect(card.locator('.rip-protection__status')).toContainText(/1 role enforced/i);
			const roles = 'input[type="checkbox"][name="reportedip_hive_2fa_enforce_roles[]"]';
			await expect(card.locator(`${roles}[value="editor"]`)).toBeChecked();
			await expect(card.locator(`${roles}[value="author"]`)).not.toBeChecked();
			await card.locator(`${roles}[value="author"]`).check();
			await page.locator('.rip-protection__panel[data-tab="basics"] button.rip-button--primary').click();
			await page.waitForURL(/tab=basics/);
			await expect(card.locator('.rip-protection__status')).toContainText(/2 roles enforced/i);
			await expect(card.locator('.rip-alert--error')).toHaveCount(0);
			await expect(card.locator(`${roles}[value="author"]`)).toBeChecked();
		} finally {
			wpArgs('option', 'update', 'reportedip_hive_2fa_enforce_roles', '[]', '--format=json');
			wpArgs('option', 'update', 'reportedip_hive_2fa_enabled_global', twoFactorWasOn || '0');
		}
	});

	test('search finds Tor across tabs, opens the details and marks the label', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection&tab=operations');
		await page.fill('#rip-protection-search', 'tor');
		await expect(page.locator('.rip-protection__panel[data-tab="basics"]')).toBeVisible();
		await expect(page.locator('#blocking .rip-protection__details')).toHaveAttribute('open', '');
		await expect(page.locator('#blocking mark').first()).toContainText(/tor/i);
		await expect(page.locator('#notifications')).toHaveClass(/rip-hidden/);
		await expect(page.locator('#rip-protection-no-results')).toHaveClass(/rip-hidden/);
		await page.fill('#rip-protection-search', '');
		await expect(page.locator('.rip-protection__panel[data-tab="operations"]')).toBeVisible();
		await expect(page.locator('.rip-protection__panel[data-tab="basics"]')).toBeHidden();
	});

	test('a section link opens its tab', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection#hardening_mode');
		await expect(page.locator('.rip-protection__panel[data-tab="advanced"]')).toBeVisible();
		await expect(page.locator('#hardening_mode')).toBeVisible();
	});

	test('restore defaults writes the recommendation of the tab and leaves the rest alone', async ({ page }) => {
		wp('option update reportedip_hive_headers_enabled 0');
		wp('option update reportedip_hive_waf_enabled 0');
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection&tab=firewall');
		page.once('dialog', (dialog) => dialog.accept());
		await page.locator('.rip-protection__panel[data-tab="firewall"] .rip-protection__reset').click();
		await page.waitForURL(/tab=firewall/);
		await expect(page.locator('.rip-alert--success').filter({ hasText: 'recommendation' })).toHaveCount(1);
		expect(wp('option get reportedip_hive_headers_enabled')).toBe('1');
		expect(wp('option get reportedip_hive_waf_enabled')).toBe('0');
		wp('option update reportedip_hive_waf_enabled 1');
	});

	test('check protection runs the readiness check and reports the counts', async ({ page }) => {
		wp('option update reportedip_hive_wizard_completed 1');
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection&tab=operations');
		await page.locator('form.rip-protection__check button[type="submit"]').click();
		await page.waitForURL(/tab=operations/);
		await expect(page.locator('.rip-alert').filter({ hasText: 'Check done' })).toContainText(/\d+ issues need attention/);
		await expect(page.locator('.rip-alert a[href*="#rip-next-steps"]')).toHaveCount(1);
	});

	test('the uninstall switch lives on the tools page and round-trips', async ({ page }) => {
		wp('option update reportedip_hive_delete_data_on_uninstall 0');
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-tools&tab=data');
		await page.locator('label.rip-toggle:has(input[type="checkbox"][name="reportedip_hive_delete_data_on_uninstall"])').click();
		await page.locator('form:has(input[name="reportedip_hive_delete_data_on_uninstall"]) input[type="submit"]').click();
		await expect.poll(() => wp('option get reportedip_hive_delete_data_on_uninstall'), { timeout: 30_000 }).toBe('1');
		wp('option update reportedip_hive_delete_data_on_uninstall 0');
	});

	test('expert mode lists the tools page and the legacy urls land on their new home', async ({ page }) => {
		wp('user meta update admin reportedip_hive_expert_mode 1');
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive');
		await expect(page.locator('#adminmenu a[href*="page=reportedip-hive-tools"]')).toHaveCount(1);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-settings&tab=blocking');
		await page.waitForURL(/page=reportedip-hive-protection.*#blocking/);
		await expect(page.locator('#blocking')).toBeVisible();
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
