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
	test.beforeAll(() => {
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

	test('a switched-on plan feature stays editable after a downgrade and a locked value survives a save', async ({ page }) => {
		wp('user meta update admin reportedip_hive_expert_mode 1');
		wp('option update reportedip_hive_block_tor 1');
		wp('option update reportedip_hive_permissions_policy "camera=()"');
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await page.locator('#blocking summary').click();
		await expect(page.locator('#blocking input[name="reportedip_hive_block_tor"]')).toBeEnabled();
		await expect(page.locator('#blocking input[name="reportedip_hive_block_tor"]')).toBeChecked();
		await page.locator('#blocking form button[type="submit"]').click();
		await page.waitForURL(/#blocking/);
		expect(wp('option get reportedip_hive_block_tor')).toBe('1');

		await page.locator('#headers').evaluate((el) => {
			(el as HTMLDetailsElement).open = true;
		});
		await expect(page.locator('#headers input[name="reportedip_hive_permissions_policy"]')).toBeDisabled();
		await page.locator('#headers form button[type="submit"]').click();
		await page.waitForURL(/#headers/);
		expect(wp('option get reportedip_hive_permissions_policy')).toBe('camera=()');
		wp('option update reportedip_hive_block_tor 0');
		wp('option delete reportedip_hive_permissions_policy');
	});

	test('runtime locks and fixed choices render as the old tabs did', async ({ page }) => {
		wp('user meta update admin reportedip_hive_expert_mode 1');
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await page.locator('#detection').evaluate((el) => {
			(el as HTMLDetailsElement).open = true;
		});
		await expect(page.locator('#detection input[name="reportedip_hive_monitor_woocommerce"]')).toBeDisabled();
		await page.locator('#lockdown').evaluate((el) => {
			(el as HTMLDetailsElement).open = true;
		});
		const admin = page.locator('#lockdown input[type="checkbox"][name="reportedip_hive_rest_allowed_roles[]"][value="administrator"]');
		await expect(admin).toBeChecked();
		await expect(admin).toBeDisabled();
		await expect(page.locator('#lockdown input[type="hidden"][name="reportedip_hive_rest_allowed_roles[]"][value="administrator"]')).toHaveCount(1);
		await page.locator('#account_security').evaluate((el) => {
			(el as HTMLDetailsElement).open = true;
		});
		await expect(page.locator('#account_security input[name="reportedip_hive_2fa_allowed_methods[]"][value="sms"]')).toBeDisabled();
	});

	test('a stored role list renders checked and round-trips through save', async ({ page }) => {
		/* Editor, not administrator: an enforced admin without a method is sent to the 2FA onboarding on login. */
		const twoFactorWasOn = wpArgs('option', 'get', 'reportedip_hive_2fa_enabled_global');
		wpArgs('option', 'update', 'reportedip_hive_2fa_enabled_global', '1');
		wpArgs('option', 'update', 'reportedip_hive_2fa_enforce_roles', '["editor"]');
		try {
			await loginAsAdmin(page);
			await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
			const card = page.locator('#account_security');
			await expect(card.locator('.rip-protection__status')).toContainText(/1 role enforced/i);
			await card.evaluate((el) => {
				(el as HTMLDetailsElement).open = true;
			});
			const roles = 'input[type="checkbox"][name="reportedip_hive_2fa_enforce_roles[]"]';
			await expect(card.locator(`${roles}[value="editor"]`)).toBeChecked();
			await expect(card.locator(`${roles}[value="author"]`)).not.toBeChecked();

			await card.locator(`${roles}[value="author"]`).check();
			await card.locator('form button[type="submit"]').click();
			await expect.poll(() => wpArgs('option', 'get', 'reportedip_hive_2fa_enforce_roles'), { timeout: 30_000 }).toBe('["editor","author"]');
			await page.waitForURL(/#account_security/);
			await expect(card.locator('.rip-protection__status')).toContainText(/2 roles enforced/i);
			await expect(card.locator('.rip-alert--error')).toHaveCount(0);
			await expect(card.locator(`${roles}[value="author"]`)).toBeChecked();
		} finally {
			wpArgs('option', 'update', 'reportedip_hive_2fa_enforce_roles', '[]');
			wpArgs('option', 'update', 'reportedip_hive_2fa_enabled_global', twoFactorWasOn || '0');
		}
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

	test('search finds Tor, opens the card and marks the label', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await page.fill('#rip-protection-search', 'tor');
		await expect(page.locator('#blocking')).toHaveAttribute('open', '');
		await expect(page.locator('#blocking mark').first()).toContainText(/tor/i);
		await expect(page.locator('#notifications')).toHaveClass(/rip-hidden/);
	});

	test('simple mode finds an expert setting through the search and offers the way in', async ({ page }) => {
		forgetExpert();
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		const field = page.locator('#blocking input[name="reportedip_hive_block_tor"]');
		await expect(field).toHaveCount(0);

		const hint = page.locator('#blocking .rip-protection__hint[data-key="reportedip_hive_block_tor"]');
		await expect(hint).toBeHidden();
		await page.fill('#rip-protection-search', 'tor');
		await expect(page.locator('#rip-protection-no-results')).toHaveClass(/rip-hidden/);
		await expect(hint).toBeVisible();
		/* Nothing in the stand-in may reach the save of that section. */
		await expect(hint.locator('input, select, textarea')).toHaveCount(0);

		await hint.locator('a.rip-button').click();
		await page.waitForURL(/page=reportedip-hive-protection#rip-field-block_tor/);
		await expect(field).toHaveCount(1);
		await expect(page.locator('#blocking')).toHaveAttribute('open', '');
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
