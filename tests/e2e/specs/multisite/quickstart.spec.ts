import { execSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * Quickstart on a network: renders for the super admin in the network
 * admin, is refused on a site admin, and writes network-wide options.
 *
 * The site-admin check opens the main site's own wp-admin rather than
 * `/site-a/wp-admin/`: the dev stack's subdir rewrite bounces sub-site
 * admin URLs, and both are the same code path (no menu entry outside the
 * network admin, so core answers with its 403 page).
 */

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER_MS ?? 'rip-hive-ms-wp';

function wp(args: string): string {
	return execSync(`docker exec ${WP_CONTAINER} wp --allow-root ${args}`, { encoding: 'utf8' }).toString().trim();
}

function siteOption(name: string): string {
	try {
		return wp(`site option get ${name}`);
	} catch {
		return '';
	}
}

function resetQuickstart(): void {
	for (const key of ['reportedip_hive_wizard_completed', 'reportedip_hive_headers_enabled', 'reportedip_hive_operation_mode']) {
		try {
			wp(`site option delete ${key}`);
		} catch {
			/* already absent */
		}
	}
	try {
		wp('site option update reportedip_hive_2fa_enabled_global 0');
		wp('transient delete reportedip_2fa_onboarding_pending_1');
	} catch {
		/* best effort */
	}
}

test.describe.configure({ mode: 'serial' });

test.describe('quickstart (multisite)', () => {
	test.beforeEach(() => {
		resetAdminBaseline('docker-compose.multisite.yml', 'wordpress-ms');
		resetQuickstart();
	});

	test.afterAll(() => {
		resetAdminBaseline('docker-compose.multisite.yml', 'wordpress-ms');
		resetQuickstart();
	});

	test('network admin can activate Local Shield', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/network/admin.php?page=reportedip-hive-quickstart');
		await page.locator('.rip-mode-card[data-mode="local"]').click();
		await page.locator('label.rip-toggle:has(#rip-quickstart-2fa)').click();
		await page.locator('#rip-quickstart-activate').click();
		await page.waitForURL(/wp-admin\/network\/admin\.php\?page=reportedip-hive(&|$)/);

		expect(siteOption('reportedip_hive_wizard_completed')).toBe('1');
		expect(siteOption('reportedip_hive_headers_enabled')).toBe('1');
		expect(siteOption('reportedip_hive_operation_mode')).toBe('local');
	});

	test('a site admin never renders the quickstart', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-quickstart');
		await expect(page.locator('#rip-quickstart-activate')).toHaveCount(0);
		await expect(page.locator('body')).not.toHaveClass(/rip-quickstart-page/);
	});
});
