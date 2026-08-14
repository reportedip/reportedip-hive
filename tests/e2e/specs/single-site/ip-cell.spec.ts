import { execFileSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * The shared IP-cell renderer (since 2.1.41) gives every admin list table the
 * same copy / lookup / external-link action cluster. The spec seeds a manual
 * block through the real plugin API and asserts the Blocked list renders the
 * cell contract: <code> IP, a `.copy-ip` button, and a hardened external link
 * to the public reportedip.com detail page. The second test pins the lookup
 * results container's screen-reader contract (role=status + aria-live).
 *
 * Serial: the specs share one seeded block row on the long-lived stack.
 */

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';
const TEST_IP = '203.0.113.99';

/**
 * Run a WP-CLI command inside the single-site WordPress container.
 */
function wp(...args: string[]): string {
	return execFileSync('docker', ['exec', WP_CONTAINER, 'wp', '--allow-root', ...args], {
		encoding: 'utf8',
	})
		.toString()
		.trim();
}

test.describe.configure({ mode: 'serial' });

test.describe('IP cell + lookup accessibility', () => {
	test.beforeAll(() => {
		resetAdminBaseline();
		wp(
			'eval',
			`ReportedIP_Hive_IP_Manager::get_instance()->block_ip("${TEST_IP}", "e2e test", 24, "manual");`
		);
	});

	test.afterAll(() => {
		try {
			wp('eval', `ReportedIP_Hive_IP_Manager::get_instance()->unblock_ip("${TEST_IP}");`);
		} catch {
			/* best effort */
		}
	});

	test('blocked-IP row renders the shared IP cell with copy + external link', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto(`/wp-admin/admin.php?page=reportedip-hive-security&tab=blocked&s=${TEST_IP}`);

		const cell = page.locator('.rip-ip-cell', { hasText: TEST_IP }).first();
		await expect(cell).toBeVisible();
		await expect(cell.locator('code.ip-address')).toHaveText(TEST_IP);
		await expect(cell.locator('button.copy-ip')).toHaveCount(1);

		const external = cell.locator(`a[href*="reportedip.com/ip/${TEST_IP}"]`);
		await expect(external).toHaveCount(1);
		await expect(external).toHaveAttribute('target', '_blank');
		await expect(external).toHaveAttribute('rel', /noopener/);
	});

	test('lookup results container is a polite aria-live status region', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-security&tab=lookup');

		const results = page.locator('#lookup-results-content');
		await expect(results).toHaveCount(1);
		await expect(results).toHaveAttribute('role', 'status');
		await expect(results).toHaveAttribute('aria-live', 'polite');
	});
});
