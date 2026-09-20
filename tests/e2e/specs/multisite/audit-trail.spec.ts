import { execFileSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';
import { forceTierPhp, FORCE_FREE_PHP } from '../../fixtures/tier';

/**
 * Audit trail on a network (Business, 2.1.62).
 *
 * A network-wide plugin deactivation is a network row (`blog_id = 0`) and
 * shows the Network badge in the Site column of the network admin; a change
 * on a sub-site names that site. The Network trigger group is offered on
 * the Protection page only here.
 *
 * Serial: the spec mutates the network's stored tier and a plugin's state.
 */

const MS_COMPOSE = 'docker-compose.multisite.yml';
const MS_SERVICE = 'wordpress-ms';
const AUDIT_URL = '/wp-admin/network/admin.php?page=reportedip-hive-security&tab=activity&sub=audit';

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER_MS ?? 'rip-hive-ms-wp';

/**
 * Run WP-CLI inside the stack's WordPress container. Arguments are passed as
 * an array so no shell gets to see braces, quotes or dollar signs.
 */
function wp(...args: string[]): string {
	return execFileSync('docker', ['exec', WP_CONTAINER, 'wp', '--allow-root', ...args], { encoding: 'utf8' })
		.toString()
		.trim();
}

function wpTolerant(...args: string[]): string {
	try {
		return wp(...args);
	} catch {
		return '';
	}
}

function php(code: string): string {
	return wp('eval', code);
}

test.describe.configure({ mode: 'serial' });

test.describe('Audit trail on multisite', () => {
	test.beforeAll(() => {
		resetAdminBaseline(MS_COMPOSE, MS_SERVICE);
		php(
			[
				forceTierPhp('business'),
				"ReportedIP_Hive_Option_Routing::set('reportedip_hive_audit_enabled', 1);",
				"ReportedIP_Hive_Option_Routing::delete('reportedip_hive_audit_triggers');",
				'ReportedIP_Hive_Defaults::seed_missing();',
				'global $wpdb; $wpdb->query("TRUNCATE {$wpdb->base_prefix}reportedip_hive_audit_log");',
			].join(' ')
		);
		wpTolerant('plugin', 'activate', 'akismet', '--network');
		wp('plugin', 'deactivate', 'akismet', '--network');
		wp('--url=localhost:9090/site-a/', '--user=admin', 'eval', "update_option('blogname', 'Site A audit');");
	});

	test.afterAll(() => {
		wpTolerant('plugin', 'deactivate', 'akismet', '--network');
		wp('--url=localhost:9090/site-a/', '--user=admin', 'eval', "update_option('blogname', 'Site A');");
		php(FORCE_FREE_PHP);
	});

	test('network admin sees network rows and site rows with their site', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto(AUDIT_URL);

		const table = page.locator('table.wp-list-table');
		await expect(table.locator('thead')).toContainText('Site');

		const plugin = table.locator('tr', { hasText: 'Plugin deactivated' }).first();
		await expect(plugin).toBeVisible();
		await expect(plugin.locator('.rip-badge', { hasText: 'Network' })).toHaveCount(1);

		const title = table.locator('tr', { hasText: 'Site title' }).first();
		await expect(title).toBeVisible();
		await expect(title).toContainText('Site A audit');
		await expect(title.locator('.rip-badge', { hasText: 'Network' })).toHaveCount(0);
	});

	test('the Network trigger group is offered on the Protection page', async ({ page }) => {
		wp('user', 'meta', 'update', 'admin', 'reportedip_hive_expert_mode', '1');
		try {
			await loginAsAdmin(page);
			await page.goto('/wp-admin/network/admin.php?page=reportedip-hive-protection');
			await expect(page.locator('input[name="reportedip_hive_audit_triggers[]"][value="multisite"]')).toHaveCount(1);
		} finally {
			wpTolerant('user', 'meta', 'delete', 'admin', 'reportedip_hive_expert_mode');
		}
	});
});
