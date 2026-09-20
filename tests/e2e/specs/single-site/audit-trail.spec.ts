import { execFileSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';
import { forceTierPhp, FORCE_FREE_PHP } from '../../fixtures/tier';

/**
 * Audit trail (Business, widened in 2.1.62).
 *
 * On Business the trail records settings, content and installer events with
 * the acting user and the affected object; the tab filters by trigger group
 * and exports what the filter shows. Below Business the same tab shows the
 * plan marker, the support arguments and five sample rows, and the export
 * handler answers 403.
 *
 * Serial: the spec mutates the stack's stored tier, a core option and a
 * plugin's activation state.
 */

const AUDIT_URL = '/wp-admin/admin.php?page=reportedip-hive-security&tab=activity&sub=audit';
const PAGE_TITLE = 'Audit E2E Page';

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';

/**
 * Run WP-CLI inside the stack's WordPress container. Arguments are passed as
 * an array so no shell gets to see braces, quotes or dollar signs.
 */
function wp(...args: string[]): string {
	return execFileSync('docker', ['exec', WP_CONTAINER, 'wp', '--allow-root', ...args], { encoding: 'utf8' })
		.toString()
		.trim();
}

function php(code: string): string {
	return wp('eval', code);
}

test.describe.configure({ mode: 'serial' });

test.describe('Audit trail', () => {
	test.beforeAll(() => {
		resetAdminBaseline();
		php(
			[
				forceTierPhp('business'),
				"ReportedIP_Hive_Option_Routing::set('reportedip_hive_audit_enabled', 1);",
				"ReportedIP_Hive_Option_Routing::delete('reportedip_hive_audit_triggers');",
				'ReportedIP_Hive_Defaults::seed_missing();',
				'global $wpdb; $wpdb->query("TRUNCATE {$wpdb->base_prefix}reportedip_hive_audit_log");',
			].join(' ')
		);
		wp('--user=admin', 'eval', "update_option('permalink_structure', '/%year%/%postname%/');");
		wp(
			'--user=admin',
			'eval',
			`$id = wp_insert_post(array('post_title' => '${PAGE_TITLE}', 'post_type' => 'page', 'post_status' => 'publish')); wp_trash_post($id);`
		);
		wp('plugin', 'deactivate', 'akismet');
	});

	test.afterAll(() => {
		wp('--user=admin', 'eval', "update_option('permalink_structure', '/%postname%/');");
		wp('plugin', 'activate', 'akismet');
		php(FORCE_FREE_PHP);
	});

	test('records settings, content and installer events with actor and object', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto(AUDIT_URL);

		const table = page.locator('table.wp-list-table');
		await expect(table).toBeVisible();

		const permalink = table.locator('tr', { hasText: 'Permalink structure' }).first();
		await expect(permalink).toBeVisible();
		await expect(permalink).toContainText('admin');
		await expect(permalink).toContainText('/%year%/%postname%/');

		const trashed = table.locator('tr', { hasText: PAGE_TITLE }).filter({ hasText: 'Moved to trash' });
		await expect(trashed).toHaveCount(1);

		const plugin = table.locator('tr', { hasText: 'Plugin deactivated' }).first();
		await expect(plugin).toBeVisible();
		await expect(plugin).toContainText('Akismet');
		await expect(plugin).toContainText('CLI');
	});

	test('filters by trigger group and exports the filtered rows', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto(`${AUDIT_URL}&audit_event=group:installer`);

		const table = page.locator('table.wp-list-table');
		await expect(table.locator('tr', { hasText: 'Plugin deactivated' })).toHaveCount(1);
		await expect(table.locator('tr', { hasText: 'Permalink structure' })).toHaveCount(0);

		const csvLink = page.locator('a.rip-button', { hasText: 'Export CSV' });
		const href = await csvLink.getAttribute('href');
		expect(href).toContain('audit_event=group%3Ainstaller');

		const response = await page.request.get(href as string);
		expect(response.status()).toBe(200);
		const body = await response.text();
		expect(body).toContain('object_label');
		expect(body).toContain('Akismet');
		expect(body).not.toContain('Permalink structure');
	});

	test('below Business the tab shows the sample rows and the export answers 403', async ({ page }) => {
		php(FORCE_FREE_PHP);
		await loginAsAdmin(page);
		await page.goto(AUDIT_URL);

		await expect(page.locator('.rip-audit-upsell')).toBeVisible();
		await expect(page.locator('.rip-audit-upsell a.rip-button--primary')).toHaveAttribute('href', /reportedip\.com\/pricing/);
		await expect(page.locator('.rip-audit-sample-note')).toBeVisible();

		const table = page.locator('table.wp-list-table');
		await expect(table.locator('tbody tr')).toHaveCount(5);
		await expect(table).toContainText('Permalink structure');
		await expect(table).not.toContainText(PAGE_TITLE);
		await expect(page.locator('a.rip-button', { hasText: 'Export CSV' })).toHaveCount(0);

		const response = await page.request.get('/wp-admin/admin-post.php?action=reportedip_hive_audit_export&format=csv');
		expect(response.status()).toBe(403);
	});
});
