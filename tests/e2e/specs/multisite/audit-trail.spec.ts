import { execFileSync } from 'node:child_process';
import type { Page } from '@playwright/test';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';
import { forceTierPhp, FORCE_FREE_PHP } from '../../fixtures/tier';

/**
 * Audit trail on a network (Business, 2.1.62).
 *
 * A network-wide plugin deactivation is a network row (`blog_id = 0`) and
 * shows the Network badge in the Site column of the network admin; a change
 * on a sub-site names that site. The network admin narrows the list to one
 * site or to the network rows. A site administrator has an Audit Trail page
 * under the site menu that shows that site's rows and nothing else; the
 * proof runs on the main site because the stack's subdirectory rewrite does
 * not serve a sub-site's wp-admin to a browser. The Network trigger group
 * is offered on the Protection page only here.
 *
 * Serial: the spec mutates the network's stored tier, a plugin's state and
 * one throwaway site administrator.
 */

const MS_COMPOSE = 'docker-compose.multisite.yml';
const MS_SERVICE = 'wordpress-ms';
const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER_MS ?? 'rip-hive-ms-wp';
const AUDIT_URL = '/wp-admin/network/admin.php?page=reportedip-hive-security&tab=activity&sub=audit';
const SITE_A = 'localhost:9090/site-a/';
const SITE_A_TITLE = 'Site A audit';
const SITE_ADMIN = 'ripe2esiteaudit';
const SITE_ADMIN_PASS = 'RipE2eSiteAudit-2162';
const MAIN_TITLE = 'Main site audit';

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

async function loginAs(page: Page, login: string, pass: string, loginPath: string): Promise<void> {
	await page.goto(loginPath);
	await page.fill('#user_login', login);
	await page.fill('#user_pass', pass);
	await page.click('#wp-submit');
	await page.waitForURL((url) => url.pathname.includes('/wp-admin/'));
}

test.describe.configure({ mode: 'serial' });

test.describe('Audit trail on multisite', () => {
	let modeBefore = 'local';

	test.beforeAll(() => {
		resetAdminBaseline(MS_COMPOSE, MS_SERVICE);
		/* Local Shield for the run: in Community mode the API mock answers the next status refresh with Professional and the trail closes mid-spec. */
		modeBefore = php("echo ReportedIP_Hive_Option_Routing::get('reportedip_hive_operation_mode', 'local');") || 'local';
		php(
			[
				"ReportedIP_Hive_Option_Routing::set('reportedip_hive_operation_mode', 'local');",
				forceTierPhp('business'),
				"ReportedIP_Hive_Option_Routing::set('reportedip_hive_audit_enabled', 1);",
				"ReportedIP_Hive_Option_Routing::delete('reportedip_hive_audit_triggers');",
				'ReportedIP_Hive_Defaults::seed_missing();',
				'global $wpdb; $wpdb->query("DELETE FROM {$wpdb->base_prefix}reportedip_hive_audit_log");',
			].join(' ')
		);
		wpTolerant('user', 'delete', SITE_ADMIN, '--network', '--yes');
		wp('user', 'create', SITE_ADMIN, `${SITE_ADMIN}@example.org`, '--role=administrator', `--user_pass=${SITE_ADMIN_PASS}`);
		wpTolerant('plugin', 'activate', 'akismet', '--network');
		wp('plugin', 'deactivate', 'akismet', '--network');
		wp(`--url=${SITE_A}`, '--user=admin', 'eval', `update_option('blogname', '${SITE_A_TITLE}');`);
		wp('--url=localhost:9090/site-b/', '--user=admin', 'eval', "update_option('blogname', 'Site B audit');");
		wp('--user=admin', 'eval', `update_option('blogname', '${MAIN_TITLE}');`);
	});

	test.afterAll(() => {
		wpTolerant('plugin', 'deactivate', 'akismet', '--network');
		wp(`--url=${SITE_A}`, '--user=admin', 'eval', "update_option('blogname', 'Site A');");
		wp('--url=localhost:9090/site-b/', '--user=admin', 'eval', "update_option('blogname', 'Site B');");
		wp('--user=admin', 'eval', "update_option('blogname', 'ReportedIP Hive Test Network');");
		wpTolerant('user', 'delete', SITE_ADMIN, '--network', '--yes');
		php(FORCE_FREE_PHP);
		php(`ReportedIP_Hive_Option_Routing::set('reportedip_hive_operation_mode', '${modeBefore}');`);
	});

	test('network admin sees network rows and site rows with their site', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto(AUDIT_URL);

		const table = page.locator('table.wp-list-table');
		await expect(table.locator('thead')).toContainText('Site');

		const plugin = table.locator('tr', { hasText: 'Plugin deactivated' }).first();
		await expect(plugin).toBeVisible();
		await expect(plugin.locator('.rip-badge', { hasText: 'Network' })).toHaveCount(1);

		const title = table.locator('tr', { hasText: SITE_A_TITLE }).first();
		await expect(title).toBeVisible();
		await expect(title).toContainText('Site title');
		await expect(title.locator('.rip-badge', { hasText: 'Network' })).toHaveCount(0);
	});

	test('the site filter narrows the network view to one site or to the network rows', async ({ page }) => {
		await loginAsAdmin(page);

		/* The Site column carries the blog name, so a site's rows are told apart by their event, not by the title text. */
		await page.goto(`${AUDIT_URL}&audit_site=network`);
		let table = page.locator('table.wp-list-table');
		await expect(table.locator('tr', { hasText: 'Plugin deactivated' })).toHaveCount(1);
		await expect(table.locator('tr', { hasText: 'Site title' })).toHaveCount(0);

		const siteId = wp(`--url=${SITE_A}`, 'eval', 'echo get_current_blog_id();');
		await page.goto(`${AUDIT_URL}&audit_site=${siteId}`);
		table = page.locator('table.wp-list-table');
		const titleRows = table.locator('tr', { hasText: 'Site title' });
		await expect(titleRows).toHaveCount(1);
		await expect(titleRows.first()).toContainText(SITE_A_TITLE);
		await expect(table.locator('tr', { hasText: 'Site B audit' })).toHaveCount(0);
		await expect(table.locator('tr', { hasText: 'Plugin deactivated' })).toHaveCount(0);
		await expect(page.locator('#rip-audit-site')).toHaveValue(siteId);
	});

	test('a site administrator sees the rows of that site only', async ({ page }) => {
		await loginAs(page, SITE_ADMIN, SITE_ADMIN_PASS, '/wp-login.php');
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-site-audit');

		await expect(page.locator('.rip-header__title')).toHaveText('Audit Trail');
		const table = page.locator('table.wp-list-table');
		await expect(table).toBeVisible();
		await expect(table.locator('thead')).not.toContainText('Site');
		await expect(page.locator('#rip-audit-site')).toHaveCount(0);

		const titleRows = table.locator('tr', { hasText: 'Site title' });
		await expect(titleRows).toHaveCount(1);
		await expect(titleRows.first()).toContainText(MAIN_TITLE);
		await expect(table.locator('tr', { hasText: SITE_A_TITLE })).toHaveCount(0);
		await expect(table.locator('tr', { hasText: 'Site B audit' })).toHaveCount(0);
		await expect(table.locator('tr', { hasText: 'Plugin deactivated' })).toHaveCount(0);

		const csv = page.locator('a.rip-button', { hasText: 'Export CSV' });
		const href = await csv.getAttribute('href');
		expect(href).toContain('/wp-admin/admin-post.php');
		expect(href).not.toContain('/wp-admin/network/');
		const response = await page.request.get(href as string);
		expect(response.status()).toBe(200);
		const body = await response.text();
		expect(body).toContain(MAIN_TITLE);
		expect(body).not.toContain(SITE_A_TITLE);
		expect(body).not.toContain('Akismet');
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
