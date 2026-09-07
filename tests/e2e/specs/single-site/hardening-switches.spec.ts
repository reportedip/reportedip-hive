import { execFileSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * Attack-surface switches (since 2.1.51): XML-RPC, feeds, REST access control
 * and the wp-admin guest block, driven against the running stack because each
 * of them answers before or instead of a normal WordPress response.
 *
 * Serial: the spec mutates shared plugin state on the long-lived stack.
 */

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';

function wp(...args: string[]): string {
	return execFileSync('docker', ['exec', WP_CONTAINER, 'wp', '--allow-root', ...args], {
		encoding: 'utf8',
	})
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

const TOUCHED = [
	'reportedip_hive_disable_xmlrpc',
	'reportedip_hive_disable_feeds',
	'reportedip_hive_rest_access_mode',
	'reportedip_hive_block_admin_guests',
	'reportedip_hive_hide_login_response_mode',
];

test.describe.configure({ mode: 'serial' });

test.describe('attack surface switches', () => {
	test.beforeAll(() => {
		resetAdminBaseline();
		for (const key of TOUCHED) {
			wpTolerant('option', 'delete', key);
		}
	});

	test.afterAll(() => {
		for (const key of TOUCHED) {
			wpTolerant('option', 'delete', key);
		}
	});

	test('xmlrpc.php is refused with the configured response', async ({ request }) => {
		wp('option', 'update', 'reportedip_hive_disable_xmlrpc', '1');
		wp('option', 'update', 'reportedip_hive_hide_login_response_mode', 'block_page');

		const blocked = await request.get('/xmlrpc.php', { failOnStatusCode: false });
		expect(blocked.status()).toBe(403);

		wp('option', 'update', 'reportedip_hive_hide_login_response_mode', '404');
		const softer = await request.get('/xmlrpc.php', { failOnStatusCode: false });
		expect(softer.status()).toBe(404);

		wp('option', 'update', 'reportedip_hive_disable_xmlrpc', '0');
		const open = await request.post('/xmlrpc.php', { failOnStatusCode: false });
		expect(open.status()).toBe(200);
	});

	test('feeds answer 404 as HTML, not as a malformed feed', async ({ request }) => {
		wp('option', 'update', 'reportedip_hive_disable_feeds', '1');

		const response = await request.get('/feed/', { failOnStatusCode: false });
		expect(response.status()).toBe(404);
		expect(response.headers()['content-type'] ?? '').toContain('text/html');

		wp('option', 'update', 'reportedip_hive_disable_feeds', '0');
		const open = await request.get('/feed/', { failOnStatusCode: false });
		expect(open.status()).toBe(200);
	});

	test('anonymous REST calls are refused while the plugin namespace stays open', async ({ request }) => {
		wp('option', 'update', 'reportedip_hive_rest_access_mode', 'logged_in');

		const posts = await request.get('/wp-json/wp/v2/posts', { failOnStatusCode: false });
		expect(posts.status()).toBe(401);
		expect(((await posts.json()) as { code?: string }).code).toBe('rest_disabled_for_guests');

		const plugin = await request.get('/wp-json/reportedip-hive/v1/2fa/methods', {
			failOnStatusCode: false,
		});
		const pluginBody = (await plugin.json()) as { code?: string };
		expect(pluginBody.code).not.toBe('rest_disabled_for_guests');

		wp('option', 'update', 'reportedip_hive_rest_access_mode', 'open');
	});

	test('the block editor still renders for an administrator in restricted mode', async ({ page }) => {
		wp('option', 'update', 'reportedip_hive_rest_access_mode', 'restricted');

		await loginAsAdmin(page);
		await page.goto('/wp-admin/post-new.php');
		await expect(page.locator('#editor')).toBeVisible({ timeout: 30_000 });

		wp('option', 'update', 'reportedip_hive_rest_access_mode', 'open');
	});

	test('wp-admin is closed for visitors without Hide Login', async ({ request }) => {
		expect(wpTolerant('option', 'get', 'reportedip_hive_hide_login_enabled')).not.toBe('1');
		wp('option', 'update', 'reportedip_hive_block_admin_guests', '1');
		wp('option', 'update', 'reportedip_hive_hide_login_response_mode', 'block_page');

		const denied = await request.get('/wp-admin/', { failOnStatusCode: false });
		expect(denied.status()).toBe(403);

		wp('option', 'update', 'reportedip_hive_block_admin_guests', '0');
		const redirected = await request.get('/wp-admin/', { failOnStatusCode: false });
		expect(redirected.status()).not.toBe(403);
	});

	test('the hardening tab renders the attack-surface cards', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-firewall&tab=hardening');

		await expect(page.locator('#rip-attack-surface-form')).toBeVisible();
		await expect(page.locator('#rip-rest-access-mode')).toBeVisible();
		await expect(page.locator('#rip-rest-namespaces')).toBeVisible();
		await expect(
			page.locator('input[name="reportedip_hive_disable_xmlrpc"][type="checkbox"]')
		).toBeVisible();
	});
});
