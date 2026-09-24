import { execFileSync } from 'node:child_process';
import { test, expect } from '../../fixtures/admin';

/**
 * Hide Login, driven over real HTTP.
 *
 * Every other layer of this feature has unit coverage, but the thing that
 * matters is the answer on the wire: the custom address has to serve the
 * sign-in form, the real one has to stop serving it, and wp-admin must not
 * hand a visitor the real address through the auth redirect. A regression
 * here locks the operator out of their own site, so it is worth the
 * seconds.
 *
 * Serial: the spec switches a site-wide setting on and off.
 *
 * @since 2.1.65
 */

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';
const SLUG = 'rip-e2e-door';

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

/** One batched call: each `docker exec` costs about five seconds here. */
function wpEval(php: string): string {
	return wp('eval', php);
}

/**
 * Switch the feature on with the probe counter off.
 *
 * Knocking at the old address is exactly what this spec does, and with the
 * counter on the fifth knock would block the test runner's address for
 * every spec that follows.
 */
function hideLogin(on: boolean, mode = 'block_page'): void {
	wpEval(
		`ReportedIP_Hive_Option_Routing::set('reportedip_hive_hide_login_slug', '${SLUG}');` +
			`ReportedIP_Hive_Option_Routing::set('reportedip_hive_hide_login_response_mode', '${mode}');` +
			`ReportedIP_Hive_Option_Routing::set('reportedip_hive_monitor_hide_login_probe', 0);` +
			`ReportedIP_Hive_Option_Routing::set('reportedip_hive_hide_login_enabled', ${on ? 1 : 0});` +
			'flush_rewrite_rules(false);'
	);
}

/** Drop anything this spec could have counted against the runner. */
function releaseProbes(): void {
	wpEval(`
		global $wpdb;
		$prefix = $wpdb->base_prefix . 'reportedip_hive_';
		$wpdb->query("DELETE FROM {$prefix}attempts WHERE attempt_type = 'hide_login_probe'");
		$wpdb->query("DELETE FROM {$prefix}blocked WHERE block_type = 'automatic'");
	`);
}

test.describe.configure({ mode: 'serial' });

test.describe('hide login', () => {
	test.afterAll(() => {
		wpTolerant(
			'eval',
			"ReportedIP_Hive_Option_Routing::set('reportedip_hive_hide_login_enabled', 0);" +
				'flush_rewrite_rules(false);'
		);
		wpTolerant(
			'option',
			'delete',
			'reportedip_hive_hide_login_slug',
			'reportedip_hive_hide_login_response_mode',
			'reportedip_hive_monitor_hide_login_probe'
		);
		releaseProbes();
	});

	test('the real login address serves the form while the feature is off', async ({ request }) => {
		hideLogin(false);

		const response = await request.get('/wp-login.php', { failOnStatusCode: false });

		expect(response.status()).toBe(200);
		expect(await response.text()).toContain('id="user_login"');
	});

	test('the custom address serves the form and the real one stops', async ({ request }) => {
		hideLogin(true);

		const hidden = await request.get(`/${SLUG}/`, { failOnStatusCode: false });

		expect(hidden.status(), 'the custom address has to answer').toBe(200);
		expect(await hidden.text(), 'and it has to be the sign-in form').toContain('id="user_login"');

		const real = await request.get('/wp-login.php', { failOnStatusCode: false });
		const body = await real.text();

		expect(real.status(), 'the real address must not answer with the form').not.toBe(200);
		expect(body).not.toContain('id="user_login"');
	});

	test('a signed-out visitor at wp-admin is never handed the real login address', async ({
		request,
	}) => {
		hideLogin(true);

		const response = await request.get('/wp-admin/', {
			failOnStatusCode: false,
			maxRedirects: 0,
		});

		expect(response.status(), 'a guest must not reach wp-admin').not.toBe(200);
		expect(
			response.headers()['location'] ?? '',
			'the auth redirect would otherwise leak the address we just hid'
		).not.toContain('wp-login.php');
	});

	test('the 404 response mode leaves no plugin fingerprint', async ({ request }) => {
		hideLogin(true, '404');

		const response = await request.get('/wp-login.php', { failOnStatusCode: false });

		expect(response.status()).toBe(404);
		expect(await response.text()).not.toContain('id="user_login"');
	});

	test('a real browser can sign in through the custom address', async ({ page }) => {
		hideLogin(true);

		await page.goto(`/${SLUG}/`);
		await page.fill('#user_login', 'admin');
		await page.fill('#user_pass', 'admin');
		await page.click('#wp-submit');

		await page.waitForURL((url) => url.pathname.includes('/wp-admin/'), { timeout: 60_000 });
	});

	test('switching the feature off gives the real address back', async ({ request }) => {
		hideLogin(false);

		const response = await request.get('/wp-login.php', { failOnStatusCode: false });

		expect(response.status()).toBe(200);
		expect(await response.text()).toContain('id="user_login"');
	});
});
