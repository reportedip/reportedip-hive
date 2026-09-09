import { execFileSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * Attack-surface switches (since 2.1.51): XML-RPC, feeds, REST access control,
 * the software fingerprints, the users sitemap, the uploads PHP block and the
 * wp-admin guest block, driven against the running stack because each of them
 * answers before or instead of a normal WordPress response.
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

/**
 * One batched `wp eval` beats several `wp option` calls: every `docker exec`
 * costs about five seconds on the Windows host.
 */
function wpEval(php: string): string {
	return wp('eval', php);
}

const TOUCHED = [
	'reportedip_hive_disable_xmlrpc',
	'reportedip_hive_disable_feeds',
	'reportedip_hive_rest_access_mode',
	'reportedip_hive_rest_allowed_roles',
	'reportedip_hive_block_admin_guests',
	'reportedip_hive_block_uploads_php',
	'reportedip_hive_hide_software_info',
	'reportedip_hive_block_user_enumeration',
	'reportedip_hive_hide_login_response_mode',
];

const UPLOADS_PROBE = 'rip-e2e-uploads-probe.php';

test.describe.configure({ mode: 'serial' });

test.describe('attack surface switches', () => {
	test.beforeAll(() => {
		resetAdminBaseline();
		wpTolerant('option', 'delete', ...TOUCHED);
	});

	test.afterAll(() => {
		wpTolerant('option', 'delete', ...TOUCHED);
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
		expect(response.headers()['content-type'] ?? '').not.toContain('rss+xml');

		wp('option', 'update', 'reportedip_hive_disable_feeds', '0');
		const open = await request.get('/feed/', { failOnStatusCode: false });
		expect(open.status()).toBe(200);
		expect(open.headers()['content-type'] ?? '').toContain('rss+xml');
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

	/**
	 * Restricted mode has three outcomes that must hold at once: a guest is
	 * refused, an administrator with a valid REST nonce is not, and a namespace
	 * from the allowlist answers anonymously. The administrator leg goes
	 * through `wpApiSettings` inside the page because a cookie without a REST
	 * nonce counts as anonymous to WordPress, so a plain cookie request would
	 * prove nothing.
	 */
	test('restricted REST mode refuses guests, keeps admins and the allowlisted namespace', async ({
		page,
		request,
		baseURL,
	}) => {
		wp('option', 'update', 'reportedip_hive_rest_access_mode', 'restricted');

		const guest = await request.get('/wp-json/wp/v2/posts', { failOnStatusCode: false });
		expect(guest.status()).toBe(401);
		expect(((await guest.json()) as { code?: string }).code).toBe('rest_disabled_for_guests');

		const oembed = await request.get(
			`/wp-json/oembed/1.0/embed?url=${encodeURIComponent(`${baseURL ?? ''}/?p=1`)}`,
			{ failOnStatusCode: false }
		);
		expect(oembed.status()).toBe(200);

		await loginAsAdmin(page);
		await page.goto('/wp-admin/');
		const adminStatus: number = await page.evaluate(async () => {
			const settings = (globalThis as { wpApiSettings?: { root: string; nonce: string } })
				.wpApiSettings;
			if (!settings) {
				return 0;
			}
			const res = await fetch(`${settings.root}wp/v2/posts`, {
				headers: { 'X-WP-Nonce': settings.nonce },
			});
			return res.status;
		});
		expect(adminStatus).toBe(200);

		wp('option', 'update', 'reportedip_hive_rest_access_mode', 'open');
	});

	/**
	 * The generator tag belongs to the fingerprint switch; the RSD discovery
	 * link is removed by the XML-RPC switch, which is where the code and the
	 * UI copy both put it. Both halves are asserted so a future move of either
	 * removal is caught.
	 */
	test('hiding software fingerprints strips the generator tag, XML-RPC off strips RSD', async ({
		request,
	}) => {
		const before = await (await request.get('/', { failOnStatusCode: false })).text();
		expect(before).toContain('name="generator"');
		expect(before).toContain('rel="EditURI"');

		wpEval('update_option("reportedip_hive_hide_software_info", 1);');
		const hidden = await (await request.get('/', { failOnStatusCode: false })).text();
		expect(hidden).not.toContain('name="generator"');
		expect(hidden).toContain('rel="EditURI"');

		wpEval('update_option("reportedip_hive_disable_xmlrpc", 1);');
		const closed = await (await request.get('/', { failOnStatusCode: false })).text();
		expect(closed).not.toContain('name="generator"');
		expect(closed).not.toContain('rel="EditURI"');

		wpEval(
			'update_option("reportedip_hive_hide_software_info", 0); update_option("reportedip_hive_disable_xmlrpc", 0);'
		);
	});

	/**
	 * With the users provider dropped the core rewrite no longer resolves and
	 * WordPress falls back to the front page, so the proof is "no urlset",
	 * not a status code.
	 */
	test('the users sitemap is unavailable while user-enumeration defence is on', async ({
		request,
	}) => {
		wp('option', 'update', 'reportedip_hive_block_user_enumeration', '1');

		const index = await (await request.get('/wp-sitemap.xml', { failOnStatusCode: false })).text();
		expect(index).not.toContain('wp-sitemap-users');
		const users = await request.get('/wp-sitemap-users-1.xml', { failOnStatusCode: false });
		expect(await users.text()).not.toContain('<urlset');

		wp('option', 'update', 'reportedip_hive_block_user_enumeration', '0');

		const openIndex = await (
			await request.get('/wp-sitemap.xml', { failOnStatusCode: false })
		).text();
		expect(openIndex).toContain('wp-sitemap-users-1.xml');
		const openUsers = await request.get('/wp-sitemap-users-1.xml', { failOnStatusCode: false });
		expect(openUsers.headers()['content-type'] ?? '').toContain('xml');
		expect(await openUsers.text()).toContain('<urlset');
	});

	/**
	 * The uploads block is a marker pair in the uploads `.htaccess` plus a real
	 * Apache refusal. The leading `update_option( $k, 0 )` seeds the row on
	 * purpose: the writer listens on `update_option_<key>` only, and on an
	 * absent row WordPress takes the `add_option` path instead, which no hook
	 * of the writer covers.
	 */
	test('the uploads htaccess block is written, enforced and removed with the switch', async ({
		request,
	}) => {
		const enableScript = [
			'$k = "reportedip_hive_block_uploads_php";',
			'$w = ReportedIP_Hive_Uploads_Htaccess_Writer::get_instance();',
			'$f = $w->get_target_path();',
			'file_put_contents( dirname( $f ) . "/' + UPLOADS_PROBE + '", chr(60) . "?php echo \'RIP-PROBE-OK\';" );',
			'update_option( $k, 0 );',
			'update_option( $k, 1 );',
			'echo wp_json_encode( array( "path" => $f, "body" => file_exists( $f ) ? file_get_contents( $f ) : "" ) );',
		].join(' ');

		const enabled = JSON.parse(wpEval(enableScript)) as { path: string; body: string };

		expect(enabled.path).toContain('/uploads/.htaccess');
		expect(enabled.body).toContain('# BEGIN ReportedIP Hive Uploads');
		expect(enabled.body).toContain('Require all denied');
		expect(enabled.body).toContain('# END ReportedIP Hive Uploads');

		const refused = await request.get(`/wp-content/uploads/${UPLOADS_PROBE}`, {
			failOnStatusCode: false,
		});
		expect(refused.status()).toBe(403);

		const disableScript = [
			'$k = "reportedip_hive_block_uploads_php";',
			'$w = ReportedIP_Hive_Uploads_Htaccess_Writer::get_instance();',
			'$f = $w->get_target_path();',
			'update_option( $k, 0 );',
			'echo wp_json_encode( array( "body" => file_exists( $f ) ? file_get_contents( $f ) : "" ) );',
		].join(' ');

		const disabled = JSON.parse(wpEval(disableScript)) as { body: string };

		expect(disabled.body).not.toContain('# BEGIN ReportedIP Hive Uploads');
		expect(disabled.body).not.toContain('# END ReportedIP Hive Uploads');
		expect(disabled.body.trim()).toBe('');

		const served = await request.get(`/wp-content/uploads/${UPLOADS_PROBE}`, {
			failOnStatusCode: false,
		});
		expect(served.status()).toBe(200);
		expect(await served.text()).toContain('RIP-PROBE-OK');

		wpEval(
			'$d = wp_get_upload_dir(); @unlink( $d["basedir"] . "/' +
				UPLOADS_PROBE +
				'" ); delete_option( "reportedip_hive_block_uploads_php" ); echo "cleaned";'
		);
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

	/**
	 * The section posts through the Settings API, not through the Firewall
	 * page's AJAX bulk save, so the round trip has to be driven on the real
	 * form: change, submit, read the values back out of the database. The
	 * toggles are `rip-toggle` inputs (opacity 0, zero box), so they are
	 * clicked through their wrapping label.
	 */
	test('the hardening form saves the attack-surface switches', async ({ page }) => {
		test.setTimeout(240_000);

		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-firewall&tab=hardening');

		const form = page.locator('#rip-attack-surface-form');
		await expect(form).toBeVisible();

		await page.selectOption('#rip-rest-access-mode', 'logged_in');
		await form.locator('label.rip-toggle:has(input[name="reportedip_hive_disable_feeds"])').click();
		await form
			.locator('label.rip-toggle:has(input[name="reportedip_hive_hide_software_info"])')
			.click();

		await form.locator('button[type="submit"]').click();
		// The saved notice is the proof the round trip through options.php
		// completed. `waitForURL` is not used: it did not resolve on this stack
		// even after the redirect carrying `settings-updated=true` had been
		// followed and the notice was on screen. The wait gets the test's whole
		// budget rather than a tighter one of its own: this step takes about
		// twelve seconds on an idle machine and timed out at ninety during a
		// full suite run, so a shorter cap only ever reports machine load.
		await expect(page.locator('body')).toContainText('Settings saved.', { timeout: 200_000 });

		// Each toggle ships a hidden `value="0"` companion under the same name,
		// so the checkbox has to be addressed by type.
		await expect(page.locator('#rip-rest-access-mode')).toHaveValue('logged_in');
		await expect(
			page.locator('input[name="reportedip_hive_disable_feeds"][type="checkbox"]')
		).toBeChecked();
		await expect(
			page.locator('input[name="reportedip_hive_hide_software_info"][type="checkbox"]')
		).toBeChecked();

		const saved = wpEval(
			'echo get_option( "reportedip_hive_rest_access_mode" ) . "|" . get_option( "reportedip_hive_disable_feeds" ) . "|" . get_option( "reportedip_hive_hide_software_info" );' +
				'update_option( "reportedip_hive_rest_access_mode", "open" );' +
				'update_option( "reportedip_hive_disable_feeds", 0 );' +
				'update_option( "reportedip_hive_hide_software_info", 0 );'
		);
		expect(saved).toBe('logged_in|1|1');
	});

	test('the hardening tab renders the attack-surface cards', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-firewall&tab=hardening');

		await expect(page.locator('#rip-attack-surface-form')).toBeVisible();
		await expect(page.locator('#rip-rest-access-mode')).toBeVisible();
		await expect(page.locator('#rip-rest-namespaces')).toBeVisible();
		await expect(
			page.locator('input[name="reportedip_hive_disable_xmlrpc"][type="checkbox"]')
		).toBeAttached();
	});
});
