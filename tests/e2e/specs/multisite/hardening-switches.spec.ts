import { execSync, execFileSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * The attack-surface switches are network state: one network option closes
 * xmlrpc.php and the feeds on every sub-site, and the settings section lives
 * on the Network Admin firewall page.
 *
 * Serial: the spec mutates shared network state on the long-lived stack.
 */

const MS_COMPOSE = 'docker-compose.multisite.yml';
const MS_SERVICE = 'wordpress-ms';

function resolveWorkspaceRoot(): string {
	return new URL('../../../../../', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
}

function wp(args: string): string {
	return execSync(
		`docker compose -f ${MS_COMPOSE} exec -T ${MS_SERVICE} wp --allow-root ${args}`,
		{ cwd: resolveWorkspaceRoot(), encoding: 'utf8' }
	)
		.toString()
		.trim();
}

/**
 * PHP goes through `execFileSync` rather than the string helper above: a
 * shell-quoted snippet would be parsed by cmd.exe on the Windows host, and
 * one `docker compose exec` costs about five seconds, so the whole check has
 * to fit into a single call.
 */
function wpEval(php: string): string {
	return execFileSync(
		'docker',
		['compose', '-f', MS_COMPOSE, 'exec', '-T', MS_SERVICE, 'wp', '--allow-root', 'eval', php],
		{ cwd: resolveWorkspaceRoot(), encoding: 'utf8' }
	)
		.toString()
		.trim();
}

/**
 * Drop both sitemeta rows this spec writes, in one call.
 */
function resetNetworkOptions(): void {
	try {
		wpEval(
			'delete_site_option( "reportedip_hive_disable_xmlrpc" ); delete_site_option( "reportedip_hive_disable_feeds" ); echo "reset";'
		);
	} catch {
		/* nothing stored */
	}
}

test.describe.configure({ mode: 'serial' });

test.describe('attack surface switches on a network', () => {
	test.beforeAll(() => {
		resetAdminBaseline(MS_COMPOSE, MS_SERVICE);
		resetNetworkOptions();
	});

	test.afterAll(() => {
		resetNetworkOptions();
	});

	/**
	 * One sitemeta value closes the network's single xmlrpc.php endpoint,
	 * which serves every sub-site. The prefixed `/site-a/xmlrpc.php` form is
	 * deliberately not asserted: in this subdir stack the prefix-stripping
	 * rewrite is absent, so that path answers 404 either way and the check
	 * would prove nothing.
	 */
	test('one network option closes xmlrpc.php for the whole network', async ({ request }) => {
		wp('network meta update 1 reportedip_hive_disable_xmlrpc 1');

		const denied = await request.post('/xmlrpc.php', { failOnStatusCode: false });
		expect([403, 404]).toContain(denied.status());

		const subsite = await request.get('/site-a/', { failOnStatusCode: false });
		expect(subsite.status()).toBe(200);

		wp('network meta update 1 reportedip_hive_disable_xmlrpc 0');
		const open = await request.post('/xmlrpc.php', { failOnStatusCode: false });
		expect(open.status()).toBe(200);
	});

	/**
	 * Storage location and effect in one test: the value lives in sitemeta,
	 * the sub-site has no row of its own, the router still reads it there, and
	 * the sub-site feed answers as closed while it is on. The feed switch is
	 * used because it is the one endpoint a sub-site really serves under its
	 * own path prefix.
	 */
	test('the switches are network options and close a sub-site endpoint', async ({ request }) => {
		const state = JSON.parse(
			wpEval(
				[
					'update_site_option( "reportedip_hive_disable_feeds", 1 );',
					'$s = get_sites( array( "path" => "/site-a/", "number" => 1 ) );',
					'$id = $s ? (int) $s[0]->blog_id : 0;',
					'switch_to_blog( $id );',
					'$site = get_option( "reportedip_hive_disable_feeds", "ABSENT" );',
					'$eff = ReportedIP_Hive_Option_Routing::get( "reportedip_hive_disable_feeds", "ABSENT" );',
					'restore_current_blog();',
					'echo wp_json_encode( array( "blog" => $id, "site" => $site, "eff" => $eff ) );',
				].join(' ')
			)
		) as { blog: number; site: string; eff: string };

		expect(state.blog).toBeGreaterThan(1);
		expect(state.site).toBe('ABSENT');
		expect(String(state.eff)).toBe('1');

		const subFeed = await request.get('/site-a/feed/', { failOnStatusCode: false });
		expect(subFeed.status()).toBe(404);
		expect(subFeed.headers()['content-type'] ?? '').toContain('text/html');

		const mainFeed = await request.get('/feed/', { failOnStatusCode: false });
		expect(mainFeed.status()).toBe(404);

		const subsite = await request.get('/site-a/', { failOnStatusCode: false });
		expect(subsite.status()).toBe(200);

		wpEval('delete_site_option( "reportedip_hive_disable_feeds" ); echo "off";');

		const restored = await request.get('/site-a/feed/', { failOnStatusCode: false });
		expect(restored.status()).toBe(200);
		expect(restored.headers()['content-type'] ?? '').toContain('rss+xml');
	});

	test('network admin sees the attack-surface section', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/network/admin.php?page=reportedip-hive-firewall&tab=hardening');

		await expect(page.locator('#rip-attack-surface-form')).toBeVisible();
		await expect(page.locator('#rip-rest-access-mode')).toBeVisible();
	});
});
