import { execFileSync } from 'node:child_process';
import { test, expect } from '../../fixtures/admin';

/**
 * The brute-force ladder, driven through the real sign-in form.
 *
 * The counter, the threshold and the ladder each have unit coverage, but
 * nothing proved that a run of wrong passwords against `wp-login.php`
 * actually ends in a block. That chain crosses four classes and a WordPress
 * hook, and it is the single feature most users install this plugin for.
 * A silent break here looks exactly like a quiet site.
 *
 * The attempts are spoofed onto a documentation address through the trusted
 * client-IP header, so the runner never locks itself out.
 *
 * Serial: the spec lowers a site-wide threshold.
 *
 * @since 2.1.65
 */

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';
const ATTACKER = '203.0.113.88';
const THRESHOLD = 3;

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

function wpEval(php: string): string {
	return wp('eval', php);
}

/** Rows this address has collected, as `attempts|blocks`. */
function state(): string {
	return wpEval(`
		global $wpdb;
		$prefix = $wpdb->base_prefix . 'reportedip_hive_';
		$a = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COALESCE(SUM(attempt_count),0) FROM {$prefix}attempts WHERE ip_address = %s", '${ATTACKER}' ) );
		$b = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$prefix}blocked WHERE ip_address = %s", '${ATTACKER}' ) );
		echo $a . '|' . $b;
	`);
}

function forget(): void {
	wpEval(`
		global $wpdb;
		$prefix = $wpdb->base_prefix . 'reportedip_hive_';
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$prefix}attempts WHERE ip_address = %s", '${ATTACKER}' ) );
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$prefix}blocked WHERE ip_address = %s", '${ATTACKER}' ) );
		if ( class_exists( 'ReportedIP_Hive_WAF_Dropin_Manager' ) ) {
			ReportedIP_Hive_WAF_Dropin_Manager::get_instance()->sync();
		}
	`);
}

test.describe.configure({ mode: 'serial' });

test.describe('login lockout', () => {
	test.beforeAll(() => {
		wpEval(
			"ReportedIP_Hive_Option_Routing::set('reportedip_hive_trusted_ip_header', 'HTTP_X_FORWARDED_FOR');" +
				"ReportedIP_Hive_Option_Routing::set('reportedip_hive_trusted_proxy_ranges', '');" +
				"ReportedIP_Hive_Option_Routing::set('reportedip_hive_monitor_failed_logins', 1);" +
				"ReportedIP_Hive_Option_Routing::set('reportedip_hive_auto_block', 1);" +
				`ReportedIP_Hive_Option_Routing::set('reportedip_hive_failed_login_threshold', ${THRESHOLD});` +
				"ReportedIP_Hive_Option_Routing::set('reportedip_hive_failed_login_timeframe', 15);"
		);
		forget();
	});

	test.afterAll(() => {
		forget();
		wpTolerant('eval', "ReportedIP_Hive_Option_Routing::set('reportedip_hive_trusted_ip_header', '');");
		wpTolerant(
			'option',
			'delete',
			'reportedip_hive_trusted_proxy_ranges',
			'reportedip_hive_failed_login_threshold',
			'reportedip_hive_failed_login_timeframe',
			'reportedip_hive_auto_block'
		);
	});

	test('wrong passwords are counted against the address that sent them', async ({ request }) => {
		const response = await request.post('/wp-login.php', {
			headers: { 'X-Forwarded-For': ATTACKER },
			form: { log: 'admin', pwd: 'definitely-not-the-password', 'wp-submit': 'Log In' },
			failOnStatusCode: false,
			maxRedirects: 0,
		});

		expect(response.status(), 'a wrong password must not sign anyone in').not.toBe(302);

		const [attempts] = state().split('|');

		expect(Number(attempts), 'the attempt has to reach the counter').toBeGreaterThan(0);
	});

	test('passing the threshold blocks the address', async ({ request }) => {
		for (let i = 0; i < THRESHOLD + 1; i++) {
			await request.post('/wp-login.php', {
				headers: { 'X-Forwarded-For': ATTACKER },
				form: { log: 'admin', pwd: `wrong-${i}`, 'wp-submit': 'Log In' },
				failOnStatusCode: false,
				maxRedirects: 0,
			});
		}

		const [, blocks] = state().split('|');

		expect(Number(blocks), 'past the threshold the address has to be blocked').toBeGreaterThan(0);
	});

	test('the blocked address is refused on the front end too', async ({ request }) => {
		const response = await request.get('/', {
			headers: { 'X-Forwarded-For': ATTACKER },
			failOnStatusCode: false,
		});

		expect(response.status(), 'the block has to hold outside the login form').toBe(403);
	});

	test('everyone else keeps signing in', async ({ request }) => {
		const response = await request.get('/wp-login.php', { failOnStatusCode: false });

		expect(response.status()).toBe(200);
		expect(await response.text()).toContain('id="user_login"');
	});
});
