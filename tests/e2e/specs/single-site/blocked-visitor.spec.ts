import { execFileSync } from 'node:child_process';
import { test, expect } from '../../fixtures/admin';

/**
 * What a blocked address actually gets back.
 *
 * The block itself, the ref code and the cache headers each have unit
 * coverage, but nothing so far proved that a real request from a blocked
 * address is refused, and that the refusal is the kind a page cache will
 * not store. A cached 403 would lock out every later visitor sharing that
 * cache, which is the expensive failure this spec guards.
 *
 * The blocked address is spoofed through the trusted client-IP header, so
 * the runner never blocks itself: a self-block would take every spec after
 * this one down with it.
 *
 * Serial: the spec changes how the site reads the client address.
 *
 * @since 2.1.65
 */

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';

/** Documentation range, never routed, and accepted as public by the IP filter. */
const VISITOR = '203.0.113.77';

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

const SPOOF = { 'X-Forwarded-For': VISITOR };

test.describe.configure({ mode: 'serial' });

test.describe('blocked visitor', () => {
	test.beforeAll(() => {
		wpEval(
			"ReportedIP_Hive_Option_Routing::set('reportedip_hive_trusted_ip_header', 'HTTP_X_FORWARDED_FOR');" +
				"ReportedIP_Hive_Option_Routing::set('reportedip_hive_trusted_proxy_ranges', '');"
		);
	});

	test.afterAll(() => {
		wpTolerant(
			'eval',
			`ReportedIP_Hive_Database::get_instance()->unblock_ip('${VISITOR}');` +
				"ReportedIP_Hive_Option_Routing::set('reportedip_hive_trusted_ip_header', '');"
		);
		wpTolerant('option', 'delete', 'reportedip_hive_trusted_proxy_ranges');
	});

	test('an unblocked address is served normally', async ({ request }) => {
		wpEval(`ReportedIP_Hive_Database::get_instance()->unblock_ip('${VISITOR}');`);

		const response = await request.get('/', { headers: SPOOF, failOnStatusCode: false });

		expect(response.status()).toBe(200);
	});

	test('a blocked address is refused, and the refusal is not cacheable', async ({ request }) => {
		wpEval(
			`ReportedIP_Hive_Database::get_instance()->block_ip('${VISITOR}', 'e2e blocked-visitor', 'manual');`
		);

		const response = await request.get('/', { headers: SPOOF, failOnStatusCode: false });

		expect(response.status(), 'a blocked address must not be served').toBe(403);

		const cacheControl = String(response.headers()['cache-control'] ?? '');

		expect(cacheControl, 'a cached block page locks out everyone behind that cache').toContain(
			'no-store'
		);
		expect(cacheControl).toContain('no-cache');
	});

	/**
	 * Which of the two layers answered has to be readable from the outside.
	 * The guard runs before WordPress and says `X-RIP-BLOCK`, the in-plugin
	 * engine says `X-RIP-Ref`. A refusal that names neither leaves a support
	 * case guessing which half of the firewall is even running.
	 */
	test('the refusal names the layer that produced it', async ({ request }) => {
		const response = await request.get('/', { headers: SPOOF, failOnStatusCode: false });

		expect(response.status()).toBe(403);

		const headers = response.headers();
		const guard = headers['x-rip-block'] ?? '';
		const engine = headers['x-rip-ref'] ?? '';

		expect(
			`${guard}${engine}`.length,
			'neither the guard nor the engine identified itself'
		).toBeGreaterThan(0);
	});

	/**
	 * The guard exists so a blocked address never costs a WordPress boot. If
	 * it is running on this stack, its answer must not carry the theme.
	 */
	test('the guard answers before WordPress is loaded', async ({ request }) => {
		const response = await request.get('/', { headers: SPOOF, failOnStatusCode: false });

		test.skip(
			!(response.headers()['x-rip-block'] ?? ''),
			'the pre-WordPress guard is not installed on this stack'
		);

		const body = await response.text();

		expect(body, 'a themed block page means WordPress booted for a blocked address').not.toContain(
			'wp-content/themes'
		);
	});

	test('the block follows the address, not the visitor', async ({ request }) => {
		const mine = await request.get('/', { failOnStatusCode: false });

		expect(mine.status(), 'everyone else has to keep browsing').toBe(200);
	});

	test('lifting the block serves the address again', async ({ request }) => {
		wpEval(`ReportedIP_Hive_Database::get_instance()->unblock_ip('${VISITOR}');`);

		const response = await request.get('/', { headers: SPOOF, failOnStatusCode: false });

		expect(response.status()).toBe(200);
	});
});
