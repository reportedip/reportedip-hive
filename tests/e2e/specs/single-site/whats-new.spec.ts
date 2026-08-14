import { execFileSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * The "What's new" release-highlights banner (since 2.1.41) renders on the
 * plugin's own admin pages from a cached payload option and is dismissed
 * per-user via the persistent-notice AJAX path.
 *
 * The payload is seeded straight into the option the plugin reads (on single
 * site `ReportedIP_Hive_Option_Routing` stores it as a plain wp_options row)
 * so the spec never depends on the live feed endpoint. Serial: the spec
 * mutates shared plugin state on the long-lived stack.
 */

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';

/**
 * Run a WP-CLI command inside the single-site WordPress container. Uses
 * execFileSync so JSON payloads survive Windows shell quoting untouched.
 */
function wp(...args: string[]): string {
	return execFileSync('docker', ['exec', WP_CONTAINER, 'wp', '--allow-root', ...args], {
		encoding: 'utf8',
	})
		.toString()
		.trim();
}

/**
 * Same as wp() but swallows failures (missing option/meta rows exit non-zero).
 */
function wpTolerant(...args: string[]): string {
	try {
		return wp(...args);
	} catch {
		return '';
	}
}

let version = '';
let verKey = '';

test.describe.configure({ mode: 'serial' });

test.describe("what's-new banner", () => {
	test.beforeAll(() => {
		resetAdminBaseline();

		version = wp('plugin', 'get', 'reportedip-hive', '--field=version');
		expect(version).toMatch(/^\d+\.\d+\.\d+$/);
		verKey = 'whatsnew_' + version.replace(/\./g, '_');

		const payload = JSON.stringify({
			version,
			published_at: '2026-08-14T00:00:00Z',
			highlights: ['E2E highlight one', 'E2E highlight two'],
			notes_url: 'https://github.com/reportedip/reportedip-hive/releases',
		});
		wpTolerant('option', 'delete', 'reportedip_hive_whatsnew_payload');
		wp('option', 'update', 'reportedip_hive_whatsnew_payload', payload, '--format=json');
		expect(wp('option', 'get', 'reportedip_hive_whatsnew_payload', '--format=json')).toContain(
			'E2E highlight one'
		);

		wpTolerant('user', 'meta', 'delete', 'admin', `reportedip_dismissed_${verKey}`);
		wpTolerant('option', 'delete', 'reportedip_hive_whatsnew_seen_version');
	});

	test.afterAll(() => {
		wpTolerant('option', 'delete', 'reportedip_hive_whatsnew_payload');
		wpTolerant('option', 'delete', 'reportedip_hive_whatsnew_seen_version');
	});

	test('banner shows the seeded highlights and dismissal persists across reloads', async ({
		page,
	}) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive');

		const banner = page.locator('.rip-notice--whatsnew');
		await expect(banner).toBeVisible();
		await expect(banner).toContainText('E2E highlight one');
		await expect(banner).toContainText('E2E highlight two');
		await expect(banner).toContainText(version);

		// Core admin JS injects the X button into `.notice.is-dismissible`;
		// the plugin's delegated handler on `.reportedip-dismissible
		// .notice-dismiss` then persists the dismissal via admin-ajax.
		const dismiss = banner.locator('button.notice-dismiss');
		await expect(dismiss).toBeVisible();

		await Promise.all([
			page.waitForResponse(
				(response) =>
					response.url().includes('admin-ajax.php') &&
					(response.request().postData() ?? '').includes('reportedip_hive_dismiss_notice')
			),
			dismiss.click(),
		]);

		await expect
			.poll(() => wpTolerant('user', 'meta', 'get', 'admin', `reportedip_dismissed_${verKey}`), {
				timeout: 15_000,
			})
			.not.toBe('');

		await page.reload();
		await expect(page.locator('.rip-header__title')).toBeVisible();
		await expect(page.locator('.rip-notice--whatsnew')).toHaveCount(0);
	});
});
