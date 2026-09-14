import { execFileSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * The System Status page carries the readiness register (since 2.1.51). The
 * specs prove the section renders, that a real misconfiguration surfaces as a
 * warning row and disappears again once the cause is gone, that the seven-day
 * dismissal round-trips into the state option, that critical rows offer no
 * dismissal at all, and that the summary notice reaches the other plugin
 * pages plus the WP-dashboard widget.
 *
 * Serial: the specs mutate the stack's trusted-proxy options and the
 * readiness state option, both of which are global.
 */

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';
const TRUSTED_HEADER_LABEL = 'Client-IP header trusted from any source';
const DISMISS_LABEL = 'Dismiss for 7 days';

/**
 * Run one PHP snippet inside the single-site WordPress container. Every
 * `docker exec` costs about five seconds on the Windows host, so each helper
 * below deliberately batches several writes into a single snippet.
 */
function wpEval(php: string): string {
	return execFileSync('docker', ['exec', WP_CONTAINER, 'wp', '--allow-root', 'eval', php], {
		encoding: 'utf8',
	})
		.toString()
		.trim();
}

/**
 * Configure a client-IP header without any trusted proxy range, which is
 * exactly the condition `Readiness::trusted_header()` raises. The cache is
 * flushed explicitly because `update_option()` fires no `updated_option`
 * hook when the stored value already matches.
 */
function openTrustedHeaderIssue(clearState = false): void {
	const reset = clearState ? 'delete_option("reportedip_hive_readiness_state");' : '';
	wpEval(
		reset +
			'update_option("reportedip_hive_trusted_ip_header","X-Forwarded-For");' +
			'update_option("reportedip_hive_trusted_proxy_ranges","");' +
			'ReportedIP_Hive_Readiness::flush_cache();' +
			'echo "ok";'
	);
}

test.describe.configure({ mode: 'serial' });

test.describe('system status readiness register', () => {
	let originalHeader = '';
	let originalRanges = '';

	test.beforeAll(() => {
		resetAdminBaseline();
		const raw = wpEval(
			'echo get_option("reportedip_hive_trusted_ip_header","")."|".get_option("reportedip_hive_trusted_proxy_ranges","");'
		);
		const parts = raw.split('|');
		originalHeader = parts[0] ?? '';
		originalRanges = parts[1] ?? '';
	});

	test.afterAll(() => {
		try {
			wpEval(
				'delete_option("reportedip_hive_readiness_state");' +
					`update_option("reportedip_hive_trusted_ip_header",${JSON.stringify(originalHeader)});` +
					`update_option("reportedip_hive_trusted_proxy_ranges",${JSON.stringify(originalRanges)});` +
					'ReportedIP_Hive_Readiness::flush_cache();' +
					'echo "ok";'
			);
		} catch {
			/* best effort */
		}
	});

	test('system status page renders the readiness register', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-debug');

		await expect(page.locator('.rip-header__title')).toBeVisible();

		const readiness = page.locator('#rip-readiness');
		await expect(readiness).toBeVisible();
		await expect(readiness.locator('.rip-settings-section__title')).toContainText('Readiness');
	});

	test('an open trusted-header condition surfaces as a warning row and clears again', async ({ page }) => {
		openTrustedHeaderIssue(true);

		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-debug');

		const row = page.locator('#rip-readiness tbody tr', { hasText: TRUSTED_HEADER_LABEL });
		await expect(row).toHaveCount(1);
		await expect(row.locator('.rip-badge--warning')).toHaveText('Warning');

		// Naming the proxy range removes the cause, so the row must vanish.
		wpEval(
			'update_option("reportedip_hive_trusted_proxy_ranges","10.0.0.0/8");' +
				'ReportedIP_Hive_Readiness::flush_cache();' +
				'echo "ok";'
		);

		await page.goto('/wp-admin/admin.php?page=reportedip-hive-debug');
		await expect(page.locator('#rip-readiness tbody tr', { hasText: TRUSTED_HEADER_LABEL })).toHaveCount(0);
	});

	test('dismissing a warning hides the row and records the dismissal', async ({ page }) => {
		openTrustedHeaderIssue(true);

		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-debug');

		const row = page.locator('#rip-readiness tbody tr', { hasText: TRUSTED_HEADER_LABEL });
		await expect(row).toHaveCount(1);

		await row.locator('a', { hasText: DISMISS_LABEL }).click();
		await page.waitForURL(/page=reportedip-hive-debug/);

		await expect(page.locator('#rip-readiness tbody tr', { hasText: TRUSTED_HEADER_LABEL })).toHaveCount(0);

		const state = wpEval(
			'$s=get_option("reportedip_hive_readiness_state",array());' +
				'$e=isset($s["trusted_header_open"])&&is_array($s["trusted_header_open"])?$s["trusted_header_open"]:array();' +
				'echo isset($e["dismissed_until"])&&(int)$e["dismissed_until"]>time()?"DISMISSED":"OPEN";'
		);
		expect(state).toBe('DISMISSED');
	});

	test('critical rows offer no dismissal', async ({ page }) => {
		// A guard hit queue the web server cannot write to raises the critical
		// `guard_queue_unwritable` row deterministically. The schema check is
		// no fixture: the bootstrap migrates a stale version on every request.
		const queueDir = wpEval('echo dirname(ReportedIP_Hive_WAF_Dropin_Manager::get_instance()->queue_path());');
		const dropin = wpEval('echo (int) get_option("reportedip_hive_waf_dropin_enabled");');
		const setWritable = (mode: string) => {
			execFileSync('docker', ['exec', WP_CONTAINER, 'chmod', mode, queueDir]);
			wpEval('ReportedIP_Hive_Readiness::flush_cache();echo "ok";');
		};
		wpEval('update_option("reportedip_hive_waf_dropin_enabled",1);echo "ok";');
		setWritable('555');

		try {
			await loginAsAdmin(page);
			await page.goto('/wp-admin/admin.php?page=reportedip-hive-debug');

			const criticals = page.locator('#rip-readiness tbody tr:has(.rip-badge--danger)');
			expect(await criticals.count()).toBeGreaterThan(0);
			await expect(criticals.locator('a', { hasText: DISMISS_LABEL })).toHaveCount(0);
		} finally {
			setWritable('755');
			wpEval(`update_option("reportedip_hive_waf_dropin_enabled",${dropin});echo "ok";`);
		}
	});

	test('the summary notice shows on other plugin pages but not on System Status', async ({ page }) => {
		openTrustedHeaderIssue(true);
		await loginAsAdmin(page);

		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		const notice = page.locator('.rip-readiness-notice');
		await expect(notice).toBeVisible();
		await expect(notice.locator('.rip-notice__title')).toContainText(/readiness issue/);
		await expect(notice.locator('a[href*="rip-readiness"]')).toHaveCount(1);

		await page.goto('/wp-admin/admin.php?page=reportedip-hive-debug');
		await expect(page.locator('.rip-readiness-notice')).toHaveCount(0);
	});

	test('the dashboard widget links its issue count to the readiness section', async ({ page }) => {
		openTrustedHeaderIssue(true);
		await loginAsAdmin(page);
		await page.goto('/wp-admin/index.php');

		const link = page.locator('#reportedip_hive_overview .rip-dw__meta a[href*="rip-readiness"]');
		await expect(link).toBeVisible();
		await expect(link).toContainText(/readiness issue/);

		const href = (await link.getAttribute('href')) ?? '';
		expect(href).toContain('page=reportedip-hive-debug');
		expect(href).toContain('#rip-readiness');
	});
});
