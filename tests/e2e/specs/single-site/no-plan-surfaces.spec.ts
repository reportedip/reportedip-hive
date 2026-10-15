import { execFileSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { forceTierPhp, FORCE_FREE_PHP } from '../../fixtures/tier';

/**
 * The free plugin alone names no price and books no plan (wordpress.org
 * rules 5 and 11): no upsell card on the dashboard, a plan badge that links
 * nowhere, no plan overview on the Community page and no "What's new"
 * banner. On a paid account it shows one dismissible hint that the add-on
 * is missing, on the plugin pages only. The add-on's suite covers the
 * surfaces it brings (`plan-surfaces.spec.ts`).
 */
const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-suite-wordpress-1';

function wpEval(php: string): string {
	return execFileSync('docker', ['exec', WP_CONTAINER, 'wp', '--allow-root', 'eval', php], { encoding: 'utf8' }).toString().trim();
}

const ADMIN = "get_user_by( 'login', 'admin' )->ID";
const FORGET_DISMISSALS = `foreach ( array( 'professional', 'business', 'enterprise' ) as $t ) { delete_user_meta( ${ADMIN}, 'reportedip_dismissed_reportedip_hive_addon_available_' . $t ); }`;

test.describe.configure({ mode: 'serial' });

test.describe('free plugin without the add-on', () => {
	test.skip(process.env.RIP_E2E_WITH_PRO === '1', 'the add-on brings the plan surfaces back; see the pro suite plan-surfaces');
	let wizard = '';
	let mode = '';

	test.beforeAll(() => {
		wizard = wpEval("echo (string) get_option( 'reportedip_hive_wizard_completed', '' );");
		mode = wpEval("echo (string) get_option( 'reportedip_hive_operation_mode', 'local' );");
		wpEval(`update_option( 'reportedip_hive_wizard_completed', 1 ); update_option( 'reportedip_hive_operation_mode', 'local' ); ${FORGET_DISMISSALS} ${FORCE_FREE_PHP}`);
	});

	test.afterAll(() => {
		wpEval(`update_option( 'reportedip_hive_wizard_completed', ${JSON.stringify(wizard)} ); update_option( 'reportedip_hive_operation_mode', ${JSON.stringify(mode || 'local')} ); ${FORGET_DISMISSALS} ${FORCE_FREE_PHP}`);
	});

	test('the dashboard carries no upsell, no plans link and a plain plan badge', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive');
		await expect(page.locator('.rip-status-banner')).toBeVisible();
		await expect(page.locator('.rip-upsell')).toHaveCount(0);
		await expect(page.locator('a[href*="reportedip.com/pricing"]')).toHaveCount(0);
		await expect(page.locator('.rip-header__actions span.rip-tier-badge')).toHaveCount(1);
		await expect(page.locator('.rip-notice--whatsnew')).toHaveCount(0);
		await expect(page.locator('.rip-tier-upgrade-banner')).toHaveCount(0);
	});

	test('the Community page shows no plan overview and no price', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-community&tab=community');
		await expect(page.getByRole('heading', { name: 'Your contribution & activity' })).toBeVisible();
		await expect(page.locator('.rip-pricing-grid')).toHaveCount(0);
		await expect(page.locator('.rip-relay-highlights')).toHaveCount(0);
		await expect(page.locator('body')).not.toContainText('€');
		await expect(page.getByRole('link', { name: 'Upgrade now' })).toHaveCount(0);
	});

	test('a paid account sees one dismissible hint that the add-on is missing', async ({ page }) => {
		wpEval(forceTierPhp('business'));
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive');
		const hint = page.locator('.notice', { hasText: 'ReportedIP Hive Pro add-on' });
		await expect(hint).toHaveCount(1);
		await expect(hint).toContainText('Business plan');
		await expect(hint.locator('a[href="https://reportedip.com/login/?redirect_to=https%3A%2F%2Freportedip.com%2Fdashboard%2F&rc=hive-plugin"]')).toHaveCount(1);

		await page.goto('/wp-admin/');
		await expect(page.locator('.notice', { hasText: 'ReportedIP Hive Pro add-on' }), 'never on the WordPress dashboard').toHaveCount(0);

		await page.goto('/wp-admin/admin.php?page=reportedip-hive');
		const dismiss = page.locator('.notice', { hasText: 'ReportedIP Hive Pro add-on' }).locator('button.notice-dismiss');
		await Promise.all([
			page.waitForResponse((r) => r.url().includes('admin-ajax.php') && (r.request().postData() ?? '').includes('reportedip_hive_dismiss_notice')),
			dismiss.click(),
		]);
		await page.reload();
		await expect(page.locator('.rip-header__title')).toBeVisible();
		await expect(page.locator('.notice', { hasText: 'ReportedIP Hive Pro add-on' })).toHaveCount(0);
	});
	test('the API status notices show on the plugin pages, never on the WordPress dashboard', async ({ page }) => {
		const QUEUE = "ReportedIP_Hive_Schema::table( 'reportedip_hive_api_queue' )";
		const CLEAR = `global $wpdb; $wpdb->delete( ${QUEUE}, array( 'ip_address' => '203.0.113.250' ) );`;
		wpEval(`${CLEAR} $wpdb->insert( ${QUEUE}, array( 'ip_address' => '203.0.113.250', 'category_ids' => '18', 'status' => 'failed', 'created_at' => gmdate( 'Y-m-d H:i:s' ) ) );`);
		try {
			await loginAsAdmin(page);
			for (const url of ['/wp-admin/admin.php?page=reportedip-hive', '/wp-admin/admin.php?page=reportedip-hive-protection']) {
				await page.goto(url);
				const notice = page.locator('.notice', { hasText: 'API reports failed' });
				await expect(notice, url).toHaveCount(1);
				await expect(notice.locator('a', { hasText: 'View queue' })).toHaveCount(1);
				await expect(notice.locator('#retry-failed-reports-notice')).toHaveCount(1);
			}
			await expect(page.locator('body')).not.toContainText('Upgrade API tier');

			await page.goto('/wp-admin/');
			await expect(page.locator('.notice', { hasText: 'API reports failed' }), 'never on the WordPress dashboard').toHaveCount(0);
		} finally {
			wpEval(CLEAR);
		}
	});
});
