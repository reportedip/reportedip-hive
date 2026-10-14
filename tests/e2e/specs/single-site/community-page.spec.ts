import { execSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';

/**
 * Community page: four tabs, settings first, the badges tab with a working
 * footer-badge preview and the template-driven banner builder, and the
 * Add-on tab that lists the catalog of the Pro add-on.
 */
const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-suite-wordpress-1';
const PAGE = '/wp-admin/admin.php?page=reportedip-hive-community';

function wp(args: string): string {
	return execSync(`docker exec ${WP_CONTAINER} wp --allow-root ${args}`, { encoding: 'utf8' }).toString().trim();
}

test.describe.configure({ mode: 'serial' });

test.describe('community page', () => {
	test.beforeAll(() => {
		wp('option update reportedip_hive_wizard_completed 1');
		wp('option update reportedip_hive_operation_mode local');
		wp('option update reportedip_hive_auto_footer_enabled 0');
	});

	test('settings open first and the nav carries the four tabs', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto(PAGE);
		const tabs = page.locator('.rip-nav-tabs .rip-nav-tabs__tab');
		await expect(tabs).toHaveText(['Settings', 'Community', 'Badges', 'Add-on']);
		await expect(tabs.nth(0)).toHaveClass(/rip-nav-tabs__tab--active/);
		await expect(page.locator('.rip-mode-card')).toHaveCount(2);
		await expect(page.locator('#rip-badge-builder')).toHaveCount(0);
	});

	test('the add-on tab lists the catalog and how to get the add-on, without a price', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto(`${PAGE}&tab=addon`);
		await expect(page.locator('.rip-nav-tabs__tab--active')).toHaveText('Add-on');
		const intro = page.locator('#rip-addon');
		await expect(intro).toContainText('Download it from your account dashboard at reportedip.com');
		await expect(intro.locator('a', { hasText: 'Open your account' })).toHaveAttribute('href', 'https://reportedip.com/login/?redirect_to=https%3A%2F%2Freportedip.com%2Fdashboard%2F&rc=hive-plugin');
		await expect(intro.locator('a', { hasText: 'Learn more' })).toHaveAttribute('href', 'https://reportedip.com/products/wordpress-plugin/?rc=hive-plugin');
		await expect(page.locator('.rip-addon__section tr[data-feature]')).toHaveCount(14);
		await expect(page.locator('.rip-addon__section tr[data-feature="hardening_mode"]')).toContainText('Hardening mode during attack waves');
		await expect(page.locator('.rip-content')).not.toContainText(/€|upgrade|unlock/i);
		await expect(page.locator('.rip-content a[href*="pricing"]')).toHaveCount(0);
	});

	test('the community tab holds the contribution panel, not the settings', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto(`${PAGE}&tab=community`);
		await expect(page.locator('.rip-nav-tabs__tab--active')).toHaveText('Community');
		await expect(page.locator('.rip-mode-card')).toHaveCount(0);
		await expect(page.getByRole('heading', { name: 'Your contribution & activity' })).toBeVisible();
	});

	test('the legacy promote sub-tab lands on badges with a live preview', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto(`${PAGE}&subtab=promote`);
		await expect(page.locator('.rip-nav-tabs__tab--active')).toHaveText('Badges');

		const footerPreview = page.locator('#rip-auto-footer-preview rip-hive-banner');
		await expect(footerPreview).toHaveCount(1);
		await expect.poll(() => footerPreview.evaluate((el) => el.shadowRoot !== null)).toBe(true);
		await expect(footerPreview).toHaveAttribute('data-variant', 'badge');
		await page.locator('input[name="reportedip_hive_auto_footer_variant"][value="shield"]').check();
		await expect(page.locator('#rip-auto-footer-preview rip-hive-banner')).toHaveAttribute('data-variant', 'shield');
		await page.locator('input[name="reportedip_hive_auto_footer_align"][value="left"]').check();
		await expect(page.locator('#rip-auto-footer-preview')).toHaveAttribute('data-align', 'left');
	});

	test('templates drive the builder and the shortcode follows', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto(`${PAGE}&tab=badges`);
		const shortcode = page.locator('#rip-cust-shortcode');
		await expect(shortcode).toHaveText('[reportedip_badge align="center"]');
		await expect(page.locator('#rip-cust-type-group')).toBeHidden();

		await page.locator('.rip-badge-preset[data-variant="stat"][data-type="api_reports_30d"]').click();
		await expect(shortcode).toHaveText('[reportedip_stat type="api_reports_30d" tone="contributor" align="center"]');
		await expect(page.locator('#rip-cust-type-group')).toBeVisible();
		await expect(page.locator('#rip-cust-preview rip-hive-banner')).toHaveAttribute('data-variant', 'stat');
		await expect(page.locator('.rip-badge-preset--active')).toHaveText('Contributor');

		await page.locator('input[name="rip-cust-theme"][value="light"]').check();
		await expect(shortcode).toHaveText('[reportedip_stat type="api_reports_30d" tone="contributor" theme="light" align="center"]');
	});
});
