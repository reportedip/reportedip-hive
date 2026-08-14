import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * The WP-dashboard security widget (since 2.1.41) surfaces the Hive snapshot
 * on wp-admin/index.php. The spec proves the widget registers for the admin,
 * renders a numeric hero value from the cached analytics sources and links
 * back into the plugin's own Security Dashboard.
 */

test.beforeAll(() => {
	resetAdminBaseline();
});

test('security widget renders on the WP dashboard and links to the plugin', async ({ page }) => {
	await loginAsAdmin(page);
	await page.goto('/wp-admin/index.php');

	const widget = page.locator('#reportedip_hive_overview');
	await expect(widget).toBeVisible();

	const hero = widget.locator('.rip-dw__hero-value');
	await expect(hero).toBeVisible();
	const heroText = (await hero.innerText()).trim();
	expect(heroText.length).toBeGreaterThan(0);

	// number_format_i18n output: digits plus optional localized thousands
	// separators (comma, dot, apostrophe, regular/narrow no-break space).
	expect(heroText).toMatch(/^[\d.,'\s  ]+$/);

	await widget.locator('.rip-dw__action', { hasText: 'Open Security Dashboard' }).click();
	await page.waitForURL((url) => (url.searchParams.get('page') ?? '').startsWith('reportedip-hive'));
	expect(page.url()).toContain('page=reportedip-hive');
});
