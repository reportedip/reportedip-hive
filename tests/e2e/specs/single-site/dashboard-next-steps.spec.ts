import { execSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * Dashboard after the quickstart: banner, next steps with an inline action,
 * area rows, expert toggle in the page header.
 */
const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';

function wp(args: string): string {
	return execSync(`docker exec ${WP_CONTAINER} wp --allow-root ${args}`, { encoding: 'utf8' }).toString().trim();
}

function tolerant(args: string): void {
	try {
		wp(args);
	} catch {
		/* absent */
	}
}

test.describe.configure({ mode: 'serial' });

test.describe('dashboard next steps', () => {
	test.beforeAll(() => {
		resetAdminBaseline();
		wp('option update reportedip_hive_wizard_completed 1');
		wp('option update reportedip_hive_operation_mode local');
		wp('option update reportedip_hive_auto_footer_enabled 0');
		tolerant('option delete reportedip_hive_readiness_state');
		tolerant('transient delete reportedip_hive_readiness_cache');
		tolerant('user meta delete admin reportedip_hive_expert_mode');
	});

	test.afterAll(() => {
		tolerant('user meta delete admin reportedip_hive_expert_mode');
		tolerant('option delete reportedip_hive_readiness_state');
		tolerant('transient delete reportedip_hive_readiness_cache');
	});

	test('the banner names the plan and the badge step switches the badge on', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive');
		await expect(page.locator('.rip-status-banner')).toHaveCount(1);
		await expect(page.locator('.rip-status-banner')).toContainText('recommendation');
		await expect(page.locator('.rip-status-banner')).not.toContainText('1970');
		await expect(page.locator('.rip-dashboard > .rip-status-banner:first-child')).toHaveCount(1);
		await expect(page.locator('.rip-api-strip')).toHaveCount(0);
		const card = page.locator('.rip-next-steps__card[data-step="badge_off"]');
		await expect(card).toBeVisible();
		await card.locator('button[type="submit"]').click();
		await page.waitForURL(/page=reportedip-hive(&|$)/);
		expect(wp('option get reportedip_hive_auto_footer_enabled')).toBe('1');
		await expect(page.locator('.rip-next-steps__card[data-step="badge_off"]')).toHaveCount(0);
	});

	test('local shield shows the community card and "not now" hides it for a week', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive');
		const card = page.locator('.rip-next-steps__card[data-step="community_pending"]');
		await expect(card).toBeVisible();
		await card.locator('.rip-next-steps__dismiss').click();
		await page.waitForURL(/page=reportedip-hive(&|$)/);
		await expect(page.locator('.rip-next-steps__card[data-step="community_pending"]')).toHaveCount(0);
	});

	test('area rows are collapsed, explained and link to the protection anchors', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive');
		const areas = page.locator('details.rip-areas');
		await expect(areas).toHaveCount(1);
		await expect(areas).not.toHaveAttribute('open', '');
		await expect(page.locator('.rip-areas__row')).toHaveCount(14);
		await expect(page.locator('.rip-areas__row a.rip-areas__label[href$="#blocking"]')).toHaveCount(1);
		await areas.locator('summary').click();
		await expect(page.locator('.rip-areas__row .rip-areas__desc').first()).toBeVisible();
		await expect(page.locator('.rip-areas__gain[href$="#hide_login"]')).toBeVisible();
	});

	test('the header toggle switches expert mode and lists the tools page', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive');
		await expect(page.locator('#adminmenu a[href*="page=reportedip-hive-tools"]')).toHaveCount(0);
		await page.locator('label.rip-toggle:has(#rip-expert-mode)').click();
		await page.waitForURL(/page=reportedip-hive(&|$)/);
		await expect(page.locator('#rip-expert-mode')).toBeChecked();
		await expect(page.locator('#adminmenu a[href*="page=reportedip-hive-tools"]')).toHaveCount(1);
		expect(wp('user meta get admin reportedip_hive_expert_mode')).toBe('1');
	});
});
