import { execFileSync } from 'node:child_process';
import type { Page } from '@playwright/test';
import { test, expect } from '../../fixtures/admin';

/**
 * WooCommerce without the add-on: a customer with 2FA who signs in through
 * My Account is sent to the wp-login challenge (the storefront challenge
 * slug is the add-on's) and holds no session until the second factor is
 * passed.
 *
 * WooCommerce is installed but inactive on the dev stack; the spec switches
 * it on for itself and restores the previous state afterwards. The free
 * suite runs with the add-on inactive.
 */

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-suite-wordpress-1';
const SHOPPER = 'rip_e2e_free_shopper';
const SHOPPER_PASS = 'RipE2eFreeShopper!42';
const TOTP_SECRET = 'JBSWY3DPEHPK3PXP';

function wp(...args: string[]): string {
	return execFileSync('docker', ['exec', WP_CONTAINER, 'wp', '--allow-root', ...args], {
		encoding: 'utf8',
	})
		.toString()
		.trim();
}

function wpEval(statements: string[]): string {
	return wp('eval', statements.join(' '));
}

/**
 * Click a submit button without waiting for the next page's `load` event:
 * a storefront theme request can keep the event from firing, so the click
 * is dispatched in the page and the caller waits for the URL.
 */
async function submitWithoutWaiting(page: Page, selector: string): Promise<void> {
	await page.locator(selector).waitFor();
	await page.evaluate((sel) => {
		(document.querySelector(sel) as HTMLElement).click();
	}, selector);
}

let wooWasActive = false;
let previous = { twofa: '0', hideLogin: '0' };
let accountUrl = '';

test.describe.configure({ mode: 'serial' });

test.describe('storefront sign-in without the add-on', () => {
	test.beforeAll(() => {
		try {
			wp('plugin', 'is-active', 'woocommerce');
			wooWasActive = true;
		} catch {
			wooWasActive = false;
		}
		if (!wooWasActive) {
			wp('plugin', 'activate', 'woocommerce');
		}

		const out = wpEval([
			"$old = array(ReportedIP_Hive_Option_Routing::get('reportedip_hive_2fa_enabled_global', '0'), ReportedIP_Hive_Option_Routing::get('reportedip_hive_hide_login_enabled', '0'));",
			"ReportedIP_Hive_Option_Routing::set('reportedip_hive_2fa_enabled_global', '1');",
			"ReportedIP_Hive_Option_Routing::set('reportedip_hive_hide_login_enabled', '0');",
			`$u = get_user_by('login', '${SHOPPER}');`,
			`if (! $u instanceof WP_User) { $id = wp_insert_user(array('user_login' => '${SHOPPER}', 'user_email' => '${SHOPPER}@example.test', 'user_pass' => '${SHOPPER_PASS}', 'role' => 'customer')); $u = get_user_by('id', $id); } else { wp_set_password('${SHOPPER_PASS}', $u->ID); $u->set_role('customer'); }`,
			`update_user_meta($u->ID, ReportedIP_Hive_Two_Factor::META_TOTP_SECRET, ReportedIP_Hive_Two_Factor_Crypto::encrypt('${TOTP_SECRET}'));`,
			"update_user_meta($u->ID, 'reportedip_hive_2fa_totp_enabled', '1');",
			"update_user_meta($u->ID, ReportedIP_Hive_Two_Factor::META_ENABLED, '1');",
			"update_user_meta($u->ID, 'reportedip_hive_2fa_method', 'totp');",
			"global $wpdb; $wpdb->delete($wpdb->base_prefix . 'reportedip_hive_trusted_devices', array('user_id' => $u->ID));",
			"echo 'SEED|' . implode('|', $old) . '|' . (class_exists('ReportedIP_Hive_Two_Factor_Frontend') ? 'pro' : 'free') . '|' . wc_get_page_permalink('myaccount');",
		]);
		const parts = out.split('SEED|')[1]?.split('|') ?? [];
		if (parts.length < 4) {
			throw new Error(`storefront seed did not report success. Output:\n${out}`);
		}
		if (parts[2] !== 'free') {
			throw new Error('The add-on is active; the free suite runs without it.');
		}
		previous = { twofa: parts[0] || '0', hideLogin: parts[1] || '0' };
		accountUrl = parts[3];
	});

	test.afterAll(() => {
		wpEval([
			`ReportedIP_Hive_Option_Routing::set('reportedip_hive_2fa_enabled_global', '${previous.twofa}');`,
			`ReportedIP_Hive_Option_Routing::set('reportedip_hive_hide_login_enabled', '${previous.hideLogin}');`,
			"require_once ABSPATH . 'wp-admin/includes/user.php';",
			`$u = get_user_by('login', '${SHOPPER}'); if ($u instanceof WP_User) { global $wpdb; $wpdb->delete($wpdb->base_prefix . 'reportedip_hive_trusted_devices', array('user_id' => $u->ID)); wp_delete_user($u->ID); }`,
			"echo 'CLEANED';",
		]);
		if (!wooWasActive) {
			wp('plugin', 'deactivate', 'woocommerce');
		}
	});

	test('a My Account sign-in lands on the wp-login challenge and is not signed in', async ({ page }) => {
		expect(accountUrl).not.toBe('');
		await page.goto(accountUrl);
		await page.fill('#username', SHOPPER);
		await page.fill('#password', SHOPPER_PASS);
		await submitWithoutWaiting(page, 'button[name="login"]');

		await page.waitForURL(/\/wp-login\.php\?.*action=reportedip_2fa/, { waitUntil: 'commit' });
		await expect(page.locator('#rip-2fa-code-totp')).toBeVisible();

		const cookies = await page.context().cookies();
		expect(cookies.some((c) => c.name.startsWith('wordpress_logged_in_')), 'no session before the second factor').toBe(false);

		await page.goto(accountUrl, { waitUntil: 'domcontentloaded' });
		await expect(page.locator('#username')).toBeVisible();
		await expect(page.locator('.woocommerce-MyAccount-navigation')).toHaveCount(0);
	});
});
