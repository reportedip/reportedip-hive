import { execFileSync } from 'node:child_process';
import type { Page } from '@playwright/test';
import { test, expect } from '../../fixtures/admin';

/**
 * Password policy on the WooCommerce account details form: with the breach
 * check switched on, a customer who picks a password from a public breach
 * list gets the error on My Account and keeps the old password.
 *
 * WooCommerce is installed but inactive on the dev stack; the spec switches
 * it on for itself and restores the previous state afterwards. The breach
 * check asks api.pwnedpasswords.com, so the stack needs outbound HTTPS.
 */

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-suite-wordpress-1';
const SHOPPER = 'rip_e2e_pw_shopper';
const SHOPPER_PASS = 'RipE2eShopperPw!42';
const LEAKED = 'Password123!';

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
 * Click a submit button in the page, so neither the WooCommerce strength
 * meter (it disables the button for a weak password) nor a slow `load`
 * event of the storefront theme gets in the way.
 */
async function clickInPage(page: Page, selector: string): Promise<void> {
	await page.locator(selector).waitFor();
	await page.evaluate((sel) => {
		const button = document.querySelector(sel) as HTMLButtonElement;
		button.disabled = false;
		button.click();
	}, selector);
}

const KEYS = [
	'reportedip_hive_password_policy_enabled',
	'reportedip_hive_password_check_hibp',
	'reportedip_hive_password_policy_all_users',
	'reportedip_hive_2fa_enforce_roles',
	'reportedip_hive_2fa_enabled_global',
];

let wooWasActive = false;
let accountUrl = '';

test.describe.configure({ mode: 'serial' });

test.describe('password policy on WooCommerce My Account', () => {
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
			`$keys = array(${KEYS.map((k) => `'${k}'`).join(', ')});`,
			"$old = array(); foreach ($keys as $k) { $old[$k] = ReportedIP_Hive_Option_Routing::get($k, null); }",
			"update_option('rip_e2e_pw_policy_prev', $old, false);",
			"ReportedIP_Hive_Option_Routing::set('reportedip_hive_password_policy_enabled', 1);",
			"ReportedIP_Hive_Option_Routing::set('reportedip_hive_password_check_hibp', 1);",
			"ReportedIP_Hive_Option_Routing::set('reportedip_hive_password_policy_all_users', 1);",
			"ReportedIP_Hive_Option_Routing::set('reportedip_hive_2fa_enforce_roles', '[]');",
			"ReportedIP_Hive_Option_Routing::set('reportedip_hive_2fa_enabled_global', 0);",
			"ReportedIP_Hive_Option_Routing::flush_resolve_cache();",
			`$u = get_user_by('login', '${SHOPPER}');`,
			`if (! $u instanceof WP_User) { wp_insert_user(array('user_login' => '${SHOPPER}', 'user_email' => '${SHOPPER}@example.test', 'user_pass' => '${SHOPPER_PASS}', 'role' => 'customer')); } else { wp_set_password('${SHOPPER_PASS}', $u->ID); $u->set_role('customer'); }`,
			"echo 'SEED|' . wc_get_page_permalink('myaccount');",
		]);
		accountUrl = out.split('SEED|')[1]?.trim() ?? '';
		if (accountUrl === '') {
			throw new Error(`password policy seed did not report success. Output:\n${out}`);
		}
	});

	test.afterAll(() => {
		wpEval([
			"$old = get_option('rip_e2e_pw_policy_prev', array());",
			"foreach ((array) $old as $k => $v) { if (null === $v) { ReportedIP_Hive_Option_Routing::delete($k); } else { ReportedIP_Hive_Option_Routing::set($k, $v); } }",
			"delete_option('rip_e2e_pw_policy_prev');",
			"require_once ABSPATH . 'wp-admin/includes/user.php';",
			`$u = get_user_by('login', '${SHOPPER}'); if ($u instanceof WP_User) { wp_delete_user($u->ID); }`,
			"echo 'CLEANED';",
		]);
		if (!wooWasActive) {
			wp('plugin', 'deactivate', 'woocommerce');
		}
	});

	test('a password from a public breach is refused on the account details form', async ({ page }) => {
		await page.goto(accountUrl);
		await page.fill('#username', SHOPPER);
		await page.fill('#password', SHOPPER_PASS);
		await clickInPage(page, 'button[name="login"]');
		await expect(page.locator('.woocommerce-MyAccount-navigation')).toBeVisible();

		await page.goto(accountUrl.replace(/\/?$/, '/') + 'edit-account/');
		await page.fill('#password_current', SHOPPER_PASS);
		await page.fill('#password_1', LEAKED);
		await page.fill('#password_2', LEAKED);
		await clickInPage(page, 'button[name="save_account_details"]');

		await expect(page.locator('.woocommerce-error, .wc-block-components-notice-banner.is-error')).toContainText('public data breach');
		const stillOld = wpEval([`$u = get_user_by('login', '${SHOPPER}'); echo wp_check_password('${SHOPPER_PASS}', $u->user_pass, $u->ID) ? 'OLD' : 'NEW';`]);
		expect(stillOld).toContain('OLD');
	});
});
