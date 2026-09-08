import { execFileSync } from 'node:child_process';
import type { Page } from '@playwright/test';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * Adaptive 2FA policies (Professional, since 2.1.51): the settings matrix
 * renders one row per trigger, saves through the Settings API, keeps the
 * administrator column off until an administrator has passed a challenge,
 * and the evaluator actually re-challenges a matched user at sign-in — even
 * on a trusted device — without ever locking out a user who has no second
 * factor at all.
 *
 * The plan is driven through `reportedip_hive_known_tier`, the durable
 * fallback the mode manager reads when no API status transient is present.
 *
 * Docker budget: every `docker exec` costs about five seconds on Windows, so
 * the whole fixture (both test users, their 2FA state, the seeded sign-in
 * history and the trusted-device row) is provisioned by a single `wp eval`
 * in beforeAll and torn down by a single one in afterAll.
 *
 * Serial: the spec mutates the stack's stored tier, its policy options and
 * two shared test users.
 */

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';
const POLICY_KEY = 'reportedip_hive_2fa_policy_new_ip';
const LATCH_KEY = 'reportedip_hive_2fa_policy_admin_verified';

/** User with TOTP, a trusted device and a sign-in history from another address. */
const STEPUP_USER = 'rip_e2e_stepup';
const STEPUP_PASS = 'RipE2eStepup!42';

/** Same role, same trigger, but no second factor at all. */
const NOMETHOD_USER = 'rip_e2e_nomethod';
const NOMETHOD_PASS = 'RipE2eNoMethod!42';

/** Plaintext trusted-device token; its SHA-256 is seeded into the table. */
const TRUSTED_TOKEN = 'ripe2epolicytrusteddevice0123456789';
const TRUSTED_COOKIE = 'reportedip_hive_trusted_device';

/** Address seeded as the account's only known IP — never the test client's. */
const KNOWN_IP = '203.0.113.9';

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

/**
 * Run a PHP snippet inside the container. Statements are joined with a space
 * so the whole batch travels as one argv entry — no shell, no quoting rules.
 */
function wpEval(statements: string[]): string {
	return wp('eval', statements.join(' '));
}

/** Submit wp-login.php with the given credentials. */
async function submitLogin(page: Page, login: string, pass: string): Promise<void> {
	await page.goto('/wp-login.php');
	await page.fill('#user_login', login);
	await page.fill('#user_pass', pass);
	await page.click('#wp-submit');
}

/** Put the seeded trusted-device token into the test's browser context. */
async function seedTrustedCookie(page: Page, baseURL: string | undefined): Promise<void> {
	await page.context().addCookies([
		{ name: TRUSTED_COOKIE, value: TRUSTED_TOKEN, url: baseURL ?? 'http://localhost:8080' },
	]);
}

let twoFactorWasOn = '0';
let logLevelWas = 'info';

test.describe.configure({ mode: 'serial' });

test.describe('adaptive 2fa policies', () => {
	test.beforeAll(() => {
		resetAdminBaseline();

		const out = wpEval([
			"$old_2fa = ReportedIP_Hive_Option_Routing::get('reportedip_hive_2fa_enabled_global', '0');",
			"$old_log = ReportedIP_Hive_Option_Routing::get('reportedip_hive_log_level', 'info');",
			'foreach (ReportedIP_Hive_Two_Factor_Policies::TRIGGERS as $t) { ReportedIP_Hive_Option_Routing::delete(ReportedIP_Hive_Two_Factor_Policies::option_key($t)); }',
			"foreach (array('reportedip_hive_2fa_policy_days', 'reportedip_hive_2fa_policy_logins', 'reportedip_hive_2fa_policy_sessions', ReportedIP_Hive_Login_Context::OPT_ADMIN_VERIFIED) as $k) { ReportedIP_Hive_Option_Routing::delete($k); }",
			"ReportedIP_Hive_Option_Routing::set('reportedip_hive_known_tier', 'professional');",
			"ReportedIP_Hive_Option_Routing::set('reportedip_hive_2fa_enabled_global', '1');",
			"ReportedIP_Hive_Option_Routing::set('reportedip_hive_log_level', 'info');",
			"ReportedIP_Hive_Option_Routing::set('reportedip_hive_hide_login_enabled', '0');",
			"delete_transient('reportedip_hive_api_status');",
			"$mk = function ($login, $pass, $role) { $u = get_user_by('login', $login); if (! $u instanceof WP_User) { $id = wp_insert_user(array('user_login' => $login, 'user_email' => $login . '@example.test', 'user_pass' => $pass, 'role' => $role)); $u = get_user_by('id', $id); } else { wp_set_password($pass, $u->ID); $u->set_role($role); } return $u; };",
			`$a = $mk('${STEPUP_USER}', '${STEPUP_PASS}', 'editor');`,
			'$sec = ReportedIP_Hive_Two_Factor_Crypto::encrypt(ReportedIP_Hive_Two_Factor_TOTP::generate_secret());',
			'update_user_meta($a->ID, ReportedIP_Hive_Two_Factor::META_TOTP_SECRET, $sec);',
			"update_user_meta($a->ID, 'reportedip_hive_2fa_totp_enabled', '1');",
			"update_user_meta($a->ID, ReportedIP_Hive_Two_Factor::META_ENABLED, '1');",
			"update_user_meta($a->ID, 'reportedip_hive_2fa_method', 'totp');",
			`update_user_meta($a->ID, ReportedIP_Hive_Audit_Logger::KNOWN_IPS_META, array('${KNOWN_IP}'));`,
			`update_user_meta($a->ID, ReportedIP_Hive_Two_Factor::META_LOGIN_CONTEXT, wp_json_encode(array('last' => array('ip' => '${KNOWN_IP}', 'net' => '203.0.113.0/24', 'ua' => 'seed', 'ua_short' => 'seed', 'country' => '', 'ts' => time()), 'verified_at' => time(), 'logins_since_verify' => 0, 'nets' => array('203.0.113.0/24'), 'uas' => array('seed'), 'countries' => array())));`,
			`$b = $mk('${NOMETHOD_USER}', '${NOMETHOD_PASS}', 'editor');`,
			"global $wpdb; $tbl = $wpdb->base_prefix . 'reportedip_hive_trusted_devices';",
			"$wpdb->delete($tbl, array('user_id' => $a->ID));",
			`$wpdb->insert($tbl, array('user_id' => $a->ID, 'token_hash' => hash('sha256', '${TRUSTED_TOKEN}'), 'device_name' => 'e2e-policy', 'ip_address' => '127.0.0.1', 'created_at' => current_time('mysql', true), 'expires_at' => gmdate('Y-m-d H:i:s', time() + 86400)));`,
			"echo 'SEED|' . $old_2fa . '|' . $old_log . '|' . $a->ID . '|' . $b->ID;",
		]);

		const parts = out.split('SEED|')[1]?.split('|') ?? [];
		if (parts.length < 4) {
			throw new Error(`policy seed did not report success. Output:\n${out}`);
		}
		twoFactorWasOn = parts[0] || '0';
		logLevelWas = parts[1] || 'info';
	});

	test.afterAll(() => {
		wpEval([
			'foreach (ReportedIP_Hive_Two_Factor_Policies::TRIGGERS as $t) { ReportedIP_Hive_Option_Routing::delete(ReportedIP_Hive_Two_Factor_Policies::option_key($t)); }',
			`foreach (array('reportedip_hive_2fa_policy_days', 'reportedip_hive_2fa_policy_logins', 'reportedip_hive_2fa_policy_sessions', 'reportedip_hive_known_tier', '${LATCH_KEY}') as $k) { ReportedIP_Hive_Option_Routing::delete($k); }`,
			`ReportedIP_Hive_Option_Routing::set('reportedip_hive_2fa_enabled_global', '${twoFactorWasOn}');`,
			`ReportedIP_Hive_Option_Routing::set('reportedip_hive_log_level', '${logLevelWas}');`,
			"require_once ABSPATH . 'wp-admin/includes/user.php';",
			"global $wpdb; $tbl = $wpdb->base_prefix . 'reportedip_hive_trusted_devices';",
			`foreach (array('${STEPUP_USER}', '${NOMETHOD_USER}') as $login) { $u = get_user_by('login', $login); if ($u instanceof WP_User) { $wpdb->delete($tbl, array('user_id' => $u->ID)); wp_delete_user($u->ID); } }`,
			"echo 'CLEANED';",
		]);
	});

	test('the matrix renders one row per trigger', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-settings&tab=two_factor');

		const matrix = page.locator('#rip-2fa-policies');
		await expect(matrix).toBeVisible();
		await expect(matrix.locator('tbody tr')).toHaveCount(7);
		await expect(matrix.locator('input[name="reportedip_hive_2fa_policy_days"]')).toBeVisible();
	});

	test('the administrator column stays off while the latch is closed', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-settings&tab=two_factor');

		const adminBox = page
			.locator('#rip-2fa-policies')
			.locator(`input[name="${POLICY_KEY}[]"][value="administrator"]`);

		await expect(adminBox).toBeDisabled();
	});

	test('ticking a role saves the policy list', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-settings&tab=two_factor');

		await page
			.locator('#rip-2fa-policies')
			.locator(`input[name="${POLICY_KEY}[]"][value="editor"]`)
			.check();
		await page.locator('#rip-2fa-policies').scrollIntoViewIfNeeded();
		await page.locator('form input[type="submit"], form button[type="submit"]').first().click();

		await expect
			.poll(() => wpTolerant('option', 'get', POLICY_KEY), { timeout: 30_000 })
			.toBe('["editor"]');
	});

	test('the free plan refuses a policy role list', async ({ page }) => {
		wpEval([
			"ReportedIP_Hive_Option_Routing::delete('reportedip_hive_known_tier');",
			"ReportedIP_Hive_Option_Routing::delete(ReportedIP_Hive_Two_Factor_Policies::option_key('new_ip'));",
			"delete_transient('reportedip_hive_api_status');",
			"echo 'FREE';",
		]);

		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-settings&tab=two_factor');

		await expect(page.locator('#rip-2fa-policies')).toHaveClass(/rip-fieldset--locked/);

		const box = page.locator(`#rip-2fa-policies input[name="${POLICY_KEY}[]"][value="editor"]`);
		await expect(box).toBeDisabled();

		// The lock is server-enforced, so post the value anyway: re-enable the
		// input in the DOM and submit the real settings form.
		await box.evaluate((el) => {
			const input = el as HTMLInputElement;
			input.disabled = false;
			input.checked = true;
		});
		await page.locator('form input[type="submit"], form button[type="submit"]').first().click();
		await page.waitForURL(/settings-updated=true/, { timeout: 30_000 });

		const stored = wpTolerant('option', 'get', POLICY_KEY);
		expect(stored).not.toContain('editor');
		expect(['', '[]']).toContain(stored);

		wpEval([
			"ReportedIP_Hive_Option_Routing::set('reportedip_hive_known_tier', 'professional');",
			"delete_transient('reportedip_hive_api_status');",
			"echo 'PRO';",
		]);
	});

	test('the three interval fields save and survive a reload', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-settings&tab=two_factor');

		await page.fill('#reportedip_hive_2fa_policy_days', '12');
		await page.fill('#reportedip_hive_2fa_policy_logins', '7');
		await page.fill('#reportedip_hive_2fa_policy_sessions', '5');
		await page.locator('form input[type="submit"], form button[type="submit"]').first().click();
		await page.waitForURL(/settings-updated=true/, { timeout: 30_000 });

		const stored = wpEval([
			"echo 'VALUES|' . ReportedIP_Hive_Option_Routing::get('reportedip_hive_2fa_policy_days', '') . '|' . ReportedIP_Hive_Option_Routing::get('reportedip_hive_2fa_policy_logins', '') . '|' . ReportedIP_Hive_Option_Routing::get('reportedip_hive_2fa_policy_sessions', '');",
		]);
		expect(stored).toContain('VALUES|12|7|5');

		await page.goto('/wp-admin/admin.php?page=reportedip-hive-settings&tab=two_factor');
		await expect(page.locator('#reportedip_hive_2fa_policy_days')).toHaveValue('12');
		await expect(page.locator('#reportedip_hive_2fa_policy_logins')).toHaveValue('7');
		await expect(page.locator('#reportedip_hive_2fa_policy_sessions')).toHaveValue('5');
	});

	test('a sign-in from a new IP is challenged despite a trusted device', async ({ page, baseURL }) => {
		wpEval([
			"ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Two_Factor_Policies::option_key('new_ip'), wp_json_encode(array('editor')));",
			"echo 'ARMED';",
		]);

		await seedTrustedCookie(page, baseURL);
		await submitLogin(page, STEPUP_USER, STEPUP_PASS);

		await expect(page).toHaveURL(/action=reportedip_2fa/);
		await expect(page.locator('#rip-2fa-panel-totp')).toBeVisible();
		await expect(page.locator('input[name="reportedip_2fa_code"]').first()).toBeVisible();

		const logged = wpEval([
			"global $wpdb; $tbl = $wpdb->base_prefix . 'reportedip_hive_logs';",
			"echo 'LOG|' . (string) $wpdb->get_var($wpdb->prepare('SELECT details FROM ' . $tbl . ' WHERE event_type = %s ORDER BY id DESC LIMIT 1', '2fa_stepup_required'));",
		]);
		expect(logged).toContain('new_ip');
	});

	test('a user without a second factor is never locked out', async ({ page }) => {
		await submitLogin(page, NOMETHOD_USER, NOMETHOD_PASS);

		await page.waitForURL((url) => url.pathname.includes('/wp-admin/'), { timeout: 30_000 });
		expect(page.url()).not.toContain('action=reportedip_2fa');

		const logged = wpEval([
			"global $wpdb; $tbl = $wpdb->base_prefix . 'reportedip_hive_logs';",
			"echo 'LOG|' . (string) $wpdb->get_var($wpdb->prepare('SELECT details FROM ' . $tbl . ' WHERE event_type = %s ORDER BY id DESC LIMIT 1', '2fa_stepup_skipped_no_method'));",
		]);
		expect(logged).toContain('new_ip');
	});

	test('the same trusted device signs in once the trigger is disarmed', async ({ page, baseURL }) => {
		wpEval([
			"ReportedIP_Hive_Option_Routing::delete(ReportedIP_Hive_Two_Factor_Policies::option_key('new_ip'));",
			"echo 'DISARMED';",
		]);

		await seedTrustedCookie(page, baseURL);
		await submitLogin(page, STEPUP_USER, STEPUP_PASS);

		await page.waitForURL((url) => url.pathname.includes('/wp-admin/'), { timeout: 30_000 });
		expect(page.url()).not.toContain('action=reportedip_2fa');
	});
});
