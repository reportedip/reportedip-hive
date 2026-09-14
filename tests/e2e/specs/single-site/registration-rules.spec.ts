import { execFileSync } from 'node:child_process';
import type { APIRequestContext, Page, Response } from '@playwright/test';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';
import { FORCE_FREE_PHP, forceTierPhp } from '../../fixtures/tier';

/**
 * Registration rules (since 2.1.51).
 *
 * The Firewall page writes every list through the generic registry writer and
 * `ReportedIP_Hive_Registration_Guard` enforces the pipeline on the real
 * wp-login registration form: allowlist, rate limit, prohibited usernames,
 * e-mail rules and finally the throwaway-mail classifier. Each spec drives a
 * genuine anonymous sign-up and reads the consequence back out of the
 * database, so a rule that only renders but never fires fails here.
 *
 * Serial: the spec mutates shared plugin state on the long-lived stack.
 */

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';
const BLOCKED_LOGIN = 'e2eblockedname';
const BASELINE_LOGIN = 'administrator';
const GHOST_LOGIN_ON = 'e2eghostone';
const GHOST_LOGIN_OFF = 'e2eghosttwo';
const KEPT_LIST = 'e2ekeepthisentry';
const REGEX_ENTRY = '/^e2e-re[0-9]+$/';
/** Baked into `Disposable_Email::RELAY_DOMAINS`; never comes from the feed. */
const THROWAWAY_DOMAIN = 'duck.com';

const USERNAME_DENIED = 'This username is not allowed';
const EMAIL_DENIED = 'This e-mail address cannot be used for registration';
const DISPOSABLE_DENIED = 'Please use a permanent e-mail address';
const LIMIT_DENIED = 'Too many registrations from your network';
const REGISTERED = 'checkemail=registered';

/**
 * Run a WP-CLI command inside the single-site WordPress container. Uses an
 * argument vector so PHP snippets survive the Windows shell unquoted.
 */
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
 * Run one PHP snippet in the container. Every helper batches its whole job
 * into a single call: one `docker exec` costs about five seconds here.
 */
function php(code: string): string {
	return wp('eval', code.replace(/\s*\n\s*/g, ' ').trim());
}

function phpTolerant(code: string): string {
	try {
		return php(code);
	} catch {
		return '';
	}
}

/**
 * Submit the core registration form anonymously. The `request` fixture keeps
 * its own cookie jar, so the logged-in administrator never leaks into a
 * sign-up.
 */
async function register(
	request: APIRequestContext,
	login: string,
	email: string
): Promise<{ url: string; status: number; body: string }> {
	const response = await request.post('/wp-login.php?action=register', {
		form: { user_login: login, user_email: email, redirect_to: '', 'wp-submit': 'Register' },
	});

	return { url: response.url(), status: response.status(), body: await response.text() };
}

/**
 * Wait for the card's own registry write, not for the admin heartbeat that
 * shares admin-ajax.php.
 *
 * Only the transport is asserted from the response: `firewall.js` calls
 * `window.location.reload()` the moment the save answers, and the reload drops
 * the network resource before `response.json()` can fetch the body ("No
 * resource with given identifier found"). The verdict is therefore read where
 * it survives — the stored option, and the alert the page raises on refusal.
 */
function registrySave(page: Page): Promise<Response> {
	return page.waitForResponse(
		(response) =>
			response.url().includes('admin-ajax.php') &&
			(response.request().postData() ?? '').includes('action=reportedip_hive_registry_save')
	);
}

let registrationWasOpen = '0';

test.describe.configure({ mode: 'serial' });

test.describe('registration rules', () => {
	test.beforeAll(() => {
		resetAdminBaseline();
		registrationWasOpen = php(`
			require_once ABSPATH . 'wp-admin/includes/user.php';
			echo (int) get_option('users_can_register');
			update_option('users_can_register', 1);
			foreach (ReportedIP_Hive_Registration_Guard::OPTION_KEYS as $key) { ReportedIP_Hive_Option_Routing::delete($key); }
			${FORCE_FREE_PHP}
			ReportedIP_Hive_Option_Routing::delete('reportedip_hive_disposable_email_action');
			ReportedIP_Hive_Option_Routing::delete('reportedip_hive_block_email_relays');
			ReportedIP_Hive_Option_Routing::set('reportedip_hive_registration_limit_enabled', 0);
			foreach (get_users(array('search' => 'e2ereg*', 'search_columns' => array('user_login'), 'fields' => 'ID')) as $id) { wp_delete_user((int) $id); }
			$leftover = get_user_by('login', '${BASELINE_LOGIN}');
			if ($leftover instanceof WP_User) { wp_delete_user($leftover->ID); }
		`);
	});

	test.afterAll(() => {
		phpTolerant(`
			require_once ABSPATH . 'wp-admin/includes/user.php';
			update_option('users_can_register', ${registrationWasOpen === '1' ? 1 : 0});
			foreach (ReportedIP_Hive_Registration_Guard::OPTION_KEYS as $key) { ReportedIP_Hive_Option_Routing::delete($key); }
			${FORCE_FREE_PHP}
			ReportedIP_Hive_Option_Routing::delete('reportedip_hive_disposable_email_action');
			ReportedIP_Hive_Option_Routing::delete('reportedip_hive_block_email_relays');
			ReportedIP_Hive_Option_Routing::delete('reportedip_hive_block_user_enumeration');
			foreach (get_users(array('search' => 'e2ereg*', 'search_columns' => array('user_login'), 'fields' => 'ID')) as $id) { wp_delete_user((int) $id); }
			$leftover = get_user_by('login', '${BASELINE_LOGIN}');
			if ($leftover instanceof WP_User) { wp_delete_user($leftover->ID); }
			global $wpdb;
			$wpdb->query("DELETE FROM " . $wpdb->base_prefix . "reportedip_hive_attempts WHERE attempt_type='registration'");
			$wpdb->query("DELETE FROM " . $wpdb->base_prefix . "reportedip_hive_blocked WHERE reason='Login attempt with a non-existent username'");
			echo 'cleaned';
		`);
	});

	test('the card saves the list and the guard refuses that login', async ({ page, request }) => {
		test.setTimeout(240_000);
		php('update_user_meta( 1, "reportedip_hive_expert_mode", 1 ); echo "expert";');

		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await page.locator('#registration').evaluate((el) => {
			(el as HTMLDetailsElement).open = true;
		});

		const field = page.locator('#registration textarea[name="reportedip_hive_prohibited_usernames"]');
		await expect(field).toBeVisible();
		await field.fill(BLOCKED_LOGIN);
		await page.locator('#registration form button[type="submit"]').click();
		await page.waitForURL(/page=reportedip-hive-protection#registration/);

		expect(wpTolerant('option', 'get', 'reportedip_hive_prohibited_usernames')).toBe(BLOCKED_LOGIN);

		const denied = await register(request, BLOCKED_LOGIN, `${BLOCKED_LOGIN}@example.org`);
		expect(denied.body).toContain(USERNAME_DENIED);
		expect(denied.url).not.toContain(REGISTERED);
	});

	test('the built-in baseline refuses administrator until it is switched off', async ({ request }) => {
		php(`
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Registration_Guard::OPT_USERNAMES, '');
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Registration_Guard::OPT_USERNAMES_BASELINE, 1);
			echo 'ready';
		`);

		const denied = await register(request, BASELINE_LOGIN, 'e2ereg-baseline@example.org');
		expect(denied.body).toContain(USERNAME_DENIED);
		expect(denied.url).not.toContain(REGISTERED);

		php(
			`ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Registration_Guard::OPT_USERNAMES_BASELINE, 0); echo 'off';`
		);

		const allowed = await register(request, BASELINE_LOGIN, 'e2ereg-baseline@example.org');
		expect(allowed.body).not.toContain(USERNAME_DENIED);
		expect(allowed.url).toContain(REGISTERED);
	});

	test('an e-mail block rule refuses that domain and lets another through', async ({ request }) => {
		php(`
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Registration_Guard::OPT_USERNAMES, '');
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Registration_Guard::OPT_EMAIL_MODE, 'block');
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Registration_Guard::OPT_EMAIL_RULES, '*@blocked-example.com');
			echo 'ready';
		`);

		const denied = await register(request, 'e2ereg-block-a', 'e2ereg-block-a@blocked-example.com');
		expect(denied.body).toContain(EMAIL_DENIED);
		expect(denied.url).not.toContain(REGISTERED);

		const allowed = await register(request, 'e2ereg-block-b', 'e2ereg-block-b@example.org');
		expect(allowed.body).not.toContain(EMAIL_DENIED);
		expect(allowed.url).toContain(REGISTERED);
	});

	/**
	 * The throwaway domain is a baked-in relay from
	 * `Disposable_Email::RELAY_DOMAINS`, not a name from the synced
	 * `disposable_domains` ruleset: that ruleset is server-delivered and this
	 * dev stack currently carries the bench seed, so any hardcoded throwaway
	 * domain drifts in and out of the list between runs. Blocking relays walks
	 * the identical pipeline step and cannot drift.
	 */
	test('an e-mail allow rule refuses everything else and beats the disposable block', async ({ request }) => {
		php(`
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Registration_Guard::OPT_EMAIL_MODE, 'off');
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Disposable_Email::OPT_ACTION, 'block');
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Disposable_Email::OPT_BLOCK_RELAYS, 1);
			echo 'ready';
		`);

		const throwaway = await register(request, 'e2ereg-disp-a', `e2ereg-disp-a@${THROWAWAY_DOMAIN}`);
		expect(throwaway.body).toContain(DISPOSABLE_DENIED);
		expect(throwaway.url).not.toContain(REGISTERED);

		php(`
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Registration_Guard::OPT_EMAIL_MODE, 'allow');
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Registration_Guard::OPT_EMAIL_RULES, '*@${THROWAWAY_DOMAIN}');
			echo 'ready';
		`);

		const allowWins = await register(request, 'e2ereg-disp-b', `e2ereg-disp-b@${THROWAWAY_DOMAIN}`);
		expect(allowWins.body).not.toContain(DISPOSABLE_DENIED);
		expect(allowWins.body).not.toContain(EMAIL_DENIED);
		expect(allowWins.url).toContain(REGISTERED);

		const outsider = await register(request, 'e2ereg-disp-c', 'e2ereg-disp-c@example.org');
		expect(outsider.body).toContain(EMAIL_DENIED);
		expect(outsider.url).not.toContain(REGISTERED);
	});

	test('allow mode with an empty list behaves like off', async ({ request }) => {
		php(`
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Registration_Guard::OPT_EMAIL_MODE, 'allow');
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Registration_Guard::OPT_EMAIL_RULES, '');
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Disposable_Email::OPT_ACTION, 'off');
			echo 'ready';
		`);

		const allowed = await register(request, 'e2ereg-empty', 'e2ereg-empty@example.org');
		expect(allowed.body).not.toContain(EMAIL_DENIED);
		expect(allowed.url).toContain(REGISTERED);
	});

	test('the rate limit refuses the fourth sign-up without blocking the address', async ({ request }) => {
		php(`
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Registration_Guard::OPT_EMAIL_MODE, 'off');
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Registration_Guard::OPT_LIMIT_ENABLED, 1);
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Registration_Guard::OPT_LIMIT_COUNT, 3);
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Registration_Guard::OPT_LIMIT_TIMEFRAME, 60);
			global $wpdb;
			$wpdb->query("DELETE FROM " . $wpdb->base_prefix . "reportedip_hive_attempts WHERE attempt_type='registration'");
			echo 'ready';
		`);

		for (const index of [1, 2, 3]) {
			const accepted = await register(request, `e2ereg-rate${index}`, `e2ereg-rate${index}@example.org`);
			expect(accepted.url, `sign-up ${index} must be accepted`).toContain(REGISTERED);
		}

		const refused = await register(request, 'e2ereg-rate4', 'e2ereg-rate4@example.org');
		expect(refused.body).toContain(LIMIT_DENIED);
		expect(refused.url).not.toContain(REGISTERED);

		const front = await request.get('/');
		expect(front.status(), 'a rate-limited visitor must still reach the site').toBe(200);

		const [seenIp, activeBlocks] = php(`
			global $wpdb;
			$attempts = $wpdb->base_prefix . 'reportedip_hive_attempts';
			$blocked = $wpdb->base_prefix . 'reportedip_hive_blocked';
			$ip = (string) $wpdb->get_var("SELECT ip_address FROM $attempts WHERE attempt_type='registration' ORDER BY last_attempt DESC LIMIT 1");
			echo $ip . '|' . (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM $blocked WHERE ip_address = %s AND is_active = 1", $ip));
		`).split('|');

		expect(seenIp.length, 'the guard must have counted the visitor address').toBeGreaterThan(0);
		expect(activeBlocks, 'the rate limit must never block an address').toBe('0');
	});

	test('the unknown-username block only fires when it is switched on', async ({ browser }) => {
		php(`
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Registration_Guard::OPT_BLOCK_UNKNOWN_USERNAME, 1);
			ReportedIP_Hive_Option_Routing::set('reportedip_hive_block_user_enumeration', 1);
			global $wpdb;
			$wpdb->query("DELETE FROM " . $wpdb->base_prefix . "reportedip_hive_attempts");
			$wpdb->query("DELETE FROM " . $wpdb->base_prefix . "reportedip_hive_blocked WHERE reason='Login attempt with a non-existent username'");
			echo 'ready';
		`);

		const visitor = await browser.newContext();
		const guest = await visitor.newPage();

		await guest.goto('/wp-login.php');
		await guest.fill('#user_login', GHOST_LOGIN_ON);
		await guest.fill('#user_pass', 'wrong-password-on-purpose');
		await guest.click('#wp-submit');

		const errorOn = guest.locator('#login_error');
		await expect(errorOn).toContainText('Invalid credentials');
		expect(await errorOn.innerText(), 'the response must not confirm the username').not.toContain(GHOST_LOGIN_ON);

		const blockedIp = php(`
			global $wpdb;
			$table = $wpdb->base_prefix . 'reportedip_hive_blocked';
			$ip = (string) $wpdb->get_var("SELECT ip_address FROM $table WHERE reason='Login attempt with a non-existent username' AND is_active = 1 ORDER BY id DESC LIMIT 1");
			if ('' !== $ip) { ReportedIP_Hive_IP_Manager::get_instance()->unblock_ip($ip); }
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Registration_Guard::OPT_BLOCK_UNKNOWN_USERNAME, 0);
			echo $ip;
		`);
		expect(blockedIp.length, 'the probing address must have been blocked').toBeGreaterThan(0);

		await guest.goto('/wp-login.php');
		await guest.fill('#user_login', GHOST_LOGIN_OFF);
		await guest.fill('#user_pass', 'wrong-password-on-purpose');
		await guest.click('#wp-submit');

		const errorOff = guest.locator('#login_error');
		await expect(errorOff).toContainText('Invalid credentials');
		expect(await errorOff.innerText(), 'the response must not confirm the username').not.toContain(GHOST_LOGIN_OFF);
		await visitor.close();

		const stillFree = php(`
			global $wpdb;
			$table = $wpdb->base_prefix . 'reportedip_hive_blocked';
			echo (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM $table WHERE ip_address = %s AND is_active = 1", '${blockedIp}'));
		`);
		expect(stillFree, 'with the option off a failed sign-in must leave the address free').toBe('0');
	});

	test('the free plan refuses an eleventh entry and keeps the stored list', async ({ page }) => {
		php(`
			${FORCE_FREE_PHP}
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Registration_Guard::OPT_USERNAMES, '${KEPT_LIST}');
			update_user_meta( 1, "reportedip_hive_expert_mode", 1 );
			echo 'ready';
		`);

		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await page.locator('#registration').evaluate((el) => {
			(el as HTMLDetailsElement).open = true;
		});

		const eleven = Array.from({ length: 11 }, (unused, index) => `e2ename${index + 1}`).join('\n');
		await page.locator('#registration textarea[name="reportedip_hive_prohibited_usernames"]').fill(eleven);
		await page.locator('#registration form button[type="submit"]').click();
		await page.waitForURL(/page=reportedip-hive-protection#registration/);

		// The refusal is reported at the card and the stored list stays.
		await expect(page.locator('#registration .rip-protection__error[data-for="reportedip_hive_prohibited_usernames"]')).toContainText(/professional plan/i);
		expect(wpTolerant('option', 'get', 'reportedip_hive_prohibited_usernames')).toBe(KEPT_LIST);
	});

	test('Professional accepts eleven entries and a regular expression', async ({ page }) => {
		php(`${forceTierPhp('professional')} update_user_meta( 1, "reportedip_hive_expert_mode", 1 ); echo 'pro';`);

		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await page.locator('#registration').evaluate((el) => {
			(el as HTMLDetailsElement).open = true;
		});

		const entries = Array.from({ length: 10 }, (unused, index) => `e2ename${index + 1}`);
		entries.push(REGEX_ENTRY);
		await page.locator('#registration textarea[name="reportedip_hive_prohibited_usernames"]').fill(entries.join('\n'));
		await page.locator('#registration form button[type="submit"]').click();
		await page.waitForURL(/page=reportedip-hive-protection#registration/);

		const stored = wpTolerant('option', 'get', 'reportedip_hive_prohibited_usernames');
		expect(
			stored
				.split('\n')
				.map((line) => line.trim())
				.filter(Boolean)
		).toHaveLength(11);
		expect(stored).toContain(REGEX_ENTRY);
	});

	test('the other registration fields render in expert mode', async ({ page }) => {
		php('update_user_meta( 1, "reportedip_hive_expert_mode", 1 ); echo "expert";');
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-protection');
		await page.locator('#registration').evaluate((el) => {
			(el as HTMLDetailsElement).open = true;
		});

		for (const name of [
			'reportedip_hive_email_rules',
			'reportedip_hive_registration_limit_enabled',
			'reportedip_hive_registration_allowlist',
			'reportedip_hive_block_unknown_username_login',
		]) {
			await expect(page.locator(`#registration [name="${name}"]`)).toBeAttached();
		}
		php('delete_user_meta( 1, "reportedip_hive_expert_mode" ); echo "simple";');
	});
});
