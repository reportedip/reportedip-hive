import { execFileSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * Registration rules on a network (since 2.1.51).
 *
 * The cards live on the Network Admin firewall page; a sub-site administrator
 * never sees them. The guard hooks `wpmu_validate_user_signup`, so the network
 * sign-up form must refuse a prohibited username with the plugin's own message
 * mirrored onto the `user_name` field code that wp-signup.php actually prints.
 * The list itself is network state and belongs in sitemeta, not in a blog
 * option.
 *
 * Serial: the spec mutates network options on the long-lived stack.
 */

const MS_CONTAINER = process.env.RIP_E2E_WP_CONTAINER_MS ?? 'rip-hive-ms-wp';
const BLOCKED_LOGIN = 'e2eblockedname';
const USERNAME_DENIED = 'This username is not allowed';

/**
 * Run a WP-CLI command inside the multisite WordPress container. Uses an
 * argument vector so PHP snippets survive the Windows shell unquoted.
 */
function wp(...args: string[]): string {
	return execFileSync('docker', ['exec', MS_CONTAINER, 'wp', '--allow-root', ...args], {
		encoding: 'utf8',
	})
		.toString()
		.trim();
}

/**
 * Run one PHP snippet in the container. Each call costs about five seconds on
 * this host, so every hook batches its whole job into a single snippet.
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

let signupWas = 'none';

test.describe.configure({ mode: 'serial' });

test.describe('network registration rules', () => {
	test.beforeAll(() => {
		resetAdminBaseline('docker-compose.multisite.yml', 'wordpress-ms');
		signupWas = php(`
			echo (string) get_site_option('registration', 'none');
			update_site_option('registration', 'user');
			foreach (ReportedIP_Hive_Registration_Guard::OPTION_KEYS as $key) { ReportedIP_Hive_Option_Routing::delete($key); }
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Registration_Guard::OPT_USERNAMES, '${BLOCKED_LOGIN}');
			ReportedIP_Hive_Option_Routing::set(ReportedIP_Hive_Registration_Guard::OPT_LIMIT_ENABLED, 0);
		`);
	});

	test.afterAll(() => {
		phpTolerant(`
			update_site_option('registration', '${signupWas}');
			foreach (ReportedIP_Hive_Registration_Guard::OPTION_KEYS as $key) { ReportedIP_Hive_Option_Routing::delete($key); }
			echo 'cleaned';
		`);
	});

	test('network admin sees the registration card', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/network/admin.php?page=reportedip-hive-protection');

		await expect(page.locator('#registration')).toBeVisible();
		await expect(page.locator('#registration .rip-protection__title')).toContainText('Registration');
	});

	test('the network sign-up form refuses a prohibited username from sitemeta', async ({ request }) => {
		const response = await request.post('/wp-signup.php', {
			form: {
				stage: 'validate-user-signup',
				user_name: BLOCKED_LOGIN,
				user_email: 'e2ereg-network@example.org',
				signup_for: 'user',
				submit: 'Next',
			},
		});
		const body = await response.text();

		expect(response.status()).toBe(200);
		expect(body).toContain(USERNAME_DENIED);
		expect(body).toContain('wp-signup-username-error');

		const [network, blog] = php(
			`echo (string) get_site_option(ReportedIP_Hive_Registration_Guard::OPT_USERNAMES, '') . '|' . (string) get_option(ReportedIP_Hive_Registration_Guard::OPT_USERNAMES, '');`
		).split('|');

		expect(network, 'the list belongs to the network').toBe(BLOCKED_LOGIN);
		expect(blog, 'no per-site copy may exist').toBe('');
	});
});
