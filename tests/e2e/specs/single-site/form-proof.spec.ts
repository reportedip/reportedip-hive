import { execFileSync } from 'node:child_process';
import type { APIRequestContext, Browser } from '@playwright/test';
import { test, expect } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';

/**
 * Form execution proof (since 2.1.53).
 *
 * The claim this feature makes cannot be proven by PHPUnit: a real browser has
 * to pass and a bare HTTP POST has to fail, and only both halves together mean
 * anything. Every spec therefore drives either a genuine page or a raw request
 * and reads the consequence back out of the database.
 *
 * Serial: the specs mutate shared plugin state on the long-lived stack.
 */

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';
const ANCHOR = 'reportedip_hive_hp';

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

/**
 * Run one PHP snippet in the container. Every helper batches its whole job into
 * a single call: one `docker exec` costs about five seconds here.
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

/** Approval state of the newest comment on the fixture post. */
function newestCommentState(postId: string): string {
	return php(`
		$rows = get_comments(array('post_id' => ${postId}, 'number' => 1, 'orderby' => 'comment_ID', 'order' => 'DESC', 'status' => 'any'));
		echo $rows ? (string) $rows[0]->comment_approved : 'none';
	`);
}

/**
 * Drop every comment on the fixture post.
 *
 * WordPress refuses a second comment from the same address within fifteen
 * seconds with HTTP 429, and it decides that by looking for a recent comment in
 * the database. Clearing the post between specs both defuses that and makes
 * each spec read its own consequence instead of the previous one's.
 */
function clearComments(postId: string): void {
	php(`
		foreach (get_comments(array('post_id' => ${postId}, 'status' => 'any', 'fields' => 'ids')) as $id) { wp_delete_comment((int) $id, true); }
	`);
}

/** Reasons recorded on the newest comment-spam log row. */
function newestSpamReasons(): string {
	return php(`
		global $wpdb;
		$row = $wpdb->get_var("SELECT details FROM {$wpdb->base_prefix}reportedip_hive_logs WHERE event_type = 'comment_spam' ORDER BY id DESC LIMIT 1");
		$data = $row ? json_decode($row, true) : array();
		echo isset($data['reasons']) ? (string) $data['reasons'] : '';
	`);
}

/** Post a comment straight at the endpoint, the way a blind bot does. */
async function postComment(
	request: APIRequestContext,
	postId: string,
	extra: Record<string, string> = {}
): Promise<number> {
	const response = await request.post('/wp-comments-post.php', {
		form: {
			comment: 'A perfectly ordinary sentence with nothing suspicious in it at all.',
			author: 'E2E Prober',
			email: 'e2e-prober@example.com',
			url: '',
			comment_post_ID: postId,
			comment_parent: '0',
			...extra,
		},
		maxRedirects: 0,
		failOnStatusCode: false,
	});

	return response.status();
}

let postId = '0';
let commentsWereOpen = '';
let moderationWasOn = '0';

test.describe.configure({ mode: 'serial' });

test.describe('form execution proof', () => {
	test.beforeAll(() => {
		resetAdminBaseline();
		const seeded = php(`
			$existing = get_posts(array('name' => 'rip-e2e-form-proof', 'post_type' => 'post', 'post_status' => 'any', 'numberposts' => 1));
			$id = $existing ? (int) $existing[0]->ID : (int) wp_insert_post(array(
				'post_title' => 'RIP E2E form proof',
				'post_name' => 'rip-e2e-form-proof',
				'post_content' => 'Fixture post for the execution-proof specs.',
				'post_status' => 'publish',
				'comment_status' => 'open',
			));
			$was_moderation = (int) get_option('comment_moderation');
			update_option('comment_moderation', 0);
			update_option('comment_previously_approved', 0);
			update_option('default_comment_status', 'open');
			ReportedIP_Hive_Option_Routing::set('reportedip_hive_form_proof_enabled', 1);
			ReportedIP_Hive_Option_Routing::set('reportedip_hive_comment_honeypot_enabled', 1);
			ReportedIP_Hive_Option_Routing::set('reportedip_hive_comment_spam_action', 'spam');
			ReportedIP_Hive_Option_Routing::set('reportedip_hive_form_proof_seen', time());
			echo $id . '|' . $was_moderation;
		`);
		[postId, moderationWasOn] = seeded.split('|');
		commentsWereOpen = postId;
	});

	test.afterAll(() => {
		phpTolerant(`
			update_option('comment_moderation', ${moderationWasOn === '1' ? 1 : 0});
			foreach (get_comments(array('post_id' => ${commentsWereOpen}, 'status' => 'any', 'fields' => 'ids')) as $id) { wp_delete_comment((int) $id, true); }
			ReportedIP_Hive_Option_Routing::delete('reportedip_hive_form_proof_enabled');
			ReportedIP_Hive_Option_Routing::delete('reportedip_hive_form_proof_seen');
			ReportedIP_Hive_Option_Routing::delete('reportedip_hive_comment_spam_action');
		`);
	});

	test('a real browser adds the proof field and its comment is accepted', async ({ browser }) => {
		const context = await browser.newContext();
		const page = await context.newPage();

		clearComments(postId);

		await page.goto('/?p=' + postId);
		await page.waitForLoadState('domcontentloaded');

		const proofName = php( "echo ReportedIP_Hive_Form_Proof::get_instance()->field_name();" );

		await expect(page.locator('input.rip-fp-anchor')).toHaveCount(1);
		await expect(page.locator(`#commentform input[name="${proofName}"]`)).toHaveCount(1);

		await page.fill('#comment', 'Ein ganz normaler Leserkommentar ueber den Artikel.');
		await page.fill('#author', 'E2E Reader');
		await page.fill('#email', 'e2e-reader@example.com');
		await page.click('#submit');
		await page.waitForLoadState('domcontentloaded');

		expect(newestCommentState(postId)).toBe('1');

		await context.close();
	});

	test('a bare post without the proof field is filed as spam', async ({ request }) => {
		clearComments(postId);
		const status = await postComment(request, postId, { [ANCHOR]: '' });

		expect(status, 'the submission was refused before the filter saw it').toBe(302);
		expect(newestCommentState(postId)).toBe('spam');
		expect(newestSpamReasons()).toContain('no_js_proof');
	});

	test('a filled decoy is filed as spam', async ({ request }) => {
		clearComments(postId);
		const status = await postComment(request, postId, { [ANCHOR]: 'http://spam.example' });

		expect(status, 'the submission was refused before the filter saw it').toBe(302);
		expect(newestCommentState(postId)).toBe('spam');
		expect(newestSpamReasons()).toContain('form_decoy_filled');
	});

	test('a post that never carried the anchor is still caught while the site renders anchors', async ({
		request,
	}) => {
		clearComments(postId);
		const status = await postComment(request, postId);

		expect(status, 'the submission was refused before the filter saw it').toBe(302);
		expect(newestCommentState(postId)).toBe('spam');
		expect(newestSpamReasons()).toContain('no_js_proof');
	});

	test('registration without the proof field is refused, with the browser passing', async ({
		request,
		browser,
	}) => {
		const wasOpen = php(`
			echo (int) get_option('users_can_register');
			update_option('users_can_register', 1);
		`);

		const bare = await request.post('/wp-login.php?action=register', {
			form: {
				user_login: 'e2eproofbare',
				user_email: 'e2eproofbare@example.com',
				redirect_to: '',
				'wp-submit': 'Register',
				[ANCHOR]: '',
			},
		});

		expect(await bare.text()).toContain('needs JavaScript');
		expect(php( "echo get_user_by('login', 'e2eproofbare') ? 'yes' : 'no';" )).toBe('no');

		const context = await browser.newContext();
		const page = await context.newPage();
		await page.goto('/wp-login.php?action=register');
		await page.fill('#user_login', 'e2eproofreal');
		await page.fill('#user_email', 'e2eproofreal@example.com');
		await page.click('#wp-submit');
		await page.waitForLoadState('domcontentloaded');

		expect(php( "echo get_user_by('login', 'e2eproofreal') ? 'yes' : 'no';" )).toBe('yes');

		await context.close();
		phpTolerant(`
			require_once ABSPATH . 'wp-admin/includes/user.php';
			foreach (array('e2eproofbare', 'e2eproofreal') as $login) {
				$user = get_user_by('login', $login);
				if ($user instanceof WP_User) { wp_delete_user($user->ID); }
			}
			update_option('users_can_register', ${wasOpen === '1' ? 1 : 0});
		`);
	});

	/**
	 * The one thing nobody wants to discover during an incident is that the
	 * off switch does not work.
	 */
	test('the kill switch releases the layer', async ({ request }) => {
		clearComments(postId);
		php( "ReportedIP_Hive_Option_Routing::set('reportedip_hive_form_proof_enabled', 0);" );

		const status = await postComment(request, postId);

		expect(status, 'the submission was refused before the filter saw it').toBe(302);
		expect(newestCommentState(postId)).not.toBe('spam');

		php( "ReportedIP_Hive_Option_Routing::set('reportedip_hive_form_proof_enabled', 1);" );
	});
});
