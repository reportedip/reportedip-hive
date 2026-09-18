import { execFileSync } from 'node:child_process';
import type { APIRequestContext } from '@playwright/test';
import { test, expect } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';
import { FORCE_FREE_PHP, forceTierPhp } from '../../fixtures/tier';

/**
 * Execution proof on third-party forms (since 2.1.58).
 *
 * Same claim as form-proof.spec.ts and the same reason PHPUnit cannot carry
 * it: a real browser has to get through and a bare POST has to be refused,
 * on three form plugins that each render and validate their own way. Every
 * spec drives either a genuine page or a raw request and reads the
 * consequence out of the database.
 *
 * Fixtures the stack already carries:
 *
 *   Contact Form 7   post 700, page /rip-e2e-cf7-page/
 *   Formidable       form_id 2, form_key ripe2efrm, page /rip-e2e-frm-page/
 *   Elementor Pro    widget ripfrm01 on post 703, page /rip-e2e-elementor-page/
 *   Ultimate Member  default forms, pages /rip-e2e-um-register/ and -login,
 *                    switched on only while its own cases run
 *
 * Serial: the specs mutate shared plugin state on the long-lived stack.
 */

const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';

/** The anchor field name on every surface this plugin does not own. */
const ANCHOR = '_reportedip_hive_hp';

const CF7_PAGE = '/rip-e2e-cf7-page/';
const FRM_PAGE = '/rip-e2e-frm-page/';
const ELEMENTOR_PAGE = '/rip-e2e-elementor-page/';
const ELEMENTOR_WIDGET = 'ripfrm01';
const UM_REGISTER_PAGE = '/rip-e2e-um-register/';

/**
 * Object ids the fixture hands back. Nothing here may be hard-coded: the three
 * forms are built by `fixtures/form-plugins-setup.php` on whichever machine
 * runs the suite, and a stack that has never seen them numbers them its own
 * way.
 */
let CF7_POST = '0';
let CF7_UNIT_TAG = '';
let ELEMENTOR_POST = '0';
let FRM_FORM = '0';
let FRM_NAME_FIELD = '0';
let FRM_TEXT_FIELD = '0';
let UM_REGISTER_FORM = '0';

const ADAPTER_OPTIONS = [
	'reportedip_hive_form_proof_cf7',
	'reportedip_hive_form_proof_formidable',
	'reportedip_hive_form_proof_elementor',
	'reportedip_hive_form_proof_um',
];

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

/** Switch the three adapters on or off in one call. */
/**
 * Build the three forms and read their ids back.
 *
 * Idempotent, so a repeated run costs one call and changes nothing.
 */
function seedForms(): void {
	const out = wp(
		'eval-file',
		'wp-content/plugins/reportedip-hive/tests/e2e/fixtures/form-plugins-setup.php'
	);
	const read = (key: string): string =>
		out
			.split(/\s+/)
			.map((pair) => pair.split('='))
			.find((pair) => pair[0] === key)?.[1] ?? '0';

	CF7_POST = read('cf7');
	ELEMENTOR_POST = read('elementor');
	FRM_FORM = read('frm');
	FRM_NAME_FIELD = read('frm_name');
	FRM_TEXT_FIELD = read('frm_text');
	UM_REGISTER_FORM = read('um_register');

	const page = php(
		`$p = get_posts(array('name' => 'rip-e2e-cf7-page', 'post_type' => 'page', 'post_status' => 'any', 'numberposts' => 1)); echo $p ? (int) $p[0]->ID : 0;`
	);
	CF7_UNIT_TAG = `wpcf7-f${CF7_POST}-p${page}-o1`;
}

/**
 * Let jQuery through, or take it away again.
 *
 * `docker/mu-plugins/rip-jquery-off-test.php` strips jQuery from the front end
 * to prove the hidden login survives a theme without it. Formidable and
 * Elementor both need it, so their browser cases would fail for a reason that
 * has nothing to do with this plugin. The switch is a file in the mounted
 * profiles directory.
 */
function setJquery(on: boolean): void {
	execFileSync('docker', [
		'exec',
		WP_CONTAINER,
		'sh',
		'-c',
		on ? 'touch /profiles/jquery-on.txt' : 'rm -f /profiles/jquery-on.txt',
	]);
}

function setAdapters(on: boolean): void {
	php(
		ADAPTER_OPTIONS.map(
			(option) => `ReportedIP_Hive_Option_Routing::set('${option}', ${on ? 1 : 0});`
		).join(' ') + ` ReportedIP_Hive_Form_Proof::stamp_adapters_since();`
	);
}

/** Push the adapter grace far enough into the past that it has run out. */
function expireGrace(): void {
	php(
		"ReportedIP_Hive_Option_Routing::set('reportedip_hive_form_adapters_since', time() - 172800);"
	);
}

/** The per-install proof field name, prefixed the way an adapter carries it. */
function proofField(): string {
	return php("echo '_' . ReportedIP_Hive_Form_Proof::get_instance()->field_name();");
}

/** How many `form_proof_failed` rows the log holds. */
function failureLogCount(): number {
	return Number(
		php(`
			global $wpdb;
			echo (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->base_prefix}reportedip_hive_logs WHERE event_type = 'form_proof_failed'");
		`)
	);
}

/** How many `form_spam` counter rows exist for any address. */
function spamAttemptCount(): number {
	return Number(
		php(`
			global $wpdb;
			echo (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->base_prefix}reportedip_hive_attempts WHERE attempt_type = 'form_spam'");
		`)
	);
}

/** Drop the counter rows, so each spec reads its own consequence. */
function clearSpamAttempts(): void {
	php(`
		global $wpdb;
		$wpdb->query("DELETE FROM {$wpdb->base_prefix}reportedip_hive_attempts WHERE attempt_type = 'form_spam'");
	`);
}

/**
 * Switch Ultimate Member on or off.
 *
 * An active Ultimate Member takes the core registration form over and sends
 * `wp-login.php?action=register` to its own page, which is exactly what
 * `registration-rules.spec.ts` drives. So the plugin is only on while its own
 * cases run. Returns false when it is not installed on this stack.
 */
function umPlugin(on: boolean): boolean {
	try {
		wp('plugin', on ? 'activate' : 'deactivate', 'ultimate-member');
		return true;
	} catch {
		return false;
	}
}

/** How many accounts the Ultimate Member cases have created. */
function umUserCount(): number {
	return Number(
		php(`
			global $wpdb;
			echo (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->users} WHERE user_login LIKE 'ripe2eum%'");
		`)
	);
}

/** Drop every account the Ultimate Member cases created. */
function clearUmUsers(): void {
	php(`
		require_once ABSPATH . 'wp-admin/includes/user.php';
		global $wpdb;
		$ids = $wpdb->get_col("SELECT ID FROM {$wpdb->users} WHERE user_login LIKE 'ripe2eum%'");
		foreach ( $ids as $id ) { wp_delete_user( (int) $id ); }
	`);
}

/**
 * Drop the sign-up counter rows.
 *
 * The registration rules hold a rate limit of three sign-ups an hour per
 * address, and every case in this file arrives from the same one. Without this
 * an Ultimate Member case is refused by the limit, and the assertion about the
 * reason it was refused for then reads the wrong field.
 */
function clearRegistrationAttempts(): void {
	php(`
		global $wpdb;
		$wpdb->query("DELETE FROM {$wpdb->base_prefix}reportedip_hive_attempts WHERE attempt_type = 'registration'");
	`);
}

/**
 * Post straight at the Ultimate Member sign-up form, the way a blind bot does.
 *
 * The plugin reads its own nonce long after the validation hook this adapter
 * uses, so a body without one still reaches the check. The consequence is read
 * from the log and from the users table, never from the response.
 */
async function postUmRegister(
	request: APIRequestContext,
	login: string,
	extra: Record<string, string> = {}
): Promise<void> {
	await request.post(UM_REGISTER_PAGE, {
		form: {
			form_id: UM_REGISTER_FORM,
			[`user_login-${UM_REGISTER_FORM}`]: login,
			[`user_email-${UM_REGISTER_FORM}`]: `${login}@example.com`,
			[`user_password-${UM_REGISTER_FORM}`]: 'Str0ngPass!234',
			[`confirm_user_password-${UM_REGISTER_FORM}`]: 'Str0ngPass!234',
			...extra,
		},
		failOnStatusCode: false,
	});
}

/** How many Formidable entries the fixture form holds. */
function formidableEntryCount(): number {
	return Number(
		php(`
			global $wpdb;
			echo (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}frm_items WHERE form_id = ${FRM_FORM}");
		`)
	);
}

function clearFormidableEntries(): void {
	php(`
		global $wpdb;
		$wpdb->query("DELETE FROM {$wpdb->prefix}frm_items WHERE form_id = ${FRM_FORM}");
	`);
}

/**
 * Formidable ships an execution proof and a honeypot of its own, so a raw POST
 * is refused before our adapter ever runs. The isolating specs switch both off
 * and one spec at the end puts them back and drives a real browser, which is
 * the only way to show the two layers do not refuse each other's traffic.
 */
function setFormidableOwnGuards(on: boolean): void {
	php(`
		$settings = get_option('frm_options', array());
		if (is_array($settings)) {
			$settings['antispam'] = ${on ? 1 : 0};
			$settings['honeypot'] = '${on ? 'basic' : 'none'}';
			update_option('frm_options', $settings);
		}
	`);
}

/**
 * Assemble a multipart body by hand.
 *
 * Contact Form 7 answers anything that is not multipart with a 415, and
 * Playwright's own `multipart` option silently leaves out every field whose
 * value is an empty string. An empty anchor is exactly what a browser that ran
 * the script sends, so the difference between "empty" and "not there" is the
 * one this spec is about and the body has to be written out here.
 */
function multipartBody(fields: Record<string, string>): { body: Buffer; type: string } {
	const boundary = `----ripE2E${Date.now()}${Math.random().toString(36).slice(2)}`;
	const parts = Object.entries(fields).map(
		([name, value]) =>
			`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`
	);

	return {
		body: Buffer.from(`${parts.join('')}--${boundary}--\r\n`, 'utf8'),
		type: `multipart/form-data; boundary=${boundary}`,
	};
}

/** Post straight at the Contact Form 7 endpoint, the way a blind bot does. */
async function postCf7(
	request: APIRequestContext,
	extra: Record<string, string> = {}
): Promise<Record<string, unknown>> {
	const { body, type } = multipartBody({
		_wpcf7: CF7_POST,
		_wpcf7_unit_tag: CF7_UNIT_TAG,
		'your-name': 'E2E Prober',
		'your-email': 'e2e-prober@example.com',
		'your-message': `An ordinary enquiry written at ${Date.now()}.`,
		...extra,
	});

	const response = await request.post(
		`/wp-json/contact-form-7/v1/contact-forms/${CF7_POST}/feedback`,
		{
			data: body,
			headers: { 'content-type': type },
			failOnStatusCode: false,
		}
	);

	return (await response.json()) as Record<string, unknown>;
}

/**
 * Post at Contact Form 7 and insist the refusal is ours.
 *
 * Contact Form 7 files a submission as spam for reasons of its own too, an
 * unverified nonce among them, so a green assertion on the status alone can
 * mean our adapter never ran. The log row is the only evidence that names us.
 */
async function expectCf7Refused(
	request: APIRequestContext,
	extra: Record<string, string> = {}
): Promise<void> {
	const logsBefore = failureLogCount();
	const body = await postCf7(request, extra);

	expect(body.status).toBe('spam');
	expect(
		failureLogCount(),
		'the refusal must come from our adapter, not from Contact Form 7'
	).toBeGreaterThan(logsBefore);
}

/**
 * Post at Formidable and insist the refusal is ours.
 *
 * Same reason as the Contact Form 7 helper: Formidable turns away a request
 * that does not look like one of its own rendered forms, so an entry table
 * that stayed empty is no evidence by itself.
 */
async function expectFormidableRefused(request: APIRequestContext): Promise<void> {
	clearFormidableEntries();
	const logsBefore = failureLogCount();

	await postFormidable(request);

	expect(formidableEntryCount()).toBe(0);
	expect(
		failureLogCount(),
		'the refusal must come from our adapter, not from Formidable'
	).toBeGreaterThan(logsBefore);
}

/** Post straight at the Elementor Pro form endpoint. */
async function postElementor(
	request: APIRequestContext,
	extra: Record<string, string> = {}
): Promise<Record<string, unknown>> {
	const response = await request.post('/wp-admin/admin-ajax.php', {
		form: {
			action: 'elementor_pro_forms_send_form',
			post_id: ELEMENTOR_POST,
			form_id: ELEMENTOR_WIDGET,
			queried_id: ELEMENTOR_POST,
			'form_fields[name]': 'E2E Prober',
			'form_fields[message]': `An ordinary enquiry written at ${Date.now()}.`,
			...extra,
		},
		failOnStatusCode: false,
	});

	return (await response.json()) as Record<string, unknown>;
}

/**
 * Post straight at the Formidable fixture page.
 *
 * `item_key` carries no value and still has to be on the wire:
 * `FrmEntriesController::process_entry()` returns before any validation when
 * the field is missing, so a post without it is dropped by Formidable and
 * never reaches the adapter at all.
 */
async function postFormidable(
	request: APIRequestContext,
	extra: Record<string, string> = {}
): Promise<number> {
	const response = await request.post(FRM_PAGE, {
		form: {
			frm_action: 'create',
			form_id: FRM_FORM,
			form_key: 'ripe2efrm',
			item_key: '',
			[`item_meta[${FRM_NAME_FIELD}]`]: 'E2E Prober',
			[`item_meta[${FRM_TEXT_FIELD}]`]: `An ordinary enquiry written at ${Date.now()}.`,
			...extra,
		},
		maxRedirects: 0,
		failOnStatusCode: false,
	});

	return response.status();
}

test.describe.configure({ mode: 'serial' });

test.describe('form adapters', () => {
	test.beforeAll(() => {
		resetAdminBaseline();
		seedForms();
		setJquery(true);
		php(`
			${forceTierPhp('business')}
			ReportedIP_Hive_Option_Routing::set('reportedip_hive_form_proof_enabled', 1);
			ReportedIP_Hive_Option_Routing::set('reportedip_hive_form_proof_pow', 0);
			ReportedIP_Hive_Option_Routing::set('reportedip_hive_reputation_on_forms', 0);
		`);
		setAdapters(true);
		setFormidableOwnGuards(false);
		expireGrace();
	});

	test.afterAll(() => {
		setJquery(false);
		setFormidableOwnGuards(true);
		phpTolerant(`
			${ADAPTER_OPTIONS.map((option) => `ReportedIP_Hive_Option_Routing::delete('${option}');`).join(' ')}
			ReportedIP_Hive_Option_Routing::delete('reportedip_hive_form_adapters_since');
			ReportedIP_Hive_Option_Routing::delete('reportedip_hive_form_proof_enabled');
			ReportedIP_Hive_Option_Routing::delete('reportedip_hive_reputation_on_forms');
			${FORCE_FREE_PHP}
			global $wpdb;
			$prefix = $wpdb->base_prefix . 'reportedip_hive_';
			$wpdb->query("DELETE FROM {$prefix}attempts WHERE attempt_type = 'form_spam'");
			$wpdb->query("DELETE FROM {$prefix}blocked WHERE block_type = 'automatic'");
			$wpdb->query("DELETE FROM {$wpdb->prefix}frm_items WHERE form_id = ${FRM_FORM}");
			if (class_exists('ReportedIP_Hive_WAF_Dropin_Manager')) {
				ReportedIP_Hive_WAF_Dropin_Manager::get_instance()->sync();
			}
		`);
	});

	/**
	 * Case 1: the anchor reaches every form, exactly once each. Twice would
	 * mean the later value overwrites the earlier one and the verdict reads a
	 * field nobody filled.
	 */
	for (const [label, url] of [
		['Contact Form 7', CF7_PAGE],
		['Formidable', FRM_PAGE],
		['Elementor', ELEMENTOR_PAGE],
	] as const) {
		test(`${label} renders the anchor exactly once`, async ({ page }) => {
			await page.goto(url);
			await page.waitForLoadState('domcontentloaded');

			await expect(page.locator('form input.rip-fp-anchor')).toHaveCount(1);
			await expect(page.locator(`form input[name="${ANCHOR}"]`)).toHaveCount(1);
		});
	}

	/** Case 2: a real browser fills the form in and is accepted. */
	test('a real browser gets through Contact Form 7', async ({ page }) => {
		await page.goto(CF7_PAGE);
		await page.fill('input[name="your-name"]', 'E2E Reader');
		await page.fill('input[name="your-email"]', 'e2e-reader@example.com');
		await page.fill('textarea[name="your-message"]', 'An ordinary enquiry from a reader.');
		await page.click('.wpcf7-submit');

		await expect(page.locator('form.wpcf7-form')).toHaveAttribute('data-status', 'sent');
	});

	test('a real browser gets through Elementor', async ({ page }) => {
		await page.goto(ELEMENTOR_PAGE);
		await page.fill('input[name="form_fields[name]"]', 'E2E Reader');
		await page.fill('textarea[name="form_fields[message]"]', 'An ordinary enquiry from a reader.');
		await page.click('.elementor-button[type="submit"]');

		await expect(page.locator('.elementor-message-success')).toBeVisible();
	});

	test('a real browser gets through Formidable', async ({ page }) => {
		clearFormidableEntries();

		await page.goto(FRM_PAGE);
		await page.fill(`input[name="item_meta[${FRM_NAME_FIELD}]"]`, 'E2E Reader');
		await page.fill(`textarea[name="item_meta[${FRM_TEXT_FIELD}]"]`, 'An ordinary enquiry from a reader.');
		await page.click('.frm_button_submit');
		await page.waitForLoadState('domcontentloaded');

		expect(formidableEntryCount()).toBe(1);
	});

	/** Case 3: a bare POST carrying none of our fields, past the grace. */
	test('a bare post without our fields is refused on Contact Form 7', async ({ request }) => {
		await expectCf7Refused(request);
	});

	test('a bare post without our fields is refused on Elementor', async ({ request }) => {
		const body = await postElementor(request);

		expect(body.success).toBe(false);
	});

	test('a bare post without our fields is refused on Formidable', async ({ request }) => {
		await expectFormidableRefused(request);
	});

	/** Case 4: a filled decoy is refused, logged and counted. */
	test('a filled decoy is refused, logged and counted', async ({ request }) => {
		clearSpamAttempts();

		await expectCf7Refused(request, { [ANCHOR]: 'http://spam.example' });

		expect(spamAttemptCount()).toBe(1);

		clearSpamAttempts();
	});

	/** Case 5: an empty anchor without the proof field is refused but never counted. */
	test('a client that never ran the script is refused but not counted', async ({ request }) => {
		clearSpamAttempts();

		await expectCf7Refused(request, { [ANCHOR]: '' });

		expect(spamAttemptCount(), 'a browser without JavaScript must never be tracked').toBe(0);
	});

	/** The proof field alone, spelled correctly, is what lets a post through. */
	test('a post carrying both fields is accepted', async ({ request }) => {
		const field = proofField();
		const body = await postCf7(request, { [ANCHOR]: '', [field]: '1' });

		expect(body.status).toBe('mail_sent');
	});

	/**
	 * Case 6: the grace. A page served from a cache filled before the switch
	 * carries no anchor at all, and refusing those readers on day one is worse
	 * than the spam it stops.
	 */
	test('during the grace a post without our fields still passes', async ({ request }) => {
		php("ReportedIP_Hive_Option_Routing::set('reportedip_hive_form_adapters_since', time());");

		const body = await postCf7(request);

		expect(body.status).toBe('mail_sent');

		expireGrace();
	});

	/** Case 7: the plan decides which adapters are armed. */
	test('the free plan leaves all three adapters inert', async ({ request }) => {
		php(FORCE_FREE_PHP);

		const cf7 = await postCf7(request);
		const elementor = await postElementor(request);

		expect(cf7.status).toBe('mail_sent');
		expect(elementor.success).toBe(true);

		clearFormidableEntries();
		await postFormidable(request);
		expect(formidableEntryCount()).toBe(1);

		php(forceTierPhp('business'));
	});

	test('professional arms Contact Form 7 and leaves the other two inert', async ({ request }) => {
		php(forceTierPhp('professional'));

		await expectCf7Refused(request);

		const elementor = await postElementor(request);

		expect(elementor.success, 'Elementor needs the Business plan').toBe(true);

		clearFormidableEntries();
		await postFormidable(request);
		expect(formidableEntryCount(), 'Formidable needs the Business plan').toBe(1);

		php(forceTierPhp('business'));
	});

	test('business arms all three adapters', async ({ request }) => {
		await expectCf7Refused(request);

		const elementor = await postElementor(request);

		expect(elementor.success).toBe(false);

		await expectFormidableRefused(request);
	});

	/** Case 8: the off switch. */
	test('the switches release the adapters', async ({ request }) => {
		setAdapters(false);

		const cf7 = await postCf7(request);
		const elementor = await postElementor(request);

		expect(cf7.status).toBe('mail_sent');
		expect(elementor.success).toBe(true);

		setAdapters(true);
		expireGrace();
	});

	/**
	 * Case 9: two forms on one page. The anchor name is the same on both, so a
	 * second form must carry its own copy rather than share or overwrite the
	 * first one's.
	 */
	test('two forms on one page both get through', async ({ page }) => {
		const pageId = php(`
			$existing = get_posts(array('name' => 'rip-e2e-two-forms', 'post_type' => 'page', 'post_status' => 'any', 'numberposts' => 1));
			$id = $existing ? (int) $existing[0]->ID : (int) wp_insert_post(array(
				'post_title' => 'RIP E2E two forms',
				'post_name' => 'rip-e2e-two-forms',
				'post_content' => '[contact-form-7 id="${CF7_POST}"]' . "\\n" . '[contact-form-7 id="${CF7_POST}"]',
				'post_status' => 'publish',
				'post_type' => 'page',
			));
			echo $id;
		`);

		await page.goto(`/?page_id=${pageId}`);
		await page.waitForLoadState('domcontentloaded');

		await expect(page.locator('form input.rip-fp-anchor')).toHaveCount(2);

		const forms = page.locator('form.wpcf7-form');

		for (let index = 0; index < 2; index++) {
			const form = forms.nth(index);
			await form.locator('input[name="your-name"]').fill(`E2E Reader ${index}`);
			await form.locator('input[name="your-email"]').fill(`e2e-reader-${index}@example.com`);
			await form
				.locator('textarea[name="your-message"]')
				.fill(`An ordinary enquiry from form ${index}.`);
			await form.locator('.wpcf7-submit').click();

			await expect(form).toHaveAttribute('data-status', 'sent');
		}

		phpTolerant(`wp_delete_post(${pageId}, true);`);
	});

	/**
	 * Formidable brings its own execution proof and its own honeypot. Both
	 * layers plant a hidden field and both read it back, and a real browser has
	 * to satisfy the pair. This is the spec that would catch the two refusing
	 * each other's traffic.
	 */
	test('Formidable passes with its own antispam and honeypot switched on', async ({ page }) => {
		setFormidableOwnGuards(true);
		clearFormidableEntries();

		await page.goto(FRM_PAGE);
		await page.fill(`input[name="item_meta[${FRM_NAME_FIELD}]"]`, 'E2E Reader');
		await page.fill(`textarea[name="item_meta[${FRM_TEXT_FIELD}]"]`, 'An ordinary enquiry from a reader.');
		await page.click('.frm_button_submit');
		await page.waitForLoadState('domcontentloaded');

		expect(formidableEntryCount(), 'the two proof layers must not refuse each other').toBe(1);

		setFormidableOwnGuards(false);
	});

	test.describe('Ultimate Member', () => {
		test.beforeAll(() => {
			if (!umPlugin(true)) {
				return;
			}
			seedForms();
		});

		test.afterAll(() => {
			clearUmUsers();
			clearRegistrationAttempts();
			umPlugin(false);
		});

		/**
		 * Ultimate Member writes the account itself instead of going through the
		 * WordPress sign-up, so nothing about this path is covered by the comment
		 * and sign-up specs. A real browser has to get an account, a blind POST
		 * must not, and a filled decoy has to cost the address a counter row.
		 */
		test('Ultimate Member refuses a blind sign-up and lets a browser through', async ({
			page,
			request,
		}) => {
			test.skip(UM_REGISTER_FORM === '0', 'Ultimate Member is not installed on this stack');

			setAdapters(true);
			expireGrace();
			clearUmUsers();
			clearSpamAttempts();
			clearRegistrationAttempts();

			const logsBefore = failureLogCount();

			await postUmRegister(request, 'ripe2eumblind');

			expect(umUserCount(), 'a body that never carried the anchor must not open an account').toBe(0);
			expect(
				failureLogCount(),
				'the refusal must come from our adapter, not from Ultimate Member'
			).toBeGreaterThan(logsBefore);

			await postUmRegister(request, 'ripe2eumdecoy', { _reportedip_hive_hp: 'filled by a bot' });

			expect(umUserCount()).toBe(0);
			expect(spamAttemptCount(), 'a filled decoy counts against the address').toBeGreaterThan(0);

			const login = `ripe2eum${Date.now().toString().slice(-6)}`;

			await page.goto(UM_REGISTER_PAGE);
			await page.waitForLoadState('domcontentloaded');
			await expect(page.locator('form input.rip-fp-anchor')).toHaveCount(1);

			await page.fill(`input[name="user_login-${UM_REGISTER_FORM}"]`, login);
			await page.fill(`input[name="user_email-${UM_REGISTER_FORM}"]`, `${login}@example.com`);
			await page.fill(`input[name="user_password-${UM_REGISTER_FORM}"]`, 'Str0ngPass!234');
			await page.fill(`input[name="confirm_user_password-${UM_REGISTER_FORM}"]`, 'Str0ngPass!234');
			await page.click('input[type="submit"].um-button');
			await page.waitForLoadState('domcontentloaded');

			expect(umUserCount(), 'a reader with a browser must get an account').toBe(1);

			clearUmUsers();
		});

		/**
		 * The registration rules used to reach an Ultimate Member sign-up only
		 * through the last safety net, moments before the row was written and with
		 * WordPress's own wording. This is the spec that would catch that
		 * regression: the refusal has to name the field it is about.
		 */
		test('Ultimate Member runs the registration rules with a readable reason', async ({ page }) => {
			test.skip(UM_REGISTER_FORM === '0', 'Ultimate Member is not installed on this stack');

			setAdapters(true);
			clearUmUsers();
			clearRegistrationAttempts();
			php("ReportedIP_Hive_Option_Routing::set('reportedip_hive_disposable_email_action', 'block');");

			await page.goto(UM_REGISTER_PAGE);
			await page.waitForLoadState('domcontentloaded');

			await page.fill(`input[name="user_login-${UM_REGISTER_FORM}"]`, 'ripe2eumthrowaway');
			await page.fill(
				`input[name="user_email-${UM_REGISTER_FORM}"]`,
				'ripe2eumthrowaway@mailinator.com'
			);
			await page.fill(`input[name="user_password-${UM_REGISTER_FORM}"]`, 'Str0ngPass!234');
			await page.fill(`input[name="confirm_user_password-${UM_REGISTER_FORM}"]`, 'Str0ngPass!234');
			await page.click('input[type="submit"].um-button');
			await page.waitForLoadState('domcontentloaded');

			expect(umUserCount(), 'a throwaway address must not open an account').toBe(0);
			await expect(page.locator(`#um-error-for-user_email-${UM_REGISTER_FORM}`)).toContainText(
				'permanent e-mail address'
			);

			php("ReportedIP_Hive_Option_Routing::set('reportedip_hive_disposable_email_action', 'monitor');");
			clearUmUsers();
		});
	});
});
