import { createHash } from 'node:crypto';
import type { APIRequestContext } from '@playwright/test';
import { test, expect } from '../../fixtures/admin';
import { resetAdminBaseline } from '../../fixtures/admin-reset';
import { forceTierPhp } from '../../fixtures/tier';
import { wp, php, phpTolerant, flag } from '../../fixtures/wp';

/**
 * The bound form challenge (since 2.1.64).
 *
 * Two claims, both of which only a live stack can carry. First, the attacker
 * that beat the plain marker on 2026-09-23, a script that reads the field
 * names out of the page and posts them back, is refused for good: without a
 * token, with a spent token and with a tampered one. Second, the two laws of
 * the feature hold: a real browser gets through, and every refusal is a
 * visible message to the sender, never a silent loss.
 *
 * The stack speaks plain HTTP, so the endpoint hands out tasks of zero
 * difficulty; the binding, the expiry and the single use are what these
 * cases prove. The arithmetic itself is covered by the unit suite and by the
 * Gravity Forms case in form-adapters.spec.ts under the forced-HTTPS flag.
 *
 * Serial: the specs mutate shared plugin state on the long-lived stack.
 */

const CF7_PAGE = '/rip-e2e-cf7-page/';
const ANCHOR = '_reportedip_hive_hp';
const ENDPOINT = '/wp-json/reportedip-hive/v1/form/challenge';

let CF7_POST = '0';
let CF7_UNIT_TAG = '';
let PROOF = '';

function seedCf7(): void {
	const out = wp(
		'eval-file',
		'wp-content/plugins/reportedip-hive/tests/e2e/fixtures/form-plugins-setup.php'
	);
	CF7_POST =
		out
			.split(/\s+/)
			.map((pair) => pair.split('='))
			.find((pair) => pair[0] === 'cf7')?.[1] ?? '0';

	const page = php(
		`$p = get_posts(array('name' => 'rip-e2e-cf7-page', 'post_type' => 'page', 'post_status' => 'any', 'numberposts' => 1)); echo $p ? (int) $p[0]->ID : 0;`
	);
	CF7_UNIT_TAG = `wpcf7-f${CF7_POST}-p${page}-o1`;
	PROOF = php("echo '_' . ReportedIP_Hive_Form_Proof::get_instance()->field_name();");
}

/** Arm the challenge with its grace already run out. */
function armChallenge(): void {
	php(`
		${forceTierPhp('business')}
		ReportedIP_Hive_Option_Routing::set('reportedip_hive_form_proof_enabled', 1);
		ReportedIP_Hive_Option_Routing::set('reportedip_hive_form_proof_pow', 1);
		ReportedIP_Hive_Option_Routing::set('reportedip_hive_form_proof_pow_since', time() - 172800);
		ReportedIP_Hive_Option_Routing::set('reportedip_hive_form_proof_pow_version', REPORTEDIP_HIVE_VERSION);
		ReportedIP_Hive_Option_Routing::set('reportedip_hive_form_proof_cf7', 1);
		ReportedIP_Hive_Option_Routing::set('reportedip_hive_form_adapters_since', time() - 172800);
		ReportedIP_Hive_Option_Routing::set('reportedip_hive_reputation_on_forms', 0);
	`);
}

function failureCount(reason?: string): number {
	const where = reason ? ` AND details LIKE '%\\"reason\\":\\"${reason}\\"%'` : '';
	return Number(
		php(`
			global $wpdb;
			echo (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->base_prefix}reportedip_hive_logs WHERE event_type = 'form_proof_failed'${where}");
		`)
	);
}

/**
 * Encode fields by hand. Playwright's `multipart` option was tried and the
 * server never saw the proof field through it; the hand-built body is what
 * a script sends, and it is what the plugin has to judge.
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

/** Post straight at the Contact Form 7 endpoint, the way a script does. */
async function postCf7(
	request: APIRequestContext,
	extra: Record<string, string>
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
		{ data: body, headers: { 'content-type': type }, failOnStatusCode: false }
	);

	return (await response.json()) as Record<string, unknown>;
}

interface Task {
	token: string;
	seed: string;
	bits: number;
	expires: number;
}

async function fetchTask(request: APIRequestContext): Promise<{ task: Task; cacheControl: string }> {
	const response = await request.post(ENDPOINT, { failOnStatusCode: false });
	expect(response.status()).toBe(200);

	return {
		task: (await response.json()) as Task,
		cacheControl: response.headers()['cache-control'] ?? '',
	};
}

function leadingZeroBits(digest: Buffer): number {
	let bits = 0;
	for (const byte of digest) {
		if (byte === 0) {
			bits += 8;
			continue;
		}
		let part = byte;
		while (part < 128) {
			bits++;
			part <<= 1;
		}
		break;
	}
	return bits;
}

/** Solve a task the way the browser does, in Node. */
function solve(task: Task): string {
	if (!task.bits) {
		return `${task.token}.0`;
	}
	for (let nonce = 0; ; nonce++) {
		const hex = nonce.toString(16);
		const digest = createHash('sha256').update(task.seed + hex).digest();
		if (leadingZeroBits(digest) >= task.bits) {
			return `${task.token}.${hex}`;
		}
	}
}

/**
 * Post at Contact Form 7 and insist the refusal is ours and visible.
 *
 * Contact Form 7 answers `spam` with its own sentence to the sender, which
 * is the visible message the second law demands; the log row is the proof
 * the refusal came from this plugin and names why.
 */
async function expectRefused(
	request: APIRequestContext,
	extra: Record<string, string>,
	reason: string
): Promise<void> {
	const before = failureCount(reason);
	const json = await postCf7(request, extra);

	expect(json.status, 'the sender must see a refusal').toBe('spam');
	expect(typeof json.message).toBe('string');
	expect((json.message as string).length).toBeGreaterThan(10);
	expect(failureCount(reason), `the refusal must be logged as ${reason}`).toBeGreaterThan(before);
}

test.describe.configure({ mode: 'serial' });

test.describe('bound form challenge', () => {
	test.beforeAll(() => {
		resetAdminBaseline();
		phpTolerant(`
			global $wpdb;
			$prefix = $wpdb->base_prefix . 'reportedip_hive_';
			$wpdb->query("DELETE FROM {$prefix}attempts WHERE attempt_type = 'form_spam'");
			$wpdb->query("DELETE FROM {$prefix}blocked WHERE block_type = 'automatic'");
			if (class_exists('ReportedIP_Hive_WAF_Dropin_Manager')) {
				ReportedIP_Hive_WAF_Dropin_Manager::get_instance()->sync();
			}
		`);
		seedCf7();
		armChallenge();
	});

	test.afterAll(() => {
		flag('force-https.txt', false);
		phpTolerant(`
			ReportedIP_Hive_Option_Routing::delete('reportedip_hive_form_proof_pow');
			ReportedIP_Hive_Option_Routing::delete('reportedip_hive_form_proof_pow_since');
			ReportedIP_Hive_Option_Routing::delete('reportedip_hive_form_proof_pow_version');
			ReportedIP_Hive_Option_Routing::delete('reportedip_hive_form_proof_cf7');
			ReportedIP_Hive_Option_Routing::delete('reportedip_hive_form_adapters_since');
			ReportedIP_Hive_Option_Routing::delete('reportedip_hive_form_proof_enabled');
			ReportedIP_Hive_Option_Routing::delete('reportedip_hive_reputation_on_forms');
			ReportedIP_Hive_Option_Routing::delete('reportedip_hive_known_tier');
			delete_transient('reportedip_hive_api_status');
		`);
	});

	/** The page stays byte-identical for every visitor: only the endpoint address. */
	test('the anchor carries the endpoint and nothing about the visitor', async ({ page }) => {
		await page.goto(CF7_PAGE);
		const anchor = page.locator('form input.rip-fp-anchor');

		await expect(anchor).toHaveCount(1);
		await expect(anchor).toHaveAttribute('data-e', /\/wp-json\/reportedip-hive\/v1\/form\/challenge$/);
		expect(await anchor.getAttribute('data-s')).toBeNull();
	});

	/** The task itself is never cacheable, and no two are alike. */
	test('the endpoint answers fresh, uncacheable tasks', async ({ request }) => {
		const first = await fetchTask(request);
		const second = await fetchTask(request);

		expect(first.cacheControl).toContain('no-store');
		expect(first.task.token).not.toBe(second.task.token);
		expect(first.task.expires).toBeGreaterThan(Date.now() / 1000);
	});

	/** The attacker of 2026-09-23: field names read out of the page, marker posted back. */
	test('a script that copies the field names and posts 1 is refused', async ({ request }) => {
		await expectRefused(request, { [ANCHOR]: '', [PROOF]: '1' }, 'marker');
	});

	test('a script that fetches and solves a task gets through once', async ({ request }) => {
		const { task } = await fetchTask(request);
		const answer = solve(task);

		const json = await postCf7(request, { [ANCHOR]: '', [PROOF]: answer });
		expect(json.status).toBe('mail_sent');

		await expectRefused(request, { [ANCHOR]: '', [PROOF]: answer }, 'replay');
	});

	test('a tampered token is refused', async ({ request }) => {
		const { task } = await fetchTask(request);
		const broken = `${task.token.slice(0, -1)}0.0`;

		await expectRefused(request, { [ANCHOR]: '', [PROOF]: broken }, 'signature');
	});

	/** First law: an update must not refuse readers of a cache filled before it. */
	test('a version change restarts the grace so a cached page keeps working', async ({ request }) => {
		php(`
			ReportedIP_Hive_Option_Routing::set('reportedip_hive_form_proof_pow_version', 'older');
			ReportedIP_Hive_Form_Proof::get_instance()->restamp_after_update();
		`);

		const json = await postCf7(request, { [ANCHOR]: '', [PROOF]: '1' });
		expect(json.status, 'the plain marker passes again during the fresh grace').toBe('mail_sent');

		armChallenge();
		await expectRefused(request, { [ANCHOR]: '', [PROOF]: '1' }, 'marker');
	});

	/** Second law, browser side: a real visitor gets through, and again after a refusal. */
	test('a real browser gets through Contact Form 7 and again after a reload', async ({ page }) => {
		for (let round = 0; round < 2; round++) {
			await page.goto(CF7_PAGE);
			await page.fill('input[name="your-name"]', 'E2E Reader');
			await page.fill('input[name="your-email"]', 'e2e-reader@example.com');
			await page.fill('textarea[name="your-message"]', `A real message, round ${round}.`);
			await page.click('form.wpcf7-form input[type="submit"]');

			await expect(page.locator('form.wpcf7-form')).toHaveAttribute('data-status', 'sent', {
				timeout: 30000,
			});
		}
	});

	/** With the browser hash API in play the task carries arithmetic and still passes. */
	test('a real browser solves a task with real difficulty', async ({ page, request }) => {
		flag('force-https.txt', true);

		try {
			const { task } = await fetchTask(request);
			expect(task.bits).toBeGreaterThan(0);

			await page.goto(CF7_PAGE);
			await page.fill('input[name="your-name"]', 'E2E Reader');
			await page.fill('input[name="your-email"]', 'e2e-reader@example.com');
			await page.fill('textarea[name="your-message"]', 'A message with a solved task.');
			await page.click('form.wpcf7-form input[type="submit"]');

			await expect(page.locator('form.wpcf7-form')).toHaveAttribute('data-status', 'sent', {
				timeout: 60000,
			});
		} finally {
			flag('force-https.txt', false);
		}
	});

	/** Second law, script side: a refusal is told to the sender, not swallowed. */
	test('a browser without our script is told', async ({ browser }) => {
		const context = await browser.newContext({ javaScriptEnabled: false });
		const page = await context.newPage();

		try {
			await page.goto(CF7_PAGE);
			const before = failureCount();
			await page.fill('input[name="your-name"]', 'E2E Reader');
			await page.fill('input[name="your-email"]', 'e2e-reader@example.com');
			await page.fill('textarea[name="your-message"]', 'No script here.');
			await page.click('form.wpcf7-form input[type="submit"]');
			await page.waitForLoadState('domcontentloaded');

			expect(failureCount(), 'the refusal is logged').toBeGreaterThan(before);
			await expect(page.locator('form.wpcf7-form'), 'the form is still there to try again').toHaveCount(1);
		} finally {
			await context.close();
		}
	});
});
