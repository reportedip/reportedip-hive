import { execSync } from 'node:child_process';

/**
 * Helpers for the password-reset 2FA E2E spec.
 *
 * The spec needs three things the standard fixtures don't provide:
 *
 *   1. A deterministic 2FA baseline on the `admin` user (TOTP secret stored
 *      so the gate doesn't soft-bail, plus five known recovery codes the
 *      spec can submit). Implemented via `wp eval-file` against a tracked
 *      PHP snippet so the baseline is version-controlled.
 *
 *   2. A way to drain the Mailpit inbox before requesting the reset, so
 *      `getLatestResetLink()` cannot accidentally pick up a stale mail
 *      from a previous run.
 *
 *   3. A way to read the freshly-arrived reset mail back out and pull the
 *      reset link. Mailpit's HTTP API is enough — no IMAP / SMTP plumbing.
 *
 * All Docker calls assume the workspace's docker-compose project name
 * (`reportedip-hive` for single-site). When that changes, this file is
 * the only place that needs touching.
 */

/**
 * Five plaintext recovery codes that match what
 * `tests/e2e/fixtures/reset-flow-setup.php` writes via
 * `Two_Factor_Recovery::store_codes()`. The spec consumes them in order;
 * if you change one side, change the other.
 */
export const RESET_FLOW_RECOVERY_CODES = [
    'aaaa-aaaa',
    'bbbb-bbbb',
    'cccc-cccc',
    'dddd-dddd',
    'eeee-eeee',
] as const;

/**
 * Login slug the baseline configures. A dedicated test user (NOT `admin`)
 * keeps 2FA-related state out of the way of unrelated specs that drive
 * the standard login flow against the same Docker stack.
 */
export const RESET_FLOW_USER = 'e2e-reset-user';

/**
 * The Mailpit base URL. The single-site docker-compose stack publishes
 * Mailpit's HTTP API on 8125 (the workspace default; CLAUDE.md docs the
 * conceptual 8025 port but compose has remapped it). Multisite uses
 * 8035. Override via `RIP_E2E_MAILPIT_URL` if a CI environment publishes
 * the API on a different port.
 */
export const MAILPIT_BASE_URL = process.env.RIP_E2E_MAILPIT_URL ?? 'http://localhost:8125';

/**
 * Compose project that hosts the WordPress container. Single-site uses
 * the workspace-default `reportedip-hive`; multisite uses `rip-hive-ms`.
 */
const COMPOSE_FILE = process.env.RIP_E2E_COMPOSE_FILE ?? 'docker-compose.yml';
const WP_SERVICE   = process.env.RIP_E2E_WP_SERVICE ?? 'wordpress';

/**
 * Run a `docker compose exec` command against the WordPress container,
 * returning stdout. Throws if the command exits non-zero so the caller
 * sees the failure inline instead of swallowing it as an empty string.
 *
 * @param cmd Shell command to run inside the container.
 */
function execInWordpress(cmd: string): string {
    const fullCmd = `docker compose -f ${COMPOSE_FILE} exec -T ${WP_SERVICE} ${cmd}`;
    return execSync(fullCmd, {
        cwd: resolveWorkspaceRoot(),
        encoding: 'utf8',
    }).toString();
}

/**
 * Walk up from this file (which lives inside `dev/`) to the workspace
 * root that owns `docker-compose.yml`. Avoids hard-coding paths so the
 * suite can run from arbitrary working directories.
 */
function resolveWorkspaceRoot(): string {
    return new URL('../../../../', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
}

/**
 * Provision the deterministic 2FA + recovery-code baseline on the admin
 * user. Idempotent — call once per spec or once per beforeAll.
 *
 * Throws if the `wp eval-file` call fails for any reason; the spec then
 * fails fast with the underlying WP_CLI error message instead of running
 * against an undefined backend state.
 */
export function setupResetFlowBaseline(): void {
    const out = execInWordpress(
        'wp --allow-root eval-file ' +
            'wp-content/plugins/reportedip-hive/tests/e2e/fixtures/reset-flow-setup.php'
    );
    if (!out.includes('Reset-flow E2E baseline ready')) {
        throw new Error(`reset-flow-setup.php did not report success. Output:\n${out}`);
    }
}

/**
 * Reverse `setupResetFlowBaseline()`. Wire up via `test.afterAll` so
 * unrelated specs (admin-dashboard render, etc.) that run later see a
 * 2FA-free admin user.
 */
export function teardownResetFlowBaseline(): void {
    const out = execInWordpress(
        'wp --allow-root eval-file ' +
            'wp-content/plugins/reportedip-hive/tests/e2e/fixtures/reset-flow-teardown.php'
    );
    if (!/Reset-flow E2E baseline torn down|noop/.test(out)) {
        throw new Error(`reset-flow-teardown.php did not report success. Output:\n${out}`);
    }
}

/**
 * DELETE all messages from the Mailpit inbox. Run before requesting a
 * fresh reset link so `getLatestResetLink()` cannot pick up stale mail.
 */
export async function clearMailbox(): Promise<void> {
    const res = await fetch(`${MAILPIT_BASE_URL}/api/v1/messages`, {
        method: 'DELETE',
    });
    if (!res.ok) {
        throw new Error(
            `Mailpit DELETE /api/v1/messages failed: ${res.status} ${res.statusText}`
        );
    }
}

/**
 * Poll Mailpit for the most recent message addressed to a given login
 * and pull the password-reset URL out of the body. The reset URL is
 * always shaped `wp-login.php?action=rp&key=<key>&login=<login>`; the
 * regex below tolerates both raw and HTML-encoded variants since
 * different WP versions emit the link differently.
 *
 * @param expectedLogin User login the mail must be for (validates the
 *                       URL's `login=` query arg).
 * @param timeoutMs     Max wait in ms. Default 10s — generous for a
 *                       local stack but short enough to fail fast.
 */
export async function getLatestResetLink(
    expectedLogin: string,
    timeoutMs = 10_000
): Promise<string> {
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
        const listRes = await fetch(`${MAILPIT_BASE_URL}/api/v1/messages?limit=1`);
        if (!listRes.ok) {
            throw new Error(`Mailpit list failed: ${listRes.status}`);
        }
        const list = (await listRes.json()) as { messages?: Array<{ ID: string }> };
        if (list.messages && list.messages.length > 0) {
            const id  = list.messages[0].ID;
            const msg = (await (await fetch(`${MAILPIT_BASE_URL}/api/v1/message/${id}`)).json()) as {
                Text?: string;
                HTML?: string;
            };
            const haystack = `${msg.Text ?? ''}\n${msg.HTML ?? ''}`.replace(/&amp;/g, '&');

            const urls = haystack.match(/https?:\/\/[^\s"'<>]+/g) ?? [];
            for (const candidate of urls) {
                const hasAction = /[?&]action=rp(&|$)/.test(candidate);
                const hasKey    = /[?&]key=[^&\s]+/.test(candidate);
                const hasLogin  = new RegExp(
                    `[?&]login=(${expectedLogin}|${encodeURIComponent(expectedLogin)})(&|$)`
                ).test(candidate);
                if (hasAction && hasKey && hasLogin) {
                    return candidate;
                }
            }
        }
        await new Promise((r) => setTimeout(r, 250));
    }

    throw new Error(`No reset mail arrived within ${timeoutMs}ms.`);
}
