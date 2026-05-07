import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright config for the ReportedIP Hive E2E suite.
 *
 * Two projects keep the dual-stack-testing policy explicit:
 *   - single-site → http://localhost:8080  (./run.sh up)
 *   - multisite   → http://localhost:8090  (./run.sh up-ms)
 *
 * Both projects share the same spec base under `specs/<project>/` so a
 * change to a spec file is scoped to one stack at a time.
 *
 * The CI job spins up the matching docker-compose stack before invoking
 * `npx playwright test --project=...` so each project runs against its
 * own real WordPress install.
 */
export default defineConfig({
    testDir: './specs',
    timeout: 60_000,
    expect: { timeout: 10_000 },
    fullyParallel: true,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 1 : 0,
    workers: process.env.CI ? 1 : undefined,
    reporter: [
        ['list'],
        ['html', { outputFolder: 'playwright-report', open: 'never' }],
        ['junit', { outputFile: 'playwright-report/junit.xml' }],
    ],

    use: {
        trace: 'retain-on-failure',
        screenshot: 'only-on-failure',
        video: 'retain-on-failure',
    },

    projects: [
        {
            name: 'single-site',
            testDir: './specs/single-site',
            use: {
                ...devices['Desktop Chrome'],
                baseURL: process.env.RIP_E2E_BASE_URL_SINGLE || 'http://localhost:8080',
            },
        },
        {
            name: 'multisite',
            testDir: './specs/multisite',
            use: {
                ...devices['Desktop Chrome'],
                baseURL: process.env.RIP_E2E_BASE_URL_MS || 'http://localhost:8090',
            },
        },
    ],
});
