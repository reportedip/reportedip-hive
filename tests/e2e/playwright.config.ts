import { defineConfig, devices, type PlaywrightTestConfig } from '@playwright/test';

/**
 * Playwright config for the ReportedIP Hive E2E suite.
 *
 * Two projects keep the dual-stack-testing policy explicit:
 *   - single-site → http://localhost:8280  (./run.sh up)
 *   - multisite   → http://localhost:8290  (./run.sh up-ms)
 *
 * Both projects share the same spec base under `specs/<project>/` so a
 * change to a spec file is scoped to one stack at a time.
 *
 * The CI job spins up the matching docker-compose stack before invoking
 * `npx playwright test --project=...` so each project runs against its
 * own real WordPress install.
 *
 * `RIP_E2E_WITH_PRO=1` runs the free specs with the add-on active: each
 * stack project then depends on a setup project that activates the add-on
 * and names a teardown project that deactivates it again
 * (setup/add-on.setup.ts). The expected differences of such a run are
 * listed in docs/PARITY.md of the monorepo.
 */

const withAddOn = process.env.RIP_E2E_WITH_PRO === '1';

const addOnProjects: NonNullable<PlaywrightTestConfig['projects']> = withAddOn
    ? ['single-site', 'multisite'].flatMap((stack) => [
          { name: `add-on-on-${stack}`, testDir: './setup', testMatch: /add-on\.setup\.ts/, teardown: `add-on-off-${stack}` },
          { name: `add-on-off-${stack}`, testDir: './setup', testMatch: /add-on\.setup\.ts/ },
      ])
    : [];
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
        ...addOnProjects,
        {
            name: 'single-site',
            testDir: './specs/single-site',
            dependencies: withAddOn ? ['add-on-on-single-site'] : [],
            use: {
                ...devices['Desktop Chrome'],
                baseURL: process.env.RIP_E2E_BASE_URL_SINGLE || 'http://localhost:8280',
            },
        },
        {
            name: 'multisite',
            testDir: './specs/multisite',
            dependencies: withAddOn ? ['add-on-on-multisite'] : [],
            use: {
                ...devices['Desktop Chrome'],
                baseURL: process.env.RIP_E2E_BASE_URL_MS || 'http://localhost:8290',
            },
        },
    ],
});
