import { execFileSync } from 'node:child_process';
import { test, expect, loginAsAdmin } from '../../fixtures/admin';

/**
 * Group transparency: the dashboard card and the Group tab show the stored
 * group list and why each entry is or is not blocked on this site. Seeded
 * locally, no request to reportedip.com.
 */
const WP_CONTAINER = process.env.RIP_E2E_WP_CONTAINER ?? 'reportedip-hive-wordpress-1';

function wpEval(php: string): string {
	return execFileSync('docker', ['exec', WP_CONTAINER, 'wp', '--allow-root', 'eval', php], { encoding: 'utf8' }).toString().trim();
}

const SEED = `
$db = ReportedIP_Hive_Database::get_instance();
$now = time();
$db->replace_group_entries( array(
	array( 'ip' => '198.51.100.10', 'reporter' => 'e2e-member-a', 'kind' => 'hive', 'categories' => array( 18 ), 'origin' => 'report', 'since' => gmdate( 'c', $now - 600 ), 'expires' => gmdate( 'c', $now + 7200 ) ),
	array( 'ip' => '198.51.100.11', 'reporter' => 'e2e-member-b', 'kind' => 'agent', 'categories' => array(), 'origin' => 'manual', 'since' => gmdate( 'c', $now - 600 ), 'expires' => gmdate( 'c', $now + 7200 ) ),
) );
ReportedIP_Hive_IP_Manager::get_instance()->block_ip( '198.51.100.10', 'group: e2e-member-a', 2, 'group' );
ReportedIP_Hive_IP_Manager::get_instance()->unblock_ip( '198.51.100.11' );
ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_group', array( 'id' => 1, 'name' => 'e2e-group', 'members' => 2, 'ban_hours' => 24 ) );
ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_group_status', array( 'last_run' => $now, 'last_result' => 'applied', 'http_code' => 200, 'entries' => 2, 'last_change' => $now, 'changes' => array( 'added' => 1 ) ) );
echo 'seeded';
`;

const CLEANUP = `
ReportedIP_Hive_Database::get_instance()->clear_group_entries();
ReportedIP_Hive_IP_Manager::get_instance()->unblock_ip( '198.51.100.10' );
foreach ( array( 'reportedip_hive_group', 'reportedip_hive_group_status' ) as $o ) { ReportedIP_Hive_Option_Routing::delete( $o ); }
echo 'clean';
`;

test.describe.configure({ mode: 'serial' });

test.describe('group transparency', () => {
	test.beforeAll(() => {
		expect(wpEval(SEED)).toContain('seeded');
	});

	test.afterAll(() => {
		wpEval(CLEANUP);
	});

	test('the dashboard shows the group card with the last sync and a link to the list', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive');
		const section = page.locator('.rip-settings-section', { hasText: 'Group and reputation' });
		await expect(section).toContainText('e2e-group');
		await expect(section).toContainText('Blocked by the group');
		await expect(section).toContainText('List received and applied.');
		await expect(section.getByRole('link', { name: 'Open the group list' })).toHaveAttribute('href', /sub=group/);
	});

	test('the group tab lists every entry with the reason it is or is not blocked', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-security&tab=ip_lists&sub=group');
		await expect(page.locator('.rip-sub-tabs__tab--active')).toContainText('Group');

		const blocked = page.locator('tr', { hasText: '198.51.100.10' });
		await expect(blocked).toContainText('Blocked by the group');
		await expect(blocked).toContainText('e2e-member-a');

		const lifted = page.locator('tr', { hasText: '198.51.100.11' });
		await expect(lifted).toContainText('lifted by hand');
		await expect(lifted).toContainText('Added in the account');

		await page.goto('/wp-admin/admin.php?page=reportedip-hive-security&tab=ip_lists&sub=group&group_status=none');
		await expect(page.locator('tr', { hasText: '198.51.100.10' })).toHaveCount(0);
		await expect(page.locator('tr', { hasText: '198.51.100.11' })).toHaveCount(1);
	});

	test('a group ban in the blocked list links into the group tab', async ({ page }) => {
		await loginAsAdmin(page);
		await page.goto('/wp-admin/admin.php?page=reportedip-hive-security&tab=ip_lists&sub=blocked&block_type=group');
		const link = page.locator('tr', { hasText: '198.51.100.10' }).locator('a:has(.block-type-badge.group)');
		await expect(link).toHaveAttribute('href', /sub=group&s=198\.51\.100\.10/);
	});
});
