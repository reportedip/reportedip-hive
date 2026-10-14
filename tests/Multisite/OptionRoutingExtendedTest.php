<?php
/**
 * Extended multisite coverage for Option_Routing semantics introduced in 2.0.
 *
 * The original {@see ReportedIP_Hive_Option_Routing_Multisite_Test} pinned
 * the basic routing contract. This file locks in the additions that landed
 * during the dual-stack-policy refactor:
 *
 *   - per-blog cache isolation in `cache_key()` (so `switch_to_blog()` does
 *     not leak resolved overrides across sub-sites)
 *   - the new `get_network_enforce_roles()` / `get_site_enforce_roles_extra()`
 *     helpers (used by the Site-2FA UI to mark roles as "enforced by network"
 *     without polluting the site-extra list)
 *   - the `update_site_option_*` hook that flushes the resolve cache
 *   - `Mode_Manager::on_mode_site_option_updated()` adapter for the sitemeta
 *     hook signature
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.0
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Option_Routing_Extended_Multisite_Test extends WP_UnitTestCase {

	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
		ReportedIP_Hive_Option_Routing::flush_resolve_cache();
	}

	/**
	 * `get_network_enforce_roles()` returns sitemeta only, no merge with
	 * the site-extra list. This matters for the Site-2FA UI, which uses the
	 * helper to draw the "enforced by network" badge.
	 */
	public function test_get_network_enforce_roles_returns_sitemeta_only() {
		update_site_option( 'reportedip_hive_2fa_enforce_roles', array( 'administrator', 'editor' ) );

		$site_id = self::factory()->blog->create();
		switch_to_blog( $site_id );
		update_option( 'reportedip_hive_2fa_enforce_roles_extra', array( 'shop_manager' ) );

		$network_only = ReportedIP_Hive_Option_Routing::get_network_enforce_roles();
		sort( $network_only );
		$this->assertSame( array( 'administrator', 'editor' ), $network_only );
		restore_current_blog();
	}

	/**
	 * `get_site_enforce_roles_extra()` returns the local extras only, no
	 * leakage from the network list.
	 */
	public function test_get_site_enforce_roles_extra_returns_wp_options_only() {
		update_site_option( 'reportedip_hive_2fa_enforce_roles', array( 'administrator' ) );

		$site_id = self::factory()->blog->create();
		switch_to_blog( $site_id );
		update_option( 'reportedip_hive_2fa_enforce_roles_extra', array( 'shop_manager' ) );

		$extras = ReportedIP_Hive_Option_Routing::get_site_enforce_roles_extra();
		$this->assertSame( array( 'shop_manager' ), $extras );
		restore_current_blog();
	}

	/**
	 * `cache_key()` must suffix the bucket with the current `blog_id`, or the
	 * resolved override leaks across `switch_to_blog()` boundaries.
	 */
	public function test_resolve_cache_isolated_per_blog() {
		update_site_option( 'reportedip_hive_2fa_enforce_roles', array( 'administrator' ) );

		$site_a = self::factory()->blog->create();
		$site_b = self::factory()->blog->create();

		switch_to_blog( $site_a );
		update_option( 'reportedip_hive_2fa_enforce_roles_extra', array( 'shop_manager' ) );
		ReportedIP_Hive_Option_Routing::flush_resolve_cache();
		$this->assertSame( array( 'administrator', 'shop_manager' ), ReportedIP_Hive_Option_Routing::resolve_2fa_enforce_roles() );
		restore_current_blog();

		switch_to_blog( $site_b );
		$this->assertSame(
			array( 'administrator' ),
			ReportedIP_Hive_Option_Routing::resolve_2fa_enforce_roles(),
			'Site-B must not see Site-A cached override.'
		);
		restore_current_blog();
	}

	/**
	 * Updating an enforce-roles key MUST invalidate the resolve cache too.
	 */
	public function test_resolve_cache_invalidated_on_enforce_roles_update() {
		update_site_option(
			'reportedip_hive_2fa_enforce_roles',
			array( 'administrator' )
		);
		$first = ReportedIP_Hive_Option_Routing::resolve_2fa_enforce_roles();
		$this->assertContains( 'administrator', $first );

		update_site_option(
			'reportedip_hive_2fa_enforce_roles',
			array( 'editor', 'author' )
		);
		$second = ReportedIP_Hive_Option_Routing::resolve_2fa_enforce_roles();
		$this->assertContains( 'editor', $second );
		$this->assertContains( 'author', $second );
		$this->assertNotContains( 'administrator', $second );
	}

	/**
	 * `Mode_Manager::on_mode_site_option_updated()` mirrors the
	 * single-site `on_mode_option_updated()` so the cached_mode value stays
	 * fresh when the option is written through sitemeta.
	 */
	public function test_mode_manager_listens_to_site_option_update_hook() {
		update_site_option( 'reportedip_hive_operation_mode', 'local' );
		$this->assertSame( 'local', ReportedIP_Hive_Mode_Manager::get_instance()->get_mode() );

		update_site_option( 'reportedip_hive_operation_mode', 'community' );
		$this->assertSame(
			'community',
			ReportedIP_Hive_Mode_Manager::get_instance()->get_mode(),
			'Mode_Manager must reflect a sitemeta-routed mode update on the same request.'
		);
	}

	/**
	 * Network-admin save handler routes form submissions through Option_Routing
	 * and DOES NOT pre-sanitize, that prevents the double-sanitize regression
	 * where complex array sanitizers (enforce_roles, allowed_methods) collapsed
	 * to `'[]'` because their callback was applied twice.
	 *
	 * Smoke: the bug rationale is locked in. We simulate a POST and verify the
	 * value reaches sitemeta unmangled.
	 */
	public function test_handle_network_admin_save_persists_complex_array_values() {
		if ( ! class_exists( 'ReportedIP_Hive_Admin_Settings' ) ) {
			require_once dirname( __DIR__, 2 ) . '/admin/class-admin-settings.php';
		}
		if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_Admin' ) ) {
			require_once dirname( __DIR__, 2 ) . '/admin/class-two-factor-admin.php';
		}

		$user_id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		grant_super_admin( $user_id );
		wp_set_current_user( $user_id );

		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_enforce_roles',
			array(
				'type'              => 'string',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_enforce_roles' ),
			)
		);

		global $new_whitelist_options;
		$new_whitelist_options['reportedip_hive_2fa_settings'] = array(
			'reportedip_hive_2fa_enforce_roles',
		);

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- harness writes $_POST/_REQUEST under controlled conditions.
		$_POST['option_page'] = 'reportedip_hive_2fa_settings';
		$_POST['_wpnonce']    = wp_create_nonce( 'reportedip_hive_2fa_settings-options' );
		$_REQUEST['_wpnonce'] = $_POST['_wpnonce'];
		$_POST['reportedip_hive_2fa_enforce_roles']   = array( 'editor', 'author' );
		$_REQUEST['reportedip_hive_2fa_enforce_roles'] = $_POST['reportedip_hive_2fa_enforce_roles'];

		// Suppress the wp_safe_redirect at the end of handle_network_admin_save().
		// the test harness has already emitted output, so the redirect would error out.
		add_filter(
			'wp_redirect',
			static function () {
				throw new \Exception( 'rip-test-redirect' );
			},
			1
		);
		try {
			$settings = new ReportedIP_Hive_Admin_Settings();
			$settings->handle_network_admin_save();
		} catch ( \Exception $e ) {
			$this->assertSame( 'rip-test-redirect', $e->getMessage() );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		$stored = get_site_option( 'reportedip_hive_2fa_enforce_roles' );
		$this->assertSame( '["editor","author"]', $stored );
	}
}
