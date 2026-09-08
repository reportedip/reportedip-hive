<?php
/**
 * Unit tests for the pure REST access decision of the attack-surface switches.
 *
 * `rest_decision()` is deliberately free of WordPress calls so the whole
 * allow/deny table — allowlisted namespaces, anonymous visitors, the two
 * modes, the administrator carve-out and the application-password route — is
 * exercised here rather than through a live REST request.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.51
 */

namespace {

	if ( ! function_exists( 'add_action' ) ) {
		function add_action( $hook, $cb, $priority = 10, $args = 1 ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( 'add_filter' ) ) {
		function add_filter( $hook, $cb, $priority = 10, $args = 1 ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( 'remove_action' ) ) {
		function remove_action( $hook, $cb, $priority = 10 ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( '__' ) ) {
		function __( $text, $domain = '' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return $text;
		}
	}
	if ( ! function_exists( 'str_starts_with' ) ) {
		function str_starts_with( $haystack, $needle ) {
			return '' === $needle || 0 === strncmp( (string) $haystack, (string) $needle, strlen( (string) $needle ) );
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-option-routing.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-attack-surface.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class AttackSurfaceRestDecisionTest extends TestCase {

		/**
		 * Namespaces seeded into the option, as the runtime would see them.
		 *
		 * @return string[]
		 */
		private function seeded_namespaces(): array {
			$raw   = (string) \ReportedIP_Hive_Defaults::all_option_defaults()['reportedip_hive_rest_allowed_namespaces'];
			$lines = array_filter( array_map( 'trim', (array) preg_split( '/\R/', $raw ) ) );

			return array_merge( \ReportedIP_Hive_Attack_Surface::ALWAYS_ALLOWED_NAMESPACES, array_values( $lines ) );
		}

		/**
		 * Run one decision against the seeded namespace list.
		 *
		 * @param string   $mode      Access mode.
		 * @param string   $route     Requested route.
		 * @param bool     $logged_in Whether a user is authenticated.
		 * @param string[] $roles     Roles of that user.
		 * @param bool     $is_admin  Administrator or super admin.
		 * @return string
		 */
		private function decide( string $mode, string $route, bool $logged_in, array $roles = array(), bool $is_admin = false ): string {
			return \ReportedIP_Hive_Attack_Surface::rest_decision(
				$mode,
				$route,
				$logged_in,
				$roles,
				$is_admin,
				$this->seeded_namespaces(),
				array( 'administrator' )
			);
		}

		public function test_open_is_the_default_mode_and_garbage_falls_back_to_it(): void {
			$GLOBALS['wp_options'] = array();
			$this->assertSame( 'open', \ReportedIP_Hive_Attack_Surface::rest_mode() );

			$GLOBALS['wp_options'] = array( 'reportedip_hive_rest_access_mode' => 'nope' );
			$this->assertSame( 'open', \ReportedIP_Hive_Attack_Surface::rest_mode() );

			$GLOBALS['wp_options'] = array( 'reportedip_hive_rest_access_mode' => 'restricted' );
			$this->assertSame( 'restricted', \ReportedIP_Hive_Attack_Surface::rest_mode() );
		}

		public function test_anonymous_request_is_denied_in_logged_in_mode(): void {
			$this->assertSame( 'deny_guest', $this->decide( 'logged_in', '/wp/v2/posts', false ) );
		}

		public function test_allowlisted_namespace_survives_for_anonymous_visitors(): void {
			$this->assertSame( 'allow', $this->decide( 'logged_in', '/oembed/1.0/embed', false ) );
			$this->assertSame( 'allow', $this->decide( 'restricted', '/wc/store/cart', false ) );
		}

		public function test_plugin_namespace_is_allowed_without_any_option_entry(): void {
			$decision = \ReportedIP_Hive_Attack_Surface::rest_decision(
				'restricted',
				'/reportedip-hive/v1/2fa/challenge',
				false,
				array(),
				false,
				\ReportedIP_Hive_Attack_Surface::ALWAYS_ALLOWED_NAMESPACES,
				array( 'administrator' )
			);
			$this->assertSame( 'allow', $decision );
		}

		public function test_rest_index_is_denied_for_guests(): void {
			$this->assertSame( 'deny_guest', $this->decide( 'logged_in', '/', false ) );
		}

		public function test_any_authenticated_user_passes_in_logged_in_mode(): void {
			$this->assertSame( 'allow', $this->decide( 'logged_in', '/wp/v2/posts', true, array( 'subscriber' ) ) );
		}

		public function test_unlisted_role_is_denied_in_restricted_mode(): void {
			$this->assertSame( 'deny_role', $this->decide( 'restricted', '/wp/v2/posts', true, array( 'editor' ) ) );
		}

		public function test_listed_role_passes_in_restricted_mode(): void {
			$this->assertSame( 'allow', $this->decide( 'restricted', '/wp/v2/posts', true, array( 'administrator' ) ) );
		}

		public function test_administrator_flag_always_passes(): void {
			$this->assertSame( 'allow', $this->decide( 'restricted', '/wp/v2/posts', true, array( 'shop_manager' ), true ) );
		}

		public function test_own_application_password_route_stays_reachable(): void {
			$this->assertSame( 'allow', $this->decide( 'restricted', '/wp/v2/users/me/application-passwords', true, array( 'subscriber' ) ) );
			$this->assertSame( 'allow', $this->decide( 'restricted', '/wp/v2/users/7/application-passwords', true, array( 'subscriber' ) ) );
		}

		public function test_route_matches_respects_segment_boundaries(): void {
			$this->assertTrue( \ReportedIP_Hive_Attack_Surface::route_matches( '/wc/store', 'wc/store' ) );
			$this->assertTrue( \ReportedIP_Hive_Attack_Surface::route_matches( '/wc/store/cart', 'wc/store' ) );
			$this->assertFalse( \ReportedIP_Hive_Attack_Surface::route_matches( '/wc/storefront/x', 'wc/store' ) );
			$this->assertFalse( \ReportedIP_Hive_Attack_Surface::route_matches( '/wp/v2/posts', '' ) );
		}

		public function test_allowed_namespaces_trims_slashes_and_blank_lines(): void {
			$GLOBALS['wp_options'] = array(
				'reportedip_hive_rest_allowed_namespaces' => "/oembed/1.0/\n\n  wc/store  \n",
			);

			$list = \ReportedIP_Hive_Attack_Surface::allowed_namespaces();

			$this->assertContains( 'oembed/1.0', $list );
			$this->assertContains( 'wc/store', $list );
			$this->assertContains( 'reportedip-hive/v1', $list );
			$this->assertNotContains( '', $list );
		}

		/**
		 * A dashboard that flattens a multi-line policy into one line must not
		 * collapse the allowlist into a single bogus namespace.
		 */
		public function test_allowed_namespaces_survive_a_flattened_list(): void {
			$GLOBALS['wp_options'] = array(
				'reportedip_hive_rest_allowed_namespaces' => 'oembed/1.0 wc/store, jetpack/v4',
			);

			$list = \ReportedIP_Hive_Attack_Surface::allowed_namespaces();

			$this->assertContains( 'oembed/1.0', $list );
			$this->assertContains( 'wc/store', $list );
			$this->assertContains( 'jetpack/v4', $list );
			$this->assertNotContains( 'oembed/1.0 wc/store, jetpack/v4', $list );
		}

		public function test_allowed_namespaces_fall_back_to_the_seeded_list(): void {
			$GLOBALS['wp_options'] = array();

			$list = \ReportedIP_Hive_Attack_Surface::allowed_namespaces();

			$this->assertSame(
				$this->seeded_namespaces(),
				$list,
				'A site whose option row was never seeded must still answer oEmbed, Store API and friends.'
			);
			$this->assertSame(
				'allow',
				\ReportedIP_Hive_Attack_Surface::rest_decision( 'logged_in', '/wc/store/cart', false, array(), false, $list, array( 'administrator' ) ),
				'The resolved fallback list has to keep the Store API open for anonymous shoppers.'
			);
		}

		public function test_default_allowlist_covers_every_rate_limit_bypass_namespace(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-rest-monitor.php' );

			$start = strpos( $source, 'private function is_route_bypassed' );
			$this->assertNotFalse( $start, 'is_route_bypassed() could not be located.' );
			$body = substr( $source, $start, (int) strpos( $source, 'apply_filters', $start ) - $start );

			preg_match_all( "#'(/[a-z0-9./-]+)'#i", $body, $matches );
			$this->assertNotEmpty( $matches[1], 'No bypass route literals found — the pin would be vacuous.' );

			$seeded = $this->seeded_namespaces();

			foreach ( $matches[1] as $route ) {
				$allowed = false;
				foreach ( $seeded as $prefix ) {
					if ( \ReportedIP_Hive_Attack_Surface::route_matches( $route, $prefix ) ) {
						$allowed = true;
						break;
					}
				}
				$this->assertTrue(
					$allowed,
					"REST_Monitor bypasses {$route} but the seeded namespace allowlist would deny it."
				);
			}
		}
	}
}
