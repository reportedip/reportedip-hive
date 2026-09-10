<?php
/**
 * Parity guard: every settings option is reachable from an admin surface, and
 * every stored option is a conscious decision about remote management.
 *
 * Two holes made this test necessary. Five registry keys were configurable from
 * MainWP and the cloud fleet but had no form anywhere in wp-admin, so a local
 * admin could not change them at all. And ninety `SAFE_OPTIONS` entries never
 * made it into the registry, which quietly kept whole feature blocks (the
 * security headers, the trusted-proxy pair, the sensor thresholds) out of
 * remote management and out of the sanitised import path.
 *
 * Neither hole was visible. The existing snapshot tests only lock what is
 * already registered, so an option that was never wired up looks exactly like
 * an option that does not exist.
 *
 * The check is a source scan rather than a behavioural test on purpose: it
 * costs nothing, is deterministic, and it also catches surfaces that do not
 * exist yet.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.51
 */

declare(strict_types=1);

namespace {
	require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-settings-registry.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-settings-effects.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-proxy-trust.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-waf.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-registration-guard.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-security-headers.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-frontend.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * Keeps the settings surface honest in both directions.
	 *
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class AdminSurfaceParityTest extends TestCase {

		/**
		 * Files that render or write settings for a human sitting in wp-admin.
		 *
		 * `admin/class-settings-import-export.php` is deliberately absent: it
		 * lists every option by definition, so including it would make the
		 * coverage assertion pass for everything and prove nothing.
		 *
		 * @var array<int, string>
		 */
		private const SURFACE_FILES = array(
			'admin/class-admin-settings.php',
			'admin/class-admin-firewall.php',
			'admin/class-two-factor-admin.php',
			'admin/class-setup-wizard.php',
			'admin/class-user-admin.php',
			'includes/class-ajax-handler.php',
			'includes/class-wizard-schema.php',
			'includes/class-two-factor-dashboard.php',
			'includes/class-two-factor-onboarding.php',
		);

		/**
		 * Registry keys with no wp-admin form, each one a known gap.
		 *
		 * Every entry here is remotely manageable but locally invisible, which
		 * is the wrong way round. The list is meant to reach zero; adding to it
		 * needs a reason at least as good as the ones below.
		 *
		 * @var array<string, string>
		 */
		private const NO_ADMIN_FORM = array();

		/**
		 * Stored options that must never become remotely manageable.
		 *
		 * @var array<string, string>
		 */
		private const NOT_REMOTE = array(
			'reportedip_hive_api_key'                    => 'Credential. A dashboard may provision it, never read or push it as a setting.',
			'reportedip_hive_cloud_management'           => 'The opt-in gate for remote management itself, so a fleet cannot grant itself access.',
			'reportedip_hive_delete_data_on_uninstall'   => 'Destructive. Nobody flips this from a remote form.',
			'reportedip_hive_operation_mode'             => 'Switching mode remotely can cut the site off from the transport carrying the change.',
			'reportedip_hive_api_endpoint'               => 'Pointing a site at another endpoint is a connection change, not a setting.',
			'reportedip_hive_access_cache_epoch'         => 'Runtime state: cache invalidation counter.',
			'reportedip_hive_cache_epoch'                => 'Runtime state: cache invalidation counter.',
			'reportedip_hive_rule_sync_last_run'         => 'Runtime state: last sync timestamp.',
			'reportedip_hive_ruleset_waf'                => 'Runtime state: synced ruleset payload.',
			'reportedip_hive_ruleset_bot_signatures'     => 'Runtime state: synced ruleset payload.',
			'reportedip_hive_ruleset_disposable_domains' => 'Runtime state: synced ruleset payload.',
			'reportedip_hive_ruleset_scan_paths'         => 'Runtime state: synced ruleset payload.',
			'reportedip_hive_ruleset_tor_exits'          => 'Runtime state: synced ruleset payload.',
			'reportedip_hive_2fa_frontend_soft_disabled' => 'Runtime state: set by the tier-downgrade lifecycle, not by an operator.',
			'reportedip_hive_form_proof_field'           => 'Runtime state: the per-site proof field name. A fleet-wide push of one name would defeat the point of it being per-site.',
			'reportedip_hive_form_proof_seen'            => 'Runtime state: when an anchor was last rendered. Measured, not configured.',
		);

		/**
		 * Stored options that belong in the registry and are not there yet.
		 *
		 * This list is the measured backlog, not a design decision. It may only
		 * ever shrink: a key that leaves it has become remotely manageable and
		 * passes through the sanitised apply path like every other setting.
		 *
		 * @var array<int, string>
		 */
		private const PENDING_REGISTRATION = array(
			'reportedip_hive_2fa_email_body_code',
			'reportedip_hive_2fa_email_subject',
			'reportedip_hive_2fa_email_subject_code',
			'reportedip_hive_2fa_password_reset_excluded_methods',
			'reportedip_hive_waf_dropin_enabled',
			'reportedip_hive_wc2fa_promo_enabled',
		);

		/**
		 * Every registry key is reachable from a form, a wizard step or an
		 * admin AJAX writer.
		 *
		 * @return void
		 */
		public function test_every_registry_key_has_an_admin_surface(): void {
			$sources = $this->surface_sources();
			$via_key = $this->keys_reachable_via_constant( $sources );
			$orphans = array();

			foreach ( array_keys( \ReportedIP_Hive_Settings_Registry::spec() ) as $key ) {
				if ( isset( self::NO_ADMIN_FORM[ $key ] ) ) {
					continue;
				}
				if ( $this->has_write_surface( $key, $sources ) ) {
					continue;
				}
				if ( isset( $via_key[ $key ] ) ) {
					continue;
				}
				$orphans[] = $key;
			}

			$this->assertSame(
				array(),
				$orphans,
				"These settings can be changed remotely but have no wp-admin form:\n" . implode( "\n", $orphans )
			);
		}

		/**
		 * The known-gap list only ever shrinks.
		 *
		 * A key that gained a form must leave the list, otherwise the list
		 * decays into a permanent excuse.
		 *
		 * @return void
		 */
		public function test_the_known_gap_list_holds_no_stale_entries(): void {
			$sources = $this->surface_sources();
			$via_key = $this->keys_reachable_via_constant( $sources );
			$stale   = array();

			foreach ( array_keys( self::NO_ADMIN_FORM ) as $key ) {
				if ( $this->has_write_surface( $key, $sources ) || isset( $via_key[ $key ] ) ) {
					$stale[] = $key;
				}
			}

			$this->assertSame(
				array(),
				$stale,
				"These keys have a form now and must leave NO_ADMIN_FORM:\n" . implode( "\n", $stale )
			);
		}

		/**
		 * Every stored option is either remotely manageable or explicitly not.
		 *
		 * A new option that lands in `SAFE_OPTIONS` without a registry entry
		 * fails here, which is the whole point: the backlog below grew because
		 * nothing ever asked the question.
		 *
		 * @return void
		 */
		public function test_every_stored_option_is_a_conscious_decision(): void {
			$registry  = \ReportedIP_Hive_Settings_Registry::spec();
			$undecided = array();

			foreach ( array_keys( \ReportedIP_Hive_Defaults::safe_options() ) as $key ) {
				if ( isset( $registry[ $key ] ) ) {
					continue;
				}
				if ( isset( self::NOT_REMOTE[ $key ] ) ) {
					continue;
				}
				if ( in_array( $key, self::PENDING_REGISTRATION, true ) ) {
					continue;
				}
				$undecided[] = $key;
			}

			$this->assertSame(
				array(),
				$undecided,
				"New stored options must either join the settings registry or be listed as deliberately local:\n" . implode( "\n", $undecided )
			);
		}

		/**
		 * The backlog holds no key that has since been registered.
		 *
		 * @return void
		 */
		public function test_the_backlog_holds_no_registered_keys(): void {
			$registry = \ReportedIP_Hive_Settings_Registry::spec();
			$done     = array();

			foreach ( self::PENDING_REGISTRATION as $key ) {
				if ( isset( $registry[ $key ] ) ) {
					$done[] = $key;
				}
			}

			$this->assertSame(
				array(),
				$done,
				"These keys are registered now and must leave PENDING_REGISTRATION:\n" . implode( "\n", $done )
			);
		}

		/**
		 * Whether an option key appears somewhere that can actually write it.
		 *
		 * Merely naming the key is not enough. The settings page also lists
		 * keys in read-only places, such as the protection-layer counter, and
		 * counting those as a form is how an option with no way to change it
		 * still passes.
		 *
		 * @param string $key     Option key.
		 * @param string $sources Concatenated surface source.
		 * @return bool
		 */
		private function has_write_surface( $key, $sources ): bool {
			$quoted = preg_quote( $key, '/' );

			$patterns = array(
				'/name="' . $quoted . '"/',
				'/register_setting\(\s*\n?\s*\'[a-z_]+\',\s*\n?\s*\'' . $quoted . '\'/',
				'/\'option\'\s*=> \'' . $quoted . '\'/',
				'/data-opt="\' \. esc_attr\( \'' . $quoted . '\'/',
				'/render_select_row\(\s*\n?\s*\'[a-z0-9-]+\',\s*\n?\s*\'' . $quoted . '\'/',
				'/render_switch_row\(\s*\n?\s*\'' . $quoted . '\'/',
			);

			foreach ( $patterns as $pattern ) {
				if ( preg_match( $pattern, $sources ) ) {
					return true;
				}
			}

			return false;
		}

		/**
		 * Concatenated source of every admin surface file.
		 *
		 * @return string
		 */
		private function surface_sources(): string {
			$root   = dirname( __DIR__, 2 );
			$source = '';

			foreach ( self::SURFACE_FILES as $relative ) {
				$path = $root . '/' . $relative;
				$this->assertFileExists( $path, 'The surface list has drifted from the code.' );
				$source .= (string) file_get_contents( $path );
			}

			return $source;
		}

		/**
		 * Option keys that the surfaces reference through a class constant.
		 *
		 * The admin markup writes `ReportedIP_Hive_WAF::OPT_PARANOIA` far more
		 * often than the literal key, so a scan looking only for literals
		 * reports dozens of false gaps.
		 *
		 * @param string $sources Concatenated surface source.
		 * @return array<string, string> Option key => constant token.
		 */
		private function keys_reachable_via_constant( $sources ): array {
			$root      = dirname( __DIR__, 2 );
			$files     = array_merge( (array) glob( $root . '/includes/*.php' ), (array) glob( $root . '/admin/*.php' ) );
			$reachable = array();

			foreach ( $files as $file ) {
				$declared = (string) file_get_contents( $file );
				if ( ! preg_match_all( '/const\s+([A-Z0-9_]+)\s*=\s*\'(reportedip_hive_[a-z0-9_]+)\'/', $declared, $matches, PREG_SET_ORDER ) ) {
					continue;
				}

				foreach ( $matches as $match ) {
					if ( false !== strpos( $sources, '::' . $match[1] ) ) {
						$reachable[ $match[2] ] = $match[1];
					}
				}
			}

			return $reachable;
		}
	}
}
