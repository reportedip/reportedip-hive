<?php
/**
 * Unit Tests for the security event taxonomy.
 *
 * Validates the event_type → family mapping that drives every dashboard
 * visualisation: threshold-suffix stripping, operational events resolving to
 * null, the ordered family list and the threat-event-type IN() helper. Pure
 * logic — no database.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.13
 */

namespace {

	if ( ! function_exists( '__' ) ) {
		function __( $text, $domain = 'default' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return $text;
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-event-taxonomy.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class EventTaxonomyTest extends TestCase {

		public function test_base_event_types_map_to_families() {
			$expected = array(
				'failed_login'        => 'login',
				'2fa_brute_force'     => 'login',
				'waf_block'           => 'firewall',
				'waf_would_block'     => 'firewall',
				'scan_404'            => 'scanner',
				'decoy_pathblock_hit' => 'scanner',
				'fake_bot'            => 'bot',
				'user_enumeration'    => 'recon',
				'rest_abuse'          => 'recon',
				'comment_spam'        => 'spam',
				'xmlrpc_abuse'        => 'spam',
				'geo_anomaly'         => 'anomaly',
			);
			foreach ( $expected as $event => $family ) {
				$this->assertSame(
					$family,
					\ReportedIP_Hive_Event_Taxonomy::classify( $event ),
					"Event $event must map to family $family"
				);
			}
		}

		public function test_threshold_suffix_is_stripped_before_lookup() {
			$this->assertSame( 'login', \ReportedIP_Hive_Event_Taxonomy::classify( 'failed_login_threshold_exceeded' ) );
			$this->assertSame( 'recon', \ReportedIP_Hive_Event_Taxonomy::classify( 'rest_abuse_threshold_exceeded' ) );
			$this->assertSame( 'scanner', \ReportedIP_Hive_Event_Taxonomy::classify( 'scan_404_threshold_exceeded' ) );
		}

		public function test_operational_events_are_not_threats() {
			$operational = array(
				'would_block_ip',
				'block_skipped_whitelist',
				'ip_blocked',
				'api_report_queued',
				'local_event_detected',
				'categories_cached',
				'hardening_mode_deactivated',
				'2fa_reset_challenge_sent',
				'totally_unknown_event',
			);
			foreach ( $operational as $event ) {
				$this->assertNull(
					\ReportedIP_Hive_Event_Taxonomy::classify( $event ),
					"Operational event $event must not resolve to a threat family"
				);
			}
		}

		public function test_families_are_ordered_and_labelled() {
			$families = \ReportedIP_Hive_Event_Taxonomy::labels();
			$this->assertSame(
				array( 'login', 'firewall', 'scanner', 'bot', 'recon', 'spam', 'anomaly' ),
				array_keys( $families )
			);
			foreach ( $families as $key => $label ) {
				$this->assertNotEmpty( $label, "Family $key must have a non-empty label" );
			}
		}

		public function test_threat_event_types_include_base_and_threshold_variants() {
			$types = \ReportedIP_Hive_Event_Taxonomy::threat_event_types();
			$this->assertContains( 'failed_login', $types );
			$this->assertContains( 'failed_login_threshold_exceeded', $types );
			$this->assertContains( 'waf_block', $types );
			$this->assertSame( $types, array_values( array_unique( $types ) ), 'Threat-type list must be free of duplicates' );
		}
	}
}
