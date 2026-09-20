<?php
/**
 * Unit Tests for the security event taxonomy.
 *
 * Validates the registry that drives every dashboard visualisation and the
 * activity filter: threshold-suffix stripping, registered operational events
 * resolving to null, unregistered ones falling into `other`, the ordered family
 * list, the threat-event-type IN() helper and the grouped filter options. Pure
 * logic, no database.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
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
				'failed_login'                    => 'login',
				'2fa_brute_force'                 => 'login',
				'unknown_username_probe'          => 'login',
				'blocked_user_denied'             => 'login',
				'waf_block'                       => 'firewall',
				'waf_would_block'                 => 'firewall',
				'scan_404'                        => 'scanner',
				'decoy_pathblock_hit'             => 'scanner',
				'fake_bot'                        => 'bot',
				'user_enumeration'                => 'recon',
				'rest_abuse'                      => 'recon',
				'rest_denied'                     => 'recon',
				'xmlrpc_denied'                   => 'recon',
				'admin_guest_denied'              => 'recon',
				'feed_denied'                     => 'recon',
				'hide_login_block'                => 'recon',
				'comment_spam'                    => 'spam',
				'comment_honeypot'                => 'spam',
				'xmlrpc_abuse'                    => 'spam',
				'prohibited_username'             => 'spam',
				'registration_denied'             => 'spam',
				'registration_limit'              => 'spam',
				'geo_anomaly_detected'            => 'anomaly',
				'blocked_by_reputation'           => 'anomaly',
				'blocked_by_tor_exit'             => 'anomaly',
				'2fa_webauthn_counter_regression' => 'anomaly',
			);
			foreach ( $expected as $event => $family ) {
				$this->assertSame(
					$family,
					\ReportedIP_Hive_Event_Taxonomy::classify( $event ),
					"Event $event must map to family $family"
				);
			}
		}

		/**
		 * Form spam reaches the charts on two slugs: the per-hit proof failure
		 * and the generated threshold event of the adapters. Before 2.1.62 the
		 * base type `form_spam` was missing from the map, so every adapter
		 * threshold hit was dropped from both dashboard cards.
		 */
		public function test_form_spam_lands_in_the_spam_family() {
			$this->assertSame( 'spam', \ReportedIP_Hive_Event_Taxonomy::classify( 'form_proof_failed' ) );
			$this->assertSame( 'spam', \ReportedIP_Hive_Event_Taxonomy::classify( 'form_spam_threshold_exceeded' ) );
			$this->assertSame( 'spam', \ReportedIP_Hive_Event_Taxonomy::classify( 'comment_spam_threshold_exceeded' ) );
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
				'2fa_stepup_required',
				'2fa_stepup_skipped_no_method',
				'successful_login',
				'xmlrpc_call',
			);
			foreach ( $operational as $event ) {
				$this->assertNull(
					\ReportedIP_Hive_Event_Taxonomy::classify( $event ),
					"Operational event $event must not resolve to a threat family"
				);
			}
		}

		/**
		 * A sensor whose slug nobody registered still has to show up somewhere,
		 * otherwise it is invisible in exactly the way form spam was.
		 */
		public function test_unregistered_events_fall_into_other() {
			$this->assertSame( 'other', \ReportedIP_Hive_Event_Taxonomy::classify( 'totally_unknown_event' ) );
			$this->assertSame( 'other', \ReportedIP_Hive_Event_Taxonomy::classify( 'totally_unknown_event_threshold_exceeded' ) );
			$this->assertFalse( \ReportedIP_Hive_Event_Taxonomy::is_registered( 'totally_unknown_event' ) );
			$this->assertTrue( \ReportedIP_Hive_Event_Taxonomy::is_registered( 'form_spam_threshold_exceeded' ) );
		}

		public function test_families_are_ordered_and_labelled() {
			$families = \ReportedIP_Hive_Event_Taxonomy::labels();
			$this->assertSame(
				array( 'login', 'firewall', 'scanner', 'bot', 'recon', 'spam', 'anomaly', 'other' ),
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
			$this->assertContains( 'form_spam_threshold_exceeded', $types );
			$this->assertSame( $types, array_values( array_unique( $types ) ), 'Threat-type list must be free of duplicates' );
		}

		/**
		 * The IN() clause selects attack rows; bookkeeping must stay out or the
		 * top-attacker table starts ranking the site's own cron.
		 */
		public function test_threat_event_types_exclude_operational_rows() {
			$types = \ReportedIP_Hive_Event_Taxonomy::threat_event_types();
			foreach ( array( 'api_error', 'cache_hit', 'ip_whitelisted', 'would_block_ip' ) as $operational ) {
				$this->assertNotContains( $operational, $types );
			}
		}

		public function test_labels_decorate_threshold_variants() {
			$base      = \ReportedIP_Hive_Event_Taxonomy::label( 'scan_404' );
			$threshold = \ReportedIP_Hive_Event_Taxonomy::label( 'scan_404_threshold_exceeded' );

			$this->assertNotEmpty( $base );
			$this->assertNotSame( $base, $threshold );
			$this->assertStringContainsString( $base, $threshold );
			$this->assertSame( 'Totally Unknown Event', \ReportedIP_Hive_Event_Taxonomy::label( 'totally_unknown_event' ) );
		}

		/**
		 * Every registry row belongs to a declared group, and the filter offers
		 * the threshold variant exactly when the bare slug is never written.
		 */
		public function test_filter_options_cover_every_registry_row() {
			$groups  = \ReportedIP_Hive_Event_Taxonomy::filter_options();
			$offered = array();
			foreach ( $groups as $group => $options ) {
				$this->assertArrayHasKey(
					$group,
					\ReportedIP_Hive_Event_Taxonomy::group_labels(),
					"Filter group $group has no label"
				);
				foreach ( $options as $slug => $label ) {
					$this->assertNotEmpty( $label, "Option $slug must have a label" );
					$offered[] = $slug;
				}
			}

			$this->assertContains( 'form_proof_failed', $offered );
			$this->assertContains( 'form_spam_threshold_exceeded', $offered );
			$this->assertContains( 'comment_honeypot', $offered );
			$this->assertContains( 'blocked_by_reputation', $offered );
			$this->assertContains( 'geo_anomaly_detected', $offered );
			$this->assertNotContains( 'form_spam', $offered, 'The bare slug is never written, offering it returns an empty result set' );
			$this->assertContains( 'comment_spam', $offered );
			$this->assertContains( 'comment_spam_threshold_exceeded', $offered );
			$this->assertSame( $offered, array_values( array_unique( $offered ) ) );
		}
	}
}
