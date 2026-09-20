<?php
/**
 * The audit registry is the one list of trigger groups and audit events.
 *
 * Every `type/action` pair the logger or a connector writes must have a
 * registry row, or the trail shows a humanised slug with no group, no badge
 * and no filter option. Every registry row must have a writer, or the filter
 * offers an option that never matches. The trigger groups feed the Protection
 * page, so their defaults and the option default must agree.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.62
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-audit-registry.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';

	/**
	 * @covers \ReportedIP_Hive_Audit_Registry
	 */
	class AuditRegistryTest extends TestCase {

		/**
		 * Sources that write audit rows: the logger and every connector.
		 *
		 * @return string
		 */
		private function writer_sources(): string {
			$root  = dirname( __DIR__, 2 );
			$files = array_merge(
				array(
					$root . '/includes/class-audit-logger.php',
					$root . '/includes/class-user-block.php',
					$root . '/admin/class-user-admin.php',
				),
				glob( $root . '/includes/audit/*.php' ) ?: array()
			);
			$body  = '';
			foreach ( $files as $file ) {
				$body .= (string) file_get_contents( $file ) . "\n";
			}
			return $body;
		}

		/**
		 * Every literal `type`, `action` pair passed to a logging call.
		 *
		 * @return string[] `type/action` keys.
		 */
		private function written_pairs(): array {
			$sources = $this->writer_sources();
			preg_match_all(
				'/(?:->record|->log_event|->log|->record_actor_event|->log_simple|->log_plugin)\(\s*\'([a-z_]+)\'\s*,\s*\'([a-z_]+)\'/s',
				$sources,
				$pairs,
				PREG_SET_ORDER
			);
			$keys = array();
			foreach ( $pairs as $pair ) {
				$keys[] = $pair[1] . '/' . $pair[2];
			}
			return array_values( array_unique( $keys ) );
		}

		public function test_every_group_has_events_and_every_event_a_group(): void {
			$groups = \ReportedIP_Hive_Audit_Registry::groups();
			$events = \ReportedIP_Hive_Audit_Registry::events();

			$this->assertSame( \ReportedIP_Hive_Audit_Registry::group_slugs(), array_keys( $groups ) );

			$used = array();
			foreach ( $events as $key => $row ) {
				$this->assertArrayHasKey( $row['group'], $groups, "{$key} points at an unknown group." );
				$this->assertContains( $row['badge'], array( 'success', 'warning', 'danger', 'info', 'neutral' ), $key );
				$this->assertNotSame( '', $row['label'], $key );
				$used[ $row['group'] ] = true;
			}
			foreach ( array_keys( $groups ) as $slug ) {
				$this->assertArrayHasKey( $slug, $used, "Group {$slug} has no events." );
			}
		}

		public function test_default_groups_match_the_option_default(): void {
			$stored = \ReportedIP_Hive_Defaults::all_option_defaults()[ \ReportedIP_Hive_Audit_Registry::OPTION_TRIGGERS ];
			$this->assertSame( \ReportedIP_Hive_Audit_Registry::default_groups(), json_decode( $stored, true ) );
			$this->assertNotContains( 'logins', \ReportedIP_Hive_Audit_Registry::default_groups(), 'Sign-ins are the loudest rows and stay off by default.' );
		}

		public function test_filter_groups_drops_unknown_slugs(): void {
			$this->assertSame( array( 'users', 'content' ), \ReportedIP_Hive_Audit_Registry::filter_groups( array( 'users', 'bogus', 'content', 'users' ) ) );
			$this->assertSame( array(), \ReportedIP_Hive_Audit_Registry::filter_groups( array() ) );
		}

		public function test_every_written_pair_is_registered(): void {
			$events = \ReportedIP_Hive_Audit_Registry::events();
			$pairs  = $this->written_pairs();
			$this->assertNotEmpty( $pairs, 'The writer scan found no logging calls; the regex is stale.' );
			foreach ( $pairs as $key ) {
				$this->assertArrayHasKey( $key, $events, "'{$key}' is written but has no registry row." );
			}
		}

		/**
		 * Actions that reach the table through a variable, not a literal.
		 *
		 * @return array<string, string> Key to the code that produces it.
		 */
		private function dynamic_pairs(): array {
			return array(
				'login/success'                   => 'on_login() picks success or new_ip',
				'login/new_ip'                    => 'on_login() picks success or new_ip',
				'profile_change/updated'          => 'on_profile_update() picks the action',
				'profile_change/email_changed'    => 'on_profile_update() picks the action',
				'profile_change/password_changed' => 'on_profile_update() picks the action',
				'content/published'               => 'Content::classify() returns the action',
				'content/unpublished'             => 'Content::classify() returns the action',
				'content/trashed'                 => 'on_trashed() passes the action',
				'content/untrashed'               => 'on_untrashed() passes the action',
				'plugin/installed'                => 'from_hook_extra() returns type and action',
				'plugin/updated'                  => 'from_hook_extra() returns type and action',
				'plugin/activated'                => 'on_activated() passes the action',
				'plugin/deactivated'              => 'on_deactivated() passes the action',
				'theme/installed'                 => 'from_hook_extra() returns type and action',
				'theme/updated'                   => 'from_hook_extra() returns type and action',
				'widget/added'                    => 'diff_sidebars() returns the action',
				'widget/removed'                  => 'diff_sidebars() returns the action',
			);
		}

		public function test_every_registered_event_has_a_writer(): void {
			$written = $this->written_pairs();
			$dynamic = $this->dynamic_pairs();
			$sources = $this->writer_sources();
			foreach ( array_keys( \ReportedIP_Hive_Audit_Registry::events() ) as $key ) {
				if ( in_array( $key, $written, true ) ) {
					continue;
				}
				$this->assertArrayHasKey( $key, $dynamic, "'{$key}' is offered in the filter but nothing writes it." );
				list( $type, $action ) = explode( '/', $key );
				$this->assertStringContainsString( "'{$type}'", $sources, "'{$key}': the type literal is gone from the writers." );
				$this->assertStringContainsString( "'{$action}'", $sources, "'{$key}': the action literal is gone from the writers." );
			}
		}

		public function test_expand_filter_value_selects_a_group_or_one_key(): void {
			$this->assertSame( array( 'plugin/deactivated' ), \ReportedIP_Hive_Audit_Registry::expand_filter_value( 'plugin/deactivated' ) );
			$this->assertSame( array( 'nonsense' ), \ReportedIP_Hive_Audit_Registry::expand_filter_value( 'nonsense' ) );
			$this->assertSame( array( 'group:nonsense' ), \ReportedIP_Hive_Audit_Registry::expand_filter_value( 'group:nonsense' ) );

			$editor = \ReportedIP_Hive_Audit_Registry::expand_filter_value( 'group:editor' );
			$this->assertSame( array( 'file/edited' ), $editor );

			$installer = \ReportedIP_Hive_Audit_Registry::expand_filter_value( 'group:installer' );
			$this->assertContains( 'plugin/deactivated', $installer );
			$this->assertContains( 'core/updated', $installer );
			$this->assertNotContains( 'file/edited', $installer );
		}

		public function test_summary_reads_old_and_new_from_the_row(): void {
			$row = (object) array(
				'event_type'   => 'setting',
				'event_action' => 'updated',
				'object_label' => 'Permalink structure',
				'event_data'   => json_encode(
					array(
						'old' => '/%postname%/',
						'new' => '/%year%/%postname%/',
					)
				),
			);
			$summary = \ReportedIP_Hive_Audit_Registry::summary( $row );
			$this->assertStringContainsString( 'Permalink structure', $summary );
			$this->assertStringContainsString( '/%postname%/', $summary );
			$this->assertStringContainsString( '/%year%/%postname%/', $summary );

			$plain = (object) array(
				'event_type'   => 'plugin',
				'event_action' => 'deactivated',
				'object_label' => 'WooCommerce',
				'event_data'   => json_encode( array( 'slug' => 'woocommerce/woocommerce.php' ) ),
			);
			$this->assertSame( 'WooCommerce', \ReportedIP_Hive_Audit_Registry::summary( $plain ) );
		}

		public function test_label_and_badge_fall_back_for_unknown_pairs(): void {
			$this->assertSame( 'Plugin deactivated', \ReportedIP_Hive_Audit_Registry::label( 'plugin', 'deactivated' ) );
			$this->assertSame( 'warning', \ReportedIP_Hive_Audit_Registry::badge( 'plugin', 'deactivated' ) );
			$this->assertSame( 'Foo Bar', \ReportedIP_Hive_Audit_Registry::label( 'foo', 'bar' ) );
			$this->assertSame( 'info', \ReportedIP_Hive_Audit_Registry::badge( 'foo', 'bar' ) );
		}

		public function test_core_option_whitelist_holds_no_secret_and_no_churn(): void {
			$options = array_keys( \ReportedIP_Hive_Audit_Registry::core_options() );
			foreach ( array( 'mailserver_pass', 'mailserver_login', 'cron', 'rewrite_rules', 'active_plugins', 'template', 'stylesheet' ) as $never ) {
				$this->assertNotContains( $never, $options );
			}
			foreach ( array( 'siteurl', 'home', 'permalink_structure', 'blog_public', 'page_on_front', 'admin_email' ) as $must ) {
				$this->assertContains( $must, $options );
			}
		}
	}
}
