<?php
/**
 * The audit trail's filter, export and gate stay wired to the registry.
 *
 * A type that is recorded but missing from the filter drop-down is invisible
 * to the reader who needs it. Since 2.1.62 the filter, the badges and the
 * sentences come from the audit registry, the export shares the table's
 * WHERE clause, and the public `record()` wrapper keeps the plan, opt-out
 * and trigger-group gate of the automatic listeners.
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

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class AuditLogTableFiltersTest extends TestCase {

		/**
		 * Read one source file from the plugin.
		 *
		 * @param string $relative Path relative to the plugin root.
		 * @return string
		 */
		private function source( string $relative ): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/' . $relative );
		}

		public function test_filter_badges_and_sentences_come_from_the_registry(): void {
			$source = $this->source( 'admin/class-audit-log-table.php' );

			$this->assertStringContainsString( 'ReportedIP_Hive_Audit_Registry::filter_options()', $source );
			$this->assertStringContainsString( 'ReportedIP_Hive_Audit_Registry::expand_filter_value(', $source );
			$this->assertStringContainsString( 'ReportedIP_Hive_Audit_Registry::badge(', $source );
			$this->assertStringContainsString( 'ReportedIP_Hive_Audit_Registry::label(', $source );
			$this->assertStringContainsString( 'ReportedIP_Hive_Audit_Registry::summary(', $source );
			$this->assertStringNotContainsString( "'user_block'     => __(", $source, 'no hand-written type list next to the registry' );
		}

		public function test_export_shares_the_table_query_builder(): void {
			$admin = $this->source( 'admin/class-admin-settings.php' );
			$body  = substr( $admin, (int) strpos( $admin, 'public function handle_audit_export(' ) );
			$body  = substr( $body, 0, (int) strpos( $body, 'fclose(' ) );

			$this->assertStringContainsString( 'ReportedIP_Hive_Audit_Log_Table::build_where(', $body );
			$this->assertStringContainsString( 'ReportedIP_Hive_Audit_Log_Table::filter_args()', $body );
			$this->assertStringContainsString( "feature_status( 'audit_log' )", $body, 'the handler keeps its own plan gate' );
			foreach ( array( 'object_type', 'object_id', 'object_label', 'summary' ) as $column ) {
				$this->assertStringContainsString( "'{$column}'", $body, "export column {$column}" );
			}
		}

		public function test_site_admin_is_scoped_to_the_current_blog_only(): void {
			$source = $this->source( 'admin/class-audit-log-table.php' );
			$body   = substr( $source, (int) strpos( $source, 'public static function build_where(' ) );
			$body   = substr( $body, 0, (int) strpos( $body, 'public function prepare_items(' ) );

			$this->assertStringContainsString( 'is_multisite() && ! is_network_admin()', $body );
			$this->assertStringContainsString( "'blog_id = %d'", $body );
			$this->assertStringNotContainsString( 'IN (%d, 0)', $body, 'network rows belong to the Network Admin' );
			$this->assertStringContainsString( "'blog_id = 0'", $body, 'the network filter selects the network rows' );
		}

		public function test_site_admin_page_reuses_the_table_and_its_scope(): void {
			$admin = $this->source( 'admin/class-admin-settings.php' );
			$body  = substr( $admin, (int) strpos( $admin, 'public function render_site_audit_page(' ) );
			$body  = substr( $body, 0, (int) strpos( $body, 'public function render_site_2fa_settings_page(' ) );

			$this->assertStringContainsString( "feature_status( 'audit_log' )", $body );
			$this->assertStringContainsString( 'new ReportedIP_Hive_Audit_Log_Table()', $body );
			$this->assertStringContainsString( "'page' => 'reportedip-hive-site-audit'", $body );
		}

		/**
		 * The public wrapper must keep the plan and opt-out gate the automatic
		 * listeners have, plus the trigger group; `log_event()` stays private.
		 */
		public function test_record_wrapper_keeps_the_gate(): void {
			$source = $this->source( 'includes/class-audit-logger.php' );
			$body   = substr( $source, (int) strpos( $source, 'public function record(' ) );
			$body   = substr( $body, 0, (int) strpos( $body, 'private function record_actor_event(' ) );

			$this->assertStringContainsString( 'self::is_enabled()', $body );
			$this->assertStringContainsString( 'ReportedIP_Hive_Audit_Registry::group_enabled(', $body );
			$this->assertStringContainsString( 'private function log_event(', $source );

			$enabled = substr( $source, (int) strpos( $source, 'public static function is_enabled(' ) );
			$enabled = substr( $enabled, 0, (int) strpos( $enabled, 'public function register_hooks(' ) );
			$this->assertStringContainsString( 'self::is_available()', $enabled );
			$this->assertStringContainsString( 'reportedip_hive_audit_enabled', $enabled );
		}

		public function test_sample_rows_render_without_the_database(): void {
			$source = $this->source( 'admin/class-admin-settings.php' );
			$body   = substr( $source, (int) strpos( $source, 'private function render_audit_upsell(' ) );
			$body   = substr( $body, 0, (int) strpos( $body, 'sample_items()' ) );

			$this->assertStringNotContainsString( 'prepare_items()', $body, 'the locked tab must not query the trail' );
			$this->assertStringContainsString( 'pricing_url()', $body );
		}
	}
}
