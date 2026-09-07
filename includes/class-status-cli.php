<?php
/**
 * WP-CLI command for a plugin status overview.
 *
 * Available as `wp reportedip status` once WP-CLI sees the plugin:
 * flattens version, operation mode, tier, protection counters, queue
 * summary and the key protection toggles into a field/value table
 * (or json/csv/yaml via --format).
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.50
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	return;
}

class ReportedIP_Hive_Status_CLI {

	/**
	 * Register the class as a WP-CLI command.
	 *
	 * @return void
	 */
	public static function register() {
		WP_CLI::add_command( 'reportedip status', __CLASS__ );
	}

	/**
	 * Show a status overview of the protection stack.
	 *
	 * Covers version, operation mode and tier, report-only state,
	 * block/whitelist counters, the report queue and the main
	 * protection toggles (hide-login, firewall, extended protection
	 * guard, enforced 2FA roles).
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Render output in a particular format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp reportedip status
	 *     wp reportedip status --format=json
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function __invoke( $args, $assoc_args ) {
		unset( $args );

		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';

		$database   = ReportedIP_Hive_Database::get_instance();
		$mode       = ReportedIP_Hive_Mode_Manager::get_instance();
		$hide_login = ReportedIP_Hive_Hide_Login::get_instance();
		$dropin     = ReportedIP_Hive_WAF_Dropin_Manager::get_instance();
		$queue      = $database->get_queue_summary();

		$enforce_roles = ReportedIP_Hive_Option_Routing::get_network_enforce_roles();

		$rows = array(
			array(
				'field' => 'version',
				'value' => REPORTEDIP_HIVE_VERSION,
			),
			array(
				'field' => 'mode',
				'value' => (string) $mode->get_mode(),
			),
			array(
				'field' => 'tier',
				'value' => (string) $mode->get_current_tier(),
			),
			array(
				'field' => 'report_only',
				'value' => $this->format_value( (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_only_mode', false ) ),
			),
			array(
				'field' => 'active_blocks',
				'value' => (string) $database->count_blocked_ips(),
			),
			array(
				'field' => 'whitelist_entries',
				'value' => (string) $database->count_whitelisted_ips(),
			),
			array(
				'field' => 'queue_pending',
				'value' => (string) (int) $queue['total_pending'],
			),
			array(
				'field' => 'queue_failed',
				'value' => (string) (int) $queue['failed'],
			),
			array(
				'field' => 'queue_oldest',
				'value' => $this->format_value( $queue['oldest_date'] ),
			),
			array(
				'field' => 'hide_login',
				'value' => $hide_login->is_active() ? $hide_login->get_slug() : 'off',
			),
			array(
				'field' => 'firewall',
				'value' => $this->format_value( ReportedIP_Hive_WAF::get_instance()->is_enabled() ),
			),
			array(
				'field' => 'guard_active',
				'value' => $this->format_value( $dropin->is_active() ),
			),
			array(
				'field' => 'guard_queue_writable',
				'value' => $this->format_value( $dropin->queue_is_writable() ),
			),
			array(
				'field' => 'issues',
				'value' => $this->format_value( $this->readiness_summary() ),
			),
			array(
				'field' => '2fa_enforced_roles',
				'value' => empty( $enforce_roles ) ? '-' : implode( ', ', $enforce_roles ),
			),
		);

		\WP_CLI\Utils\format_items( $format, $rows, array( 'field', 'value' ) );
	}

	/**
	 * Open readiness issues as `key (severity)`, comma separated.
	 *
	 * Raw English on purpose: WP-CLI output is machine-readable plumbing and
	 * stays out of the translation catalogue.
	 *
	 * @return string
	 */
	private function readiness_summary() {
		$parts = array();
		foreach ( ReportedIP_Hive_Readiness::open_issues( true ) as $issue ) {
			$parts[] = $issue['key'] . ' (' . $issue['severity'] . ')';
		}

		return implode( ', ', $parts );
	}

	/**
	 * Normalise a value for the field/value listing.
	 *
	 * Booleans become yes/no, null/empty becomes the '-' placeholder,
	 * everything else is cast to string.
	 *
	 * @param mixed $value Raw value.
	 * @return string
	 */
	private function format_value( $value ) {
		if ( is_bool( $value ) ) {
			return $value ? 'yes' : 'no';
		}

		if ( null === $value || '' === $value ) {
			return '-';
		}

		return (string) $value;
	}
}

ReportedIP_Hive_Status_CLI::register();
