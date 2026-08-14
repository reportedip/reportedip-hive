<?php
/**
 * WP-CLI command for one-off IP lookups.
 *
 * Available as `wp reportedip lookup <ip>` once WP-CLI sees the plugin:
 * flattens `ReportedIP_Hive_IP_Manager::get_ip_info()` into a field/value
 * table (or json/csv/yaml via --format).
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.41
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	return;
}

class ReportedIP_Hive_Lookup_CLI {

	/**
	 * Register the class as a WP-CLI command.
	 *
	 * @return void
	 */
	public static function register() {
		WP_CLI::add_command( 'reportedip lookup', __CLASS__ );
	}

	/**
	 * Look up local status and community reputation for an IP address.
	 *
	 * When Community mode is configured, an uncached lookup spends one
	 * check-quota call against the reportedip.com API.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : The IP address to look up (IPv4 or IPv6).
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
	 *     # Look up an address as a table
	 *     wp reportedip lookup 203.0.113.9
	 *
	 *     # Machine-readable output
	 *     wp reportedip lookup 203.0.113.9 --format=json
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function __invoke( $args, $assoc_args ) {
		$ip = isset( $args[0] ) ? (string) $args[0] : '';

		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			WP_CLI::error( 'Invalid IP address: ' . $ip );
		}

		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';

		$info       = ReportedIP_Hive_IP_Manager::get_instance()->get_ip_info( $ip );
		$reputation = isset( $info['reputation'] ) && is_array( $info['reputation'] ) ? $info['reputation'] : array();

		$rows = array(
			array(
				'field' => 'ip',
				'value' => $this->format_value( $info['ip_address'] ?? $ip ),
			),
			array(
				'field' => 'valid',
				'value' => $this->format_value( $info['is_valid'] ?? null ),
			),
			array(
				'field' => 'private',
				'value' => $this->format_value( $info['is_private'] ?? null ),
			),
			array(
				'field' => 'version',
				'value' => $this->format_value( $info['ip_version'] ?? null ),
			),
			array(
				'field' => 'blocked',
				'value' => $this->format_value( $info['is_blocked'] ?? null ),
			),
			array(
				'field' => 'whitelisted',
				'value' => $this->format_value( $info['is_whitelisted'] ?? null ),
			),
			array(
				'field' => 'country',
				'value' => $this->format_value( $info['country'] ?? null ),
			),
			array(
				'field' => 'asn',
				'value' => $this->format_value( $info['asn'] ?? null ),
			),
			array(
				'field' => 'isp',
				'value' => $this->format_value( $info['isp'] ?? null ),
			),
			array(
				'field' => 'confidence',
				'value' => $this->format_value( $reputation['abuseConfidencePercentage'] ?? null ),
			),
			array(
				'field' => 'total_reports',
				'value' => $this->format_value( $reputation['totalReports'] ?? null ),
			),
			array(
				'field' => 'is_tor',
				'value' => $this->format_value( $reputation['isTor'] ?? null ),
			),
			array(
				'field' => 'last_reported',
				'value' => $this->format_value( $reputation['lastReportedAt'] ?? null ),
			),
		);

		\WP_CLI\Utils\format_items( $format, $rows, array( 'field', 'value' ) );
	}

	/**
	 * Normalise a value for the field/value listing.
	 *
	 * Booleans become yes/no, null/empty becomes the '-' placeholder,
	 * everything else is cast to string.
	 *
	 * @param mixed $value Raw value from the info array.
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

ReportedIP_Hive_Lookup_CLI::register();
