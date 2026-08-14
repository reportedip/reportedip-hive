<?php
/**
 * Trusted-proxy source validation for client IP resolution.
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

/**
 * Decides whether the connecting peer (REMOTE_ADDR) is a proxy the site
 * operator has declared trustworthy, and therefore whether the configured
 * client-IP header may be honored at all.
 *
 * Without a source check, anyone who connects directly to the site can spoof
 * the trusted header and impersonate a whitelisted IP (or shed a blocked
 * identity). The same range list is baked into the pre-WordPress guard so
 * both WAF layers resolve the client IP identically.
 *
 * Pure static and dependency-free apart from the CIDR matcher, so the unit
 * suite can exercise the full behavior matrix against the stub harness.
 *
 * @since 2.1.41
 */
final class ReportedIP_Hive_Proxy_Trust {

	/**
	 * Parse a raw textarea value into a clean list of IP/CIDR range strings.
	 *
	 * Accepts one entry per line; blank lines and `#` comment lines are
	 * skipped; entries that are neither a valid IP nor a valid CIDR range
	 * are dropped silently (the sanitizer reports them at save time).
	 *
	 * @param string $raw Raw option value (newline-separated entries).
	 * @return string[] Valid IP/CIDR strings, de-duplicated, order preserved.
	 * @since  2.1.41
	 */
	public static function parse_ranges( $raw ) {
		$ranges = array();

		foreach ( preg_split( '/\r\n|\r|\n/', (string) $raw ) as $line ) {
			$line = trim( $line );
			if ( '' === $line || 0 === strpos( $line, '#' ) ) {
				continue;
			}
			if ( ! self::is_valid_entry( $line ) ) {
				continue;
			}
			if ( ! in_array( $line, $ranges, true ) ) {
				$ranges[] = $line;
			}
		}

		return $ranges;
	}

	/**
	 * Whether the connecting peer is allowed to supply the client-IP header.
	 *
	 * An empty range list means every peer is trusted — that is the
	 * pre-2.1.41 behavior and keeps existing configurations working.
	 *
	 * @param string   $remote_addr Connecting peer address (REMOTE_ADDR).
	 * @param string[] $ranges      Parsed IP/CIDR range list.
	 * @return bool True when the header may be honored.
	 * @since  2.1.41
	 */
	public static function source_is_trusted( $remote_addr, array $ranges ) {
		if ( empty( $ranges ) ) {
			return true;
		}

		if ( ! filter_var( $remote_addr, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		foreach ( $ranges as $range ) {
			if ( false === strpos( $range, '/' ) ) {
				if ( $remote_addr === $range ) {
					return true;
				}
				continue;
			}
			if ( ReportedIP_Hive_Database::ip_in_cidr( $remote_addr, $range ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Validate a single entry as either a bare IP or a CIDR range with a
	 * plausible mask (0-32 for IPv4, 0-128 for IPv6).
	 *
	 * @param string $entry Candidate entry.
	 * @return bool
	 * @since  2.1.41
	 */
	private static function is_valid_entry( $entry ) {
		if ( false === strpos( $entry, '/' ) ) {
			return false !== filter_var( $entry, FILTER_VALIDATE_IP );
		}

		list( $addr, $mask ) = array_pad( explode( '/', $entry, 2 ), 2, '' );
		if ( false === filter_var( $addr, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		if ( ! preg_match( '/^\d{1,3}$/', $mask ) ) {
			return false;
		}

		$max = false !== strpos( $addr, ':' ) ? 128 : 32;
		return (int) $mask <= $max;
	}
}
