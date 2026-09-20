<?php
/**
 * Base class of the audit connectors.
 *
 * A connector is a list of WordPress hooks plus one callback per hook. It
 * knows nothing about the table; every row goes through
 * {@see ReportedIP_Hive_Audit_Logger::record()}, which applies the tier and
 * opt-out gate. The helpers here are the shared noise controls: who acted
 * and through which agent, how a value is stored, and how a hook that fires
 * several times per request is collapsed into one row.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.62
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hook list plus callbacks; subclasses own one trigger group each.
 *
 * @since 2.1.62
 */
abstract class ReportedIP_Hive_Audit_Connector {

	/**
	 * Rows written in this request, keyed by dedupe key.
	 *
	 * @var array<string, true>
	 */
	private static $seen = array();

	/**
	 * Request-wide suppression flags, keyed by name.
	 *
	 * @var array<string, true>
	 */
	private static $suppressed = array();

	/**
	 * Hooks this connector listens to.
	 *
	 * @return array<string, array{0:string, 1:int, 2:int}> Hook name to method, priority, accepted args.
	 * @since  2.1.62
	 */
	abstract protected function hooks();

	/**
	 * Attach every hook of {@see hooks()}.
	 *
	 * @return void
	 * @since  2.1.62
	 */
	public function register() {
		foreach ( $this->hooks() as $hook => $spec ) {
			add_action( $hook, array( $this, $spec[0] ), $spec[1], $spec[2] );
		}
	}

	/**
	 * Write one row through the logger.
	 *
	 * @param string              $type    Event type.
	 * @param string              $action  Event action.
	 * @param array<string,mixed> $data    Structured data; `agent` is added here.
	 * @param array<string,mixed> $object  `type`, `id`, `label` of the affected object.
	 * @param int|null            $blog_id Explicit scope, 0 for network rows, null for the current site.
	 * @return void
	 * @since  2.1.62
	 */
	protected function log( $type, $action, array $data, array $object = array(), $blog_id = null ) {
		$data['agent'] = self::agent();
		$user          = wp_get_current_user();

		ReportedIP_Hive_Audit_Logger::get_instance()->record( $type, $action, $data, (int) $user->ID, (string) $user->user_login, $object, $blog_id );
	}

	/**
	 * How the current request reached WordPress.
	 *
	 * @return string One of `cli`, `cron`, `xmlrpc`, `rest`, `ajax`, `web`.
	 * @since  2.1.62
	 */
	public static function agent() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return 'cli';
		}
		if ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) {
			return 'cron';
		}
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return 'xmlrpc';
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return 'rest';
		}
		if ( function_exists( 'wp_doing_ajax' ) && wp_doing_ajax() ) {
			return 'ajax';
		}
		return 'web';
	}

	/**
	 * Storage form of a changed value.
	 *
	 * Scalars are cut to {@see ReportedIP_Hive_Audit_Registry::VALUE_MAX_LENGTH};
	 * a list becomes its own added/removed diff against the other side, so a
	 * long list is never truncated into something that reads wrong.
	 *
	 * @param mixed $value Value to store.
	 * @param mixed $other The other side of the change, for list diffs.
	 * @return mixed
	 * @since  2.1.62
	 */
	public static function value_for_row( $value, $other = null ) {
		if ( is_array( $value ) ) {
			$other = is_array( $other ) ? $other : array();
			$mine  = array_map( 'strval', self::flatten( $value ) );
			$their = array_map( 'strval', self::flatten( $other ) );
			return array(
				'added'   => array_values( array_diff( $mine, $their ) ),
				'removed' => array_values( array_diff( $their, $mine ) ),
			);
		}
		if ( null === $value || false === $value ) {
			return '';
		}
		if ( true === $value ) {
			return '1';
		}
		$value = (string) $value;
		if ( function_exists( 'mb_substr' ) ) {
			return mb_substr( $value, 0, ReportedIP_Hive_Audit_Registry::VALUE_MAX_LENGTH );
		}
		return substr( $value, 0, ReportedIP_Hive_Audit_Registry::VALUE_MAX_LENGTH );
	}

	/**
	 * Flatten a nested array into `key=value` strings for a diff.
	 *
	 * @param array<mixed> $value  Array.
	 * @param string       $prefix Key prefix for nesting.
	 * @return string[]
	 * @since  2.1.62
	 */
	private static function flatten( array $value, $prefix = '' ) {
		$out = array();
		foreach ( $value as $key => $item ) {
			$path = '' === $prefix ? (string) $key : $prefix . '.' . $key;
			if ( is_array( $item ) ) {
				$out = array_merge( $out, self::flatten( $item, $path ) );
			} else {
				$out[] = $path . '=' . ( is_bool( $item ) ? ( $item ? '1' : '0' ) : (string) $item );
			}
		}
		return $out;
	}

	/**
	 * Whether this key was already written in the current request.
	 *
	 * Marks the key on the first call. Callers put everything that makes the
	 * row distinct into the key, including a hash of the diff, so a second
	 * genuine change in the same request is not swallowed.
	 *
	 * @param string $key Dedupe key.
	 * @return bool True when already seen.
	 * @since  2.1.62
	 */
	public static function seen( $key ) {
		if ( isset( self::$seen[ $key ] ) ) {
			return true;
		}
		self::$seen[ $key ] = true;
		return false;
	}

	/**
	 * Silence a named capture for the rest of the request.
	 *
	 * Used where one core action fires a second one the trail would otherwise
	 * report twice: `add_user_to_blog()` fires `set_user_role`, and
	 * `wpmu_delete_user()` fires `deleted_user`.
	 *
	 * @param string $name Flag name.
	 * @return void
	 * @since  2.1.62
	 */
	public static function suppress( $name ) {
		self::$suppressed[ $name ] = true;
	}

	/**
	 * Whether a named capture is silenced.
	 *
	 * @param string $name Flag name.
	 * @return bool
	 * @since  2.1.62
	 */
	public static function suppressed( $name ) {
		return isset( self::$suppressed[ $name ] );
	}

	/**
	 * Reset request state; for tests.
	 *
	 * @return void
	 * @since  2.1.62
	 */
	public static function reset_request_state() {
		self::$seen       = array();
		self::$suppressed = array();
	}
}
