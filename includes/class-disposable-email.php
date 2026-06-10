<?php
/**
 * Disposable-email registration sensor.
 *
 * Inspects the e-mail address on user registration (WordPress core and
 * WooCommerce) against the `disposable_domains` ruleset (bundled baseline,
 * free; the live multi-thousand-domain list arrives via Priority Sync). A
 * throwaway-mail domain is logged and — when the operator opts into blocking —
 * rejected with a registration error. Privacy relays (Apple Hide My Email,
 * Firefox Relay, SimpleLogin, Addy.io) are a distinct, legitimate category and
 * pass through unless the operator explicitly opts into blocking them.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Registration-time disposable-email and privacy-relay classifier.
 *
 * @since 2.2.0
 */
class ReportedIP_Hive_Disposable_Email {

	/**
	 * Action taken on a throwaway address: off | monitor | block.
	 */
	const OPT_ACTION = 'reportedip_hive_disposable_email_action';

	/**
	 * Whether privacy relays are blocked alongside throwaway domains.
	 */
	const OPT_BLOCK_RELAYS = 'reportedip_hive_block_email_relays';

	/**
	 * Known privacy-relay domains. These are legitimate forwarding services, not
	 * throwaway mail; they pass through unless {@see OPT_BLOCK_RELAYS} is on. The
	 * baked-in set is a safety net even when the synced list omits the `relay`
	 * classification.
	 *
	 * @var string[]
	 */
	const RELAY_DOMAINS = array(
		'privaterelay.appleid.com',
		'mozmail.com',
		'relay.firefox.com',
		'simplelogin.com',
		'simplelogin.io',
		'aleeas.com',
		'slmail.me',
		'anonaddy.com',
		'anonaddy.me',
		'addy.io',
		'4wrd.cc',
		'duck.com',
	);

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Disposable_Email|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return ReportedIP_Hive_Disposable_Email
	 * @since  2.2.0
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Hook the WordPress and WooCommerce registration validation points.
	 *
	 * @since 2.2.0
	 */
	private function __construct() {
		add_filter( 'registration_errors', array( $this, 'on_registration_errors' ), 10, 3 );
		add_action( 'woocommerce_register_post', array( $this, 'on_woocommerce_register' ), 10, 3 );
	}

	/**
	 * Validate a core WordPress registration.
	 *
	 * @param WP_Error $errors Existing registration errors.
	 * @param string   $login  Sanitised user login (unused).
	 * @param string   $email  Submitted e-mail address.
	 * @return WP_Error
	 * @since  2.2.0
	 */
	public function on_registration_errors( $errors, $login, $email ) {
		if ( $errors instanceof WP_Error ) {
			$this->evaluate( (string) $email, $errors );
		}
		return $errors;
	}

	/**
	 * Validate a WooCommerce registration. The validation errors object is
	 * passed by handle, so adding to it rejects the registration.
	 *
	 * @param string   $username Submitted username (unused).
	 * @param string   $email    Submitted e-mail address.
	 * @param WP_Error $errors   WooCommerce validation errors.
	 * @return void
	 * @since  2.2.0
	 */
	public function on_woocommerce_register( $username, $email, $errors ) {
		if ( $errors instanceof WP_Error ) {
			$this->evaluate( (string) $email, $errors );
		}
	}

	/**
	 * Whether the sensor is active (action not off, feature available).
	 *
	 * @return bool
	 * @since  2.2.0
	 */
	public function is_enabled() {
		if ( 'off' === $this->action() ) {
			return false;
		}
		if ( class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			$status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'disposable_email' );
			if ( empty( $status['available'] ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * The configured action: off | monitor | block.
	 *
	 * @return string
	 * @since  2.2.0
	 */
	public function action() {
		$action = (string) ReportedIP_Hive_Option_Routing::get( self::OPT_ACTION, 'monitor' );
		return in_array( $action, array( 'off', 'monitor', 'block' ), true ) ? $action : 'monitor';
	}

	/**
	 * Apply the configured action to a submitted e-mail address: log a throwaway
	 * (and, unless the operator allows them, a relay), and add a registration
	 * error when blocking.
	 *
	 * @param string   $email  Submitted e-mail address.
	 * @param WP_Error $errors Errors object to add to when blocking.
	 * @return void
	 * @since  2.2.0
	 */
	private function evaluate( $email, WP_Error $errors ) {
		if ( ! $this->is_enabled() ) {
			return;
		}
		$domain = self::domain_of( $email );
		if ( '' === $domain ) {
			return;
		}

		$category = self::classify_domain( $domain, $this->get_disposable_rules() );
		if ( 'clean' === $category ) {
			return;
		}
		if ( 'relay' === $category && ! ReportedIP_Hive_Option_Routing::get( self::OPT_BLOCK_RELAYS, false ) ) {
			return;
		}

		$action = $this->action();
		$ip     = class_exists( 'ReportedIP_Hive' ) ? ReportedIP_Hive::get_client_ip() : '';

		if ( class_exists( 'ReportedIP_Hive' ) ) {
			$logger = ReportedIP_Hive::get_instance()->get_logger();
			if ( $logger instanceof ReportedIP_Hive_Logger ) {
				$logger->log_security_event(
					'disposable_email',
					$ip,
					array(
						'domain'   => $domain,
						'category' => $category,
						'action'   => $action,
					),
					'low'
				);
			}
		}

		if ( 'block' === $action ) {
			$errors->add(
				'reportedip_hive_disposable_email',
				__( 'Please use a permanent e-mail address. Disposable-mail providers are not accepted.', 'reportedip-hive' )
			);
		}
	}

	/**
	 * Resolve the active disposable-domain rules from the synced ruleset (or the
	 * bundled baseline).
	 *
	 * @return array<int,mixed>
	 * @since  2.2.0
	 */
	public function get_disposable_rules() {
		if ( ! class_exists( 'ReportedIP_Hive_Rule_Sync' ) ) {
			return array();
		}
		$ruleset = ReportedIP_Hive_Rule_Sync::get_instance()->get_ruleset( 'disposable_domains' );
		return isset( $ruleset['rules'] ) && is_array( $ruleset['rules'] ) ? $ruleset['rules'] : array();
	}

	/**
	 * Extract the lower-cased domain part of an e-mail address.
	 *
	 * @param string $email E-mail address.
	 * @return string Domain, or empty string when none.
	 * @since  2.2.0
	 */
	public static function domain_of( $email ) {
		$email = strtolower( trim( (string) $email ) );
		$at    = strrpos( $email, '@' );
		if ( false === $at ) {
			return '';
		}
		return substr( $email, $at + 1 );
	}

	/**
	 * Classify a domain as `disposable`, `relay` or `clean`. Pure: the rule list
	 * is supplied, so it is deterministically unit-testable. Rules may be plain
	 * domain strings (baseline) or `{domain, category}` arrays (the synced list
	 * tags privacy relays as `relay`).
	 *
	 * @param string           $domain Lower-cased domain.
	 * @param array<int,mixed> $rules  Disposable-domain rules.
	 * @return string `disposable` | `relay` | `clean`.
	 * @since  2.2.0
	 */
	public static function classify_domain( $domain, array $rules ) {
		$domain = strtolower( trim( (string) $domain ) );
		if ( '' === $domain ) {
			return 'clean';
		}

		foreach ( self::RELAY_DOMAINS as $relay ) {
			if ( $domain === $relay || self::is_subdomain_of( $domain, $relay ) ) {
				return 'relay';
			}
		}

		foreach ( $rules as $rule ) {
			if ( is_string( $rule ) ) {
				$candidate = strtolower( $rule );
				$category  = 'disposable';
			} elseif ( is_array( $rule ) && ! empty( $rule['domain'] ) ) {
				$candidate = strtolower( (string) $rule['domain'] );
				$category  = isset( $rule['category'] ) ? (string) $rule['category'] : 'disposable';
			} else {
				continue;
			}
			if ( $domain === $candidate || self::is_subdomain_of( $domain, $candidate ) ) {
				return 'relay' === $category ? 'relay' : 'disposable';
			}
		}

		return 'clean';
	}

	/**
	 * Whether `$domain` is a subdomain of `$base` (label-boundary aware so
	 * `notmailinator.com` does not match `mailinator.com`).
	 *
	 * @param string $domain Candidate domain.
	 * @param string $base   Base domain.
	 * @return bool
	 * @since  2.2.0
	 */
	private static function is_subdomain_of( $domain, $base ) {
		$suffix = '.' . $base;
		return substr( $domain, -strlen( $suffix ) ) === $suffix;
	}
}
