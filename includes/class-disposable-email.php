<?php
/**
 * Disposable-email registration sensor.
 *
 * Inspects the e-mail address on user registration against the
 * `disposable_domains` ruleset (bundled baseline,
 * free; the live multi-thousand-domain list arrives via Priority Sync). A
 * throwaway-mail domain is logged and, when the operator opts into blocking.
 * rejected with a registration error. Privacy relays (Apple Hide My Email,
 * Firefox Relay, SimpleLogin, Addy.io) are a distinct, legitimate category and
 * pass through unless the operator explicitly opts into blocking them.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.2
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Disposable-email and privacy-relay classifier for registrations and,
 * since 2.1.72, comments and protected third-party forms.
 *
 * @since 2.1.2
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
	 * Action taken on a throwaway address in a comment or a protected
	 * third-party form: off | monitor | block.
	 */
	const OPT_FORMS_ACTION = 'reportedip_hive_disposable_email_forms';

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
	 * @since  2.1.2
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Private constructor: the registration surfaces belong to
	 * {@see ReportedIP_Hive_Registration_Guard}, which calls
	 * {@see evaluate()} as the last step of its pipeline so an operator's own
	 * e-mail allow rule can overrule the throwaway list.
	 *
	 * @since 2.1.2
	 */
	private function __construct() {
	}

	/**
	 * Whether the sensor is active (action not off, feature available).
	 *
	 * @return bool
	 * @since  2.1.2
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
	 * @since  2.1.2
	 */
	public function action() {
		return self::read_action( self::OPT_ACTION, 'monitor' );
	}

	/**
	 * A stored action, or the fallback when it is not one of the three.
	 *
	 * @param string $option   Option key.
	 * @param string $fallback Action used for a missing or unknown value.
	 * @return string off | monitor | block.
	 * @since  2.1.72
	 */
	private static function read_action( $option, $fallback ) {
		$action = (string) ReportedIP_Hive_Option_Routing::get( $option, $fallback );
		return in_array( $action, array( 'off', 'monitor', 'block' ), true ) ? $action : $fallback;
	}

	/**
	 * Apply the configured action to a submitted e-mail address: log a throwaway
	 * (and, unless the operator allows them, a relay), and add a registration
	 * error when blocking.
	 *
	 * Public since 2.1.51: the registration guard owns the hooks and calls
	 * this as the last pipeline step.
	 *
	 * @param string   $email  Submitted e-mail address.
	 * @param WP_Error $errors Errors object to add to when blocking.
	 * @return void
	 * @since  2.1.2
	 */
	public function evaluate( $email, WP_Error $errors ) {
		if ( ! $this->is_enabled() ) {
			return;
		}
		$category = $this->classify_address( $email );
		if ( 'clean' === $category ) {
			return;
		}

		$action = $this->action();
		$this->log( self::domain_of( $email ), $category, $action, 'register' );

		if ( 'block' === $action ) {
			$errors->add( 'reportedip_hive_disposable_email', self::refusal() );
		}
	}

	/**
	 * The configured action for comments and protected forms.
	 *
	 * @return string off | monitor | block.
	 * @since  2.1.72
	 */
	public function forms_action() {
		return self::read_action( self::OPT_FORMS_ACTION, 'block' );
	}

	/**
	 * Check the addresses of a comment or form submission.
	 *
	 * Logs the first throwaway (or, when relays are blocked, relay) address
	 * and returns the refusal the sender sees while the action is `block`.
	 *
	 * @param string   $surface Surface identifier (`comment`, adapter slug).
	 * @param string[] $emails  Addresses found in the submission.
	 * @return string Refusal message, or an empty string to proceed.
	 * @since  2.1.72
	 */
	public function check_submission( $surface, array $emails ) {
		$action = $this->forms_action();
		if ( 'off' === $action || array() === $emails ) {
			return '';
		}

		foreach ( $emails as $email ) {
			$category = $this->classify_address( (string) $email );
			if ( 'clean' === $category ) {
				continue;
			}
			$this->log( self::domain_of( (string) $email ), $category, $action, (string) $surface );
			return 'block' === $action ? self::refusal() : '';
		}

		return '';
	}

	/**
	 * Every distinct e-mail address among the scalar values of a submission.
	 * Pure apart from `is_email()`; recurses into nested field arrays, so it
	 * reads every form plugin without knowing its field names.
	 *
	 * @param array<mixed> $values Submitted values, typically `$_POST`.
	 * @return string[]
	 * @since  2.1.72
	 */
	public static function emails_in( array $values ) {
		$found = array();
		array_walk_recursive(
			$values,
			static function ( $value ) use ( &$found ) {
				$value = is_string( $value ) ? strtolower( trim( $value ) ) : '';
				if ( is_email( $value ) ) {
					$found[ $value ] = $value;
				}
			}
		);
		return array_values( $found );
	}

	/**
	 * Classify one address, honouring the relay switch: a relay counts as
	 * clean unless the operator blocks relays.
	 *
	 * @param string $email E-mail address.
	 * @return string `disposable` | `relay` | `clean`.
	 * @since  2.1.72
	 */
	public function classify_address( $email ) {
		$domain = self::domain_of( $email );
		if ( '' === $domain ) {
			return 'clean';
		}
		$category = self::classify_domain( $domain, $this->get_disposable_rules() );
		if ( 'relay' === $category && ! ReportedIP_Hive_Option_Routing::get( self::OPT_BLOCK_RELAYS, false ) ) {
			return 'clean';
		}
		return $category;
	}

	/**
	 * The sentence a refused sender sees.
	 *
	 * @return string
	 * @since  2.1.72
	 */
	public static function refusal() {
		return __( 'Please use a permanent e-mail address. Disposable-mail providers are not accepted.', 'reportedip-hive' );
	}

	/**
	 * Write the `disposable_email` event.
	 *
	 * @param string $domain   Matched domain.
	 * @param string $category `disposable` or `relay`.
	 * @param string $action   Configured action.
	 * @param string $surface  Where the address was submitted.
	 * @return void
	 * @since  2.1.72
	 */
	private function log( $domain, $category, $action, $surface ) {
		if ( ! class_exists( 'ReportedIP_Hive' ) ) {
			return;
		}
		$logger = ReportedIP_Hive::get_instance()->get_logger();
		if ( $logger instanceof ReportedIP_Hive_Logger ) {
			$logger->log_security_event(
				'disposable_email',
				ReportedIP_Hive::get_client_ip(),
				array(
					'domain'   => $domain,
					'category' => $category,
					'action'   => $action,
					'surface'  => $surface,
				),
				'low'
			);
		}
	}

	/**
	 * Resolve the active disposable-domain rules from the synced ruleset (or the
	 * bundled baseline).
	 *
	 * @return array<int,mixed>
	 * @since  2.1.2
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
	 * @since  2.1.2
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
	 * @since  2.1.2
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
	 * @since  2.1.2
	 */
	private static function is_subdomain_of( $domain, $base ) {
		$suffix = '.' . $base;
		return substr( $domain, -strlen( $suffix ) ) === $suffix;
	}
}
