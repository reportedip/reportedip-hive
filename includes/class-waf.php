<?php
/**
 * Request-inspecting web application firewall engine.
 *
 * Evaluates the inbound request (URI, query, body, user-agent) against the
 * active `waf` ruleset — the bundled Paranoia-Level-1 baseline (free on every
 * plan) plus, on Professional tiers, the deeper server-delivered ruleset from
 * {@see ReportedIP_Hive_Rule_Sync}. The engine is ReDoS-hardened (bounded
 * PCRE backtracking, fail-open on a pattern that errors), short-circuits on the
 * first hit and is whitelisted-IP / privileged-user aware so it cannot lock an
 * administrator out of their own site.
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
 * WAF request-inspection engine.
 *
 * @since 2.2.0
 */
class ReportedIP_Hive_WAF {

	/**
	 * Master enable toggle option.
	 */
	const OPT_ENABLED = 'reportedip_hive_waf_enabled';

	/**
	 * Report-only toggle option (log a match, never block).
	 */
	const OPT_REPORT_ONLY = 'reportedip_hive_waf_report_only';

	/**
	 * Maximum Paranoia Level the operator opted into (clamped by tier).
	 */
	const OPT_PARANOIA = 'reportedip_hive_waf_paranoia';

	/**
	 * Number of confirmed hits within the window before the IP is laddered.
	 */
	const OPT_BLOCK_THRESHOLD = 'reportedip_hive_waf_block_threshold';

	/**
	 * Drop-in (pre-WordPress execution) master toggle.
	 */
	const OPT_DROPIN_ENABLED = 'reportedip_hive_waf_dropin_enabled';

	/**
	 * Last resolved guard path for the drop-in.
	 */
	const OPT_DROPIN_PATH = 'reportedip_hive_waf_dropin_path';

	/**
	 * Last detected server type for the drop-in.
	 */
	const OPT_DROPIN_SERVER = 'reportedip_hive_waf_dropin_server';

	/**
	 * Counting window (minutes) for the repeat-offender escalation ladder.
	 */
	const ESCALATION_TIMEFRAME_MINUTES = 10;

	/**
	 * Hard cap on bytes scanned from the request body, so a multi-megabyte
	 * upload cannot turn rule evaluation into a denial-of-service vector.
	 */
	const MAX_BODY_BYTES = 65536;

	/**
	 * Hard cap on a single inspection subject, after assembly.
	 */
	const MAX_SUBJECT_BYTES = 131072;

	/**
	 * PCRE backtracking ceiling applied during matching to bound worst-case
	 * pattern cost (catastrophic backtracking yields a skip, not a hang).
	 */
	const PCRE_BACKTRACK_LIMIT = 100000;

	/**
	 * Maps a rule group to the {@see ReportedIP_Hive_Block_Ref} reason key.
	 */
	const GROUP_REASON = array(
		'sql_injection'  => 'waf_sqli',
		'xss'            => 'waf_xss',
		'path_traversal' => 'waf_traversal',
		'cmd_injection'  => 'waf_cmd',
		'file_probe'     => 'waf_file',
		'scanner_ua'     => 'waf_scanner',
	);

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_WAF|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return ReportedIP_Hive_WAF
	 * @since  2.2.0
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Wire the inspection hook. Priority 1 mirrors the IP-block gate so a
	 * malicious request is rejected before other plugins' `init` handlers run.
	 *
	 * @since 2.2.0
	 */
	private function __construct() {
		add_action( 'init', array( $this, 'inspect' ), 1 );
	}

	/**
	 * Inspect the current request and block (or log) the first rule hit.
	 *
	 * @return void
	 * @since  2.2.0
	 */
	public function inspect() {
		/*
		 * Exempt cron, WP-CLI and the authenticated back office. wp-admin and
		 * admin-ajax (both `is_admin()` at this hook) are backend contexts whose
		 * payloads come from already-authenticated users; inspecting them only
		 * manufactures false positives. REST_REQUEST is not yet defined at
		 * `init` priority 1, so back-office detection rests on is_admin().
		 */
		if ( wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) || is_admin() ) {
			return;
		}
		if ( ! ReportedIP_Hive_Option_Routing::get( self::OPT_ENABLED, true ) ) {
			return;
		}
		if ( ! class_exists( 'ReportedIP_Hive' ) ) {
			return;
		}

		/*
		 * Content authors — editors, authors, contributors, including multisite
		 * editors who lack `unfiltered_html` — legitimately submit markup and
		 * code through the block-editor REST saves and the classic editor. They
		 * are exempt; the WAF targets the external, unauthenticated front-end
		 * attack surface.
		 */
		if ( is_user_logged_in() && current_user_can( 'edit_posts' ) ) {
			return;
		}

		$ip = ReportedIP_Hive::get_client_ip();
		if ( '' === $ip || 'unknown' === $ip ) {
			return;
		}

		$ip_manager = class_exists( 'ReportedIP_Hive_IP_Manager' )
			? ReportedIP_Hive_IP_Manager::get_instance()
			: null;
		if ( $ip_manager && method_exists( $ip_manager, 'is_whitelisted' ) && $ip_manager->is_whitelisted( $ip ) ) {
			return;
		}

		$rules = $this->get_active_rules();
		if ( empty( $rules ) ) {
			return;
		}

		$raw_body = file_get_contents( 'php://input', false, null, 0, self::MAX_BODY_BYTES );
		$hit      = $this->evaluate(
			$rules,
			wp_unslash( $_SERVER ), // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- wp_unslash applied; raw attack surface inspected verbatim, never echoed.
			wp_unslash( $_POST ),   // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Raw attack surface inspected before any handler; nonce belongs to the real handler.
			is_string( $raw_body ) ? $raw_body : null
		);

		if ( null !== $hit ) {
			$this->handle_hit( $hit, $ip );
		}
	}

	/**
	 * Pure detection core: test the supplied request data against the supplied
	 * rules and return the first matching rule, or null. Takes the request data
	 * as arguments (no superglobal or WordPress access) so it is deterministically
	 * unit-testable and reusable. ReDoS is bounded by a temporary PCRE
	 * backtrack-limit that is always restored.
	 *
	 * @param array<int,array<string,mixed>> $rules    Active rules.
	 * @param array<string,mixed>            $server   Request server vars (e.g. $_SERVER), unslashed.
	 * @param array<string,mixed>            $post     Request body params (e.g. $_POST), unslashed.
	 * @param string|null                    $raw_body Raw request body for non-form payloads, or null.
	 * @return array<string,mixed>|null The matched rule, or null when nothing matches.
	 * @since  2.2.0
	 */
	public function evaluate( array $rules, array $server, array $post, $raw_body ) {
		if ( empty( $rules ) ) {
			return null;
		}

		$subjects = $this->collect_subjects( $this->required_targets( $rules ), $server, $post, $raw_body );
		if ( empty( $subjects ) ) {
			return null;
		}

		$previous_limit = ini_get( 'pcre.backtrack_limit' );
		if ( false !== $previous_limit ) {
			ini_set( 'pcre.backtrack_limit', (string) self::PCRE_BACKTRACK_LIMIT ); // phpcs:ignore WordPress.PHP.IniSet.Risky -- Bounding PCRE backtracking is a deliberate ReDoS mitigation, restored below.
		}

		$hit = null;
		foreach ( $rules as $rule ) {
			if ( ! is_array( $rule ) || empty( $rule['pattern'] ) ) {
				continue;
			}
			$target  = isset( $rule['target'] ) ? (string) $rule['target'] : 'all';
			$subject = isset( $subjects[ $target ] ) ? $subjects[ $target ] : '';
			if ( '' === $subject ) {
				continue;
			}
			if ( $this->matches( (string) $rule['pattern'], $subject ) ) {
				$hit = $rule;
				break;
			}
		}

		if ( false !== $previous_limit ) {
			ini_set( 'pcre.backtrack_limit', (string) $previous_limit ); // phpcs:ignore WordPress.PHP.IniSet.Risky -- Restoring the previous PCRE backtrack limit.
		}

		return $hit;
	}

	/**
	 * Resolve the active, tier-clamped rule list.
	 *
	 * The bundled baseline is Paranoia Level 1 only; deeper levels arrive in the
	 * synced ruleset and are honoured only while the Professional Priority-Sync
	 * feature is available, so a downgrade silently falls back to the free floor.
	 *
	 * @return array<int,array<string,mixed>>
	 * @since  2.2.0
	 */
	public function get_active_rules() {
		if ( ! class_exists( 'ReportedIP_Hive_Rule_Sync' ) ) {
			return array();
		}
		$ruleset = ReportedIP_Hive_Rule_Sync::get_instance()->get_ruleset( 'waf' );
		$rules   = isset( $ruleset['rules'] ) && is_array( $ruleset['rules'] ) ? $ruleset['rules'] : array();
		if ( empty( $rules ) ) {
			return array();
		}

		$max_pl = $this->paranoia_cap();
		$active = array();
		foreach ( $rules as $rule ) {
			if ( ! is_array( $rule ) || empty( $rule['pattern'] ) ) {
				continue;
			}
			$pl = isset( $rule['paranoia'] ) ? (int) $rule['paranoia'] : 1;
			if ( $pl > $max_pl ) {
				continue;
			}
			$active[] = $rule;
		}
		return $active;
	}

	/**
	 * The effective Paranoia-Level ceiling for the current tier.
	 *
	 * Free tiers are pinned to Level 1; Professional unlocks the operator-chosen
	 * level (2 or 3) carried in the synced ruleset.
	 *
	 * @return int 1, 2 or 3.
	 * @since  2.2.0
	 */
	public function paranoia_cap() {
		$priority_available = false;
		if ( class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			$status             = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'rule_sync_priority' );
			$priority_available = ! empty( $status['available'] );
		}
		if ( ! $priority_available ) {
			return 1;
		}
		$chosen = (int) ReportedIP_Hive_Option_Routing::get( self::OPT_PARANOIA, 1 );
		return max( 1, min( 3, $chosen ) );
	}

	/**
	 * Whether the engine is enabled (display helper for the admin surface).
	 *
	 * @return bool
	 * @since  2.2.0
	 */
	public function is_enabled() {
		return (bool) ReportedIP_Hive_Option_Routing::get( self::OPT_ENABLED, true );
	}

	/**
	 * Whether report-only mode is active (engine logs, never blocks).
	 *
	 * @return bool
	 * @since  2.2.0
	 */
	public function is_report_only() {
		if ( ReportedIP_Hive_Option_Routing::get( self::OPT_REPORT_ONLY, false ) ) {
			return true;
		}
		return (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_only_mode', false );
	}

	/**
	 * Count of rules active under the current tier (display helper).
	 *
	 * @return int
	 * @since  2.2.0
	 */
	public function active_rule_count() {
		return count( $this->get_active_rules() );
	}

	/**
	 * Determine which inspection subjects the active rules actually need, so the
	 * engine never assembles a body payload no rule will read.
	 *
	 * @param array<int,array<string,mixed>> $rules Active rules.
	 * @return array<string,bool> Keyed by target name.
	 * @since  2.2.0
	 */
	private function required_targets( array $rules ) {
		$needed = array();
		foreach ( $rules as $rule ) {
			$target            = isset( $rule['target'] ) ? (string) $rule['target'] : 'all';
			$needed[ $target ] = true;
		}
		return $needed;
	}

	/**
	 * Assemble the inspection subjects for the required targets only.
	 *
	 * @param array<string,bool> $targets Required target map.
	 * @return array<string,string>
	 * @since  2.2.0
	 */
	private function collect_subjects( array $targets, array $server, array $post, $raw_body ) {
		$want_uri  = isset( $targets['uri'] ) || isset( $targets['all'] );
		$want_body = isset( $targets['body'] ) || isset( $targets['all'] );
		$want_ua   = isset( $targets['ua'] ) || isset( $targets['all'] );

		$uri  = $want_uri ? $this->uri_subject( $server ) : '';
		$body = $want_body ? $this->body_subject( $post, $raw_body ) : '';
		$ua   = $want_ua ? $this->ua_subject( $server ) : '';

		$subjects = array();
		if ( isset( $targets['uri'] ) ) {
			$subjects['uri'] = $uri;
		}
		if ( isset( $targets['body'] ) ) {
			$subjects['body'] = $body;
		}
		if ( isset( $targets['ua'] ) ) {
			$subjects['ua'] = $ua;
		}
		if ( isset( $targets['all'] ) ) {
			$subjects['all'] = $this->cap( $uri . "\n" . $body . "\n" . $ua );
		}
		return $subjects;
	}

	/**
	 * Build the URI subject: the raw request target plus a once-decoded variant
	 * so both `../` and `%2e%2e` style payloads are visible to a single pattern.
	 *
	 * @param array<string,mixed> $server Unslashed server vars.
	 * @return string
	 * @since  2.2.0
	 */
	private function uri_subject( array $server ) {
		$raw = isset( $server['REQUEST_URI'] ) ? (string) $server['REQUEST_URI'] : '';
		if ( '' === $raw ) {
			return '';
		}
		$decoded = rawurldecode( $raw );
		return $this->cap( $raw === $decoded ? $raw : $raw . "\n" . $decoded );
	}

	/**
	 * Build the body subject from the parsed parameters and the raw input
	 * stream (for JSON / non-form bodies), bounded to {@see MAX_BODY_BYTES}.
	 *
	 * @param array<string,mixed> $post     Unslashed body params.
	 * @param string|null         $raw_body Raw request body, or null.
	 * @return string
	 * @since  2.2.0
	 */
	private function body_subject( array $post, $raw_body ) {
		$parts = array();
		if ( ! empty( $post ) ) {
			$parts[] = $this->flatten( $post );
		}
		if ( is_string( $raw_body ) && '' !== $raw_body ) {
			$parts[] = substr( $raw_body, 0, self::MAX_BODY_BYTES );
		}
		if ( empty( $parts ) ) {
			return '';
		}
		return $this->cap( implode( "\n", $parts ) );
	}

	/**
	 * Build the user-agent subject.
	 *
	 * @param array<string,mixed> $server Unslashed server vars.
	 * @return string
	 * @since  2.2.0
	 */
	private function ua_subject( array $server ) {
		return isset( $server['HTTP_USER_AGENT'] )
			? $this->cap( (string) $server['HTTP_USER_AGENT'] )
			: '';
	}

	/**
	 * Recursively flatten a request array into a single inspectable string.
	 *
	 * @param mixed $value Value to flatten.
	 * @return string
	 * @since  2.2.0
	 */
	private function flatten( $value ) {
		if ( is_array( $value ) ) {
			$out = '';
			foreach ( $value as $key => $item ) {
				$out .= ' ' . $key . '=' . $this->flatten( $item );
			}
			return $out;
		}
		if ( is_scalar( $value ) ) {
			return (string) $value;
		}
		return '';
	}

	/**
	 * Truncate a subject to the inspection ceiling.
	 *
	 * @param string $subject Subject string.
	 * @return string
	 * @since  2.2.0
	 */
	private function cap( $subject ) {
		if ( strlen( $subject ) > self::MAX_SUBJECT_BYTES ) {
			return substr( $subject, 0, self::MAX_SUBJECT_BYTES );
		}
		return $subject;
	}

	/**
	 * Safely evaluate a rule pattern against a subject.
	 *
	 * The pattern ships without delimiters; a tilde delimiter is added (and any
	 * literal tilde escaped). A `false` return — an invalid pattern or a
	 * backtrack-limit hit — is treated as a non-match (fail-open) so a single
	 * bad rule can never take the site down or hang the request.
	 *
	 * @param string $pattern Raw PCRE body (no delimiters).
	 * @param string $subject Subject to test.
	 * @return bool True on a confirmed match.
	 * @since  2.2.0
	 */
	private function matches( $pattern, $subject ) {
		if ( '' === $pattern ) {
			return false;
		}
		$compiled = '~' . str_replace( '~', '\~', $pattern ) . '~';
		$result   = @preg_match( $compiled, $subject ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A malformed delivered rule must fail open, not emit a warning into the response.
		return 1 === $result;
	}

	/**
	 * Act on a rule hit: always log, then block unless report-only.
	 *
	 * @param array<string,mixed> $rule The matched rule.
	 * @param string              $ip   Client IP.
	 * @return void
	 * @since  2.2.0
	 */
	private function handle_hit( array $rule, $ip ) {
		$group    = isset( $rule['group'] ) ? (string) $rule['group'] : '';
		$severity = isset( $rule['severity'] ) ? (string) $rule['severity'] : 'high';
		$reason   = isset( self::GROUP_REASON[ $group ] ) ? self::GROUP_REASON[ $group ] : 'scan';
		$rule_id  = isset( $rule['id'] ) ? (string) $rule['id'] : 'waf_rule';

		$report_only = $this->is_report_only();

		if ( class_exists( 'ReportedIP_Hive' ) ) {
			$logger = ReportedIP_Hive::get_instance()->get_logger();
			if ( $logger instanceof ReportedIP_Hive_Logger ) {
				$logger->log_security_event(
					$report_only ? 'waf_would_block' : 'waf_block',
					$ip,
					array(
						'rule'        => $rule_id,
						'group'       => $group,
						'target'      => isset( $rule['target'] ) ? (string) $rule['target'] : 'all',
						'report_only' => $report_only,
					),
					$severity
				);
			}
		}

		if ( $report_only ) {
			return;
		}

		$this->escalate( $ip, $group, $rule_id );

		ReportedIP_Hive::serve_blocked_page( $reason );
	}

	/**
	 * Feed a confirmed hit into the shared attempt tracker so a repeat offender
	 * graduates to a laddered IP block via the existing escalation path. The
	 * threshold defaults to 3 so a single false positive blocks only the
	 * offending request, not the IP.
	 *
	 * @param string $ip      Client IP.
	 * @param string $group   Rule group.
	 * @param string $rule_id Rule id.
	 * @return void
	 * @since  2.2.0
	 */
	private function escalate( $ip, $group, $rule_id ) {
		if ( ! class_exists( 'ReportedIP_Hive' ) ) {
			return;
		}
		$monitor = ReportedIP_Hive::get_instance()->get_security_monitor();
		if ( ! ( $monitor instanceof ReportedIP_Hive_Security_Monitor ) ) {
			return;
		}
		$threshold = (int) ReportedIP_Hive_Option_Routing::get( self::OPT_BLOCK_THRESHOLD, 3 );
		if ( $threshold < 1 ) {
			$threshold = 1;
		}
		$monitor->track_generic_attempt(
			$ip,
			'waf',
			'waf_block',
			$threshold,
			self::ESCALATION_TIMEFRAME_MINUTES,
			array(
				'group' => $group,
				'rule'  => $rule_id,
			)
		);
	}
}
