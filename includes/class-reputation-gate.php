<?php
/**
 * Community-reputation gate for public form submissions.
 *
 * The sign-in path has asked the community network about a visitor's address
 * since 1.0. Comments, sign-ups and password resets did not, so an address the
 * network already knows as abusive could keep posting as long as it stayed
 * below the local score. This gate closes that gap with the same threshold, the
 * same floor and the same consequence the sign-in path uses.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.53
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Reputation check on the public form surfaces.
 *
 * @since 2.1.53
 */
class ReportedIP_Hive_Reputation_Gate {

	/**
	 * Master toggle for the form-side reputation check.
	 */
	const OPT_ENABLED = 'reportedip_hive_reputation_on_forms';

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Reputation_Gate|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return ReportedIP_Hive_Reputation_Gate
	 * @since  2.1.53
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Wire the comment surface. Registration and password reset are owned by
	 * `Registration_Guard` and `Form_Proof` respectively and call in from
	 * there, so each surface keeps exactly one owning class.
	 *
	 * Priority 6 puts the check after the local scoring at 5: an address that
	 * already gave itself away locally costs no community lookup.
	 *
	 * @since 2.1.53
	 */
	private function __construct() {
		add_filter( 'preprocess_comment', array( $this, 'check_comment' ), 6 );
	}

	/**
	 * Whether the gate is active.
	 *
	 * @return bool
	 * @since  2.1.53
	 */
	public function is_enabled() {
		return (bool) ReportedIP_Hive_Option_Routing::get( self::OPT_ENABLED, true );
	}

	/**
	 * The confidence a submission is refused at.
	 *
	 * Deliberately the very value the sign-in path enforces, read through the
	 * same floor and the same hardening clamp: a visitor the site would refuse
	 * a login to must not be able to post a comment instead.
	 *
	 * @return int Percentage.
	 * @since  2.1.53
	 */
	public static function threshold() {
		/**
		 * Filters the lowest confidence a reputation block will act on.
		 *
		 * The floor guards against false positives from over-aggressive
		 * threshold configuration: stored thresholds and the hardening clamp
		 * cannot push enforcement below it. Raising the floor tightens a site
		 * further; lowering it below the settings-registry minimum has no
		 * effect because stored thresholds never go that low.
		 *
		 * @param int $floor Minimum confidence percentage (default 25).
		 * @since 2.1.50
		 */
		$floor = max(
			1,
			min( 100, (int) apply_filters( 'reportedip_hive_reputation_threshold_floor', ReportedIP_Hive_Defaults::MIN_BLOCK_THRESHOLD ) )
		);

		return max(
			$floor,
			ReportedIP_Hive_Hardening_Mode::effective_block_threshold(
				(int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_threshold', 75 )
			)
		);
	}

	/**
	 * Decide whether a submission from this address may proceed.
	 *
	 * Fail-open throughout: no key, no quota, no answer or any doubt lets the
	 * submission through. A community verdict is hearsay about an address, and
	 * hearsay must never be the reason a site stops accepting input.
	 *
	 * @param string $surface Surface identifier.
	 * @param string $ip      Client address.
	 * @return string Empty string to proceed, otherwise the refusal message.
	 * @since  2.1.53
	 */
	public function check( $surface, $ip ) {
		if ( ! $this->is_enabled() ) {
			return '';
		}

		$surfaces = (array) apply_filters( 'reportedip_hive_reputation_form_surfaces', array( 'comment', 'register', 'lostpassword' ) );
		if ( ! in_array( (string) $surface, $surfaces, true ) ) {
			return '';
		}

		$ip = (string) $ip;
		if ( '' === $ip || 'unknown' === $ip ) {
			return '';
		}

		if ( ! class_exists( 'ReportedIP_Hive' ) ) {
			return '';
		}

		$ip_manager = ReportedIP_Hive_IP_Manager::get_instance();

		if ( $ip_manager->is_whitelisted( $ip ) || ReportedIP_Hive::is_own_server_ip( $ip ) ) {
			return '';
		}

		if ( $ip_manager->is_blocked( $ip ) ) {
			return '';
		}

		$verdict = $this->verdict( $ip );

		if ( empty( $verdict['exceeds'] ) ) {
			return '';
		}

		if ( ! empty( $verdict['infrastructure'] ) ) {
			$this->log(
				'reputation_infrastructure_spared',
				$ip,
				array(
					'surface'    => $surface,
					'confidence' => $verdict['confidence'],
					'threshold'  => $verdict['threshold'],
				),
				'low'
			);

			return '';
		}

		$report_only = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_only_mode', false );

		if ( $report_only ) {
			$this->log(
				'would_block_by_reputation',
				$ip,
				array(
					'surface'          => $surface,
					'confidence'       => $verdict['confidence'],
					'reports'          => $verdict['reports'],
					'threshold'        => $verdict['threshold'],
					'report_only_mode' => true,
				),
				'high'
			);

			return '';
		}

		$this->enforce( $ip, $surface, $verdict );

		return self::message( $surface );
	}

	/**
	 * Ask the community network about an address. Repeat lookups inside the
	 * same window are answered by {@see ReportedIP_Hive_Cache::get_reputation()}.
	 *
	 * @param string $ip Client address.
	 * @return array{exceeds:bool, confidence:int, reports:int, threshold:int, infrastructure:bool}
	 * @since  2.1.53
	 */
	private function verdict( $ip ) {
		$threshold = self::threshold();
		$api       = ReportedIP_Hive_API::get_instance();

		if ( ! $api->is_configured() ) {
			return self::read_response( false, $threshold );
		}

		return self::read_response( $api->check_ip_reputation( $ip ), $threshold );
	}

	/**
	 * Turn a lookup answer into a verdict. Pure, so the one guarantee that
	 * matters here can actually be tested.
	 *
	 * Every failure mode of the lookup arrives as `false`: an exhausted daily
	 * allowance, an HTTP 429, a timeout, a network error, a negative cache hit,
	 * a missing key. All of them must read as "no opinion", never as a reason
	 * to refuse a submission. A community verdict is an extra source of
	 * evidence, and losing it may cost the site that evidence, never its
	 * ability to accept input. The local score runs before this and is
	 * unaffected either way.
	 *
	 * @param mixed $reputation Answer from the lookup, or false on any failure.
	 * @param int   $threshold  Confidence the refusal starts at.
	 * @return array{exceeds:bool, confidence:int, reports:int, threshold:int, infrastructure:bool}
	 * @since  2.1.53
	 */
	public static function read_response( $reputation, $threshold ) {
		$verdict = array(
			'exceeds'        => false,
			'confidence'     => 0,
			'reports'        => 0,
			'threshold'      => (int) $threshold,
			'infrastructure' => false,
		);

		if ( ! is_array( $reputation ) || ! isset( $reputation['abuseConfidencePercentage'] ) ) {
			return $verdict;
		}

		if ( ! is_numeric( $reputation['abuseConfidencePercentage'] ) ) {
			return $verdict;
		}

		$verdict['confidence']     = (int) $reputation['abuseConfidencePercentage'];
		$verdict['reports']        = isset( $reputation['totalReports'] ) && is_numeric( $reputation['totalReports'] )
			? (int) $reputation['totalReports']
			: 0;
		$verdict['infrastructure'] = ! empty( $reputation['isWhitelisted'] );
		$verdict['exceeds']        = $verdict['confidence'] >= (int) $threshold;

		return $verdict;
	}

	/**
	 * Write the temporary block, log it and tell the community.
	 *
	 * Identical to what a refused sign-in does, so the address is closed on
	 * every surface rather than only on the form it just used.
	 *
	 * @param string               $ip      Client address.
	 * @param string               $surface Surface identifier.
	 * @param array<string, mixed> $verdict Verdict from {@see verdict()}.
	 * @return void
	 * @since  2.1.53
	 */
	private function enforce( $ip, $surface, array $verdict ) {
		/** This filter is documented in reportedip-hive.php */
		$hours = max( 1, (int) apply_filters( 'reportedip_hive_reputation_block_hours', 24 ) );

		$database = ReportedIP_Hive_Database::get_instance();
		$database->block_ip(
			$ip,
			sprintf(
				'Community reputation: %1$d%% confidence (threshold %2$d%%)',
				(int) $verdict['confidence'],
				(int) $verdict['threshold']
			),
			'reputation',
			$hours
		);
		$database->update_daily_stats( 'reputation_blocks' );

		$this->log(
			'blocked_by_reputation',
			$ip,
			array(
				'surface'     => $surface,
				'confidence'  => $verdict['confidence'],
				'reports'     => $verdict['reports'],
				'threshold'   => $verdict['threshold'],
				'block_hours' => $hours,
			),
			'high'
		);

		$monitor = ReportedIP_Hive::get_instance()->get_security_monitor();

		if ( $monitor instanceof ReportedIP_Hive_Security_Monitor ) {
			$monitor->report_security_event(
				$ip,
				'reputation_threat',
				array(
					'confidence' => $verdict['confidence'],
					'reports'    => $verdict['reports'],
					'threshold'  => $verdict['threshold'],
				)
			);
		}
	}

	/**
	 * Write one log row.
	 *
	 * @param string               $event    Event slug.
	 * @param string               $ip       Client address.
	 * @param array<string, mixed> $details  Event metadata.
	 * @param string               $severity Severity.
	 * @return void
	 * @since  2.1.53
	 */
	private function log( $event, $ip, array $details, $severity ) {
		$logger = ReportedIP_Hive::get_instance()->get_logger();

		if ( $logger instanceof ReportedIP_Hive_Logger ) {
			$logger->log_security_event( $event, $ip, $details, $severity );
		}
	}

	/**
	 * The refusal a visitor sees. Says what happened and where to go with it,
	 * because the one person most likely to read it is someone sharing an
	 * address with whoever earned the reputation.
	 *
	 * @param string $surface Surface identifier.
	 * @return string
	 * @since  2.1.53
	 */
	public static function message( $surface ) {
		if ( 'comment' === $surface ) {
			return __( 'Your comment was not accepted: your internet address is listed for abuse in the community threat network. If you believe this is wrong, contact the site owner.', 'reportedip-hive' );
		}

		if ( 'register' === $surface ) {
			return __( 'Registration is not available from your internet address: it is listed for abuse in the community threat network. If you believe this is wrong, contact the site owner.', 'reportedip-hive' );
		}

		if ( 'lostpassword' === $surface ) {
			return __( 'A password reset cannot be requested from your internet address: it is listed for abuse in the community threat network. If you believe this is wrong, contact the site owner.', 'reportedip-hive' );
		}

		return __( 'Your submission was not accepted: your internet address is listed for abuse in the community threat network. If you believe this is wrong, contact the site owner.', 'reportedip-hive' );
	}

	/**
	 * Refuse a comment from an address the community network knows as abusive.
	 *
	 * Skips the lookup when the local score already decided, so a bot that gave
	 * itself away for free costs no community quota.
	 *
	 * @param array<string,mixed> $commentdata Incoming comment data.
	 * @return array<string,mixed>
	 * @since  2.1.53
	 */
	public function check_comment( $commentdata ) {
		if ( ! $this->is_enabled() ) {
			return $commentdata;
		}

		if ( ! empty( $commentdata['comment_type'] ) && ! in_array( (string) $commentdata['comment_type'], array( '', 'comment' ), true ) ) {
			return $commentdata;
		}

		if ( is_user_logged_in() && current_user_can( 'edit_posts' ) ) {
			return $commentdata;
		}

		if ( class_exists( 'ReportedIP_Hive_Comment_Spam_Filter' )
			&& null !== ReportedIP_Hive_Comment_Spam_Filter::get_instance()->last_verdict() ) {
			return $commentdata;
		}

		$message = $this->check( 'comment', ReportedIP_Hive::get_client_ip() );

		if ( '' === $message ) {
			return $commentdata;
		}

		wp_die(
			esc_html( $message ),
			esc_html__( 'Comment not accepted', 'reportedip-hive' ),
			array( 'response' => 403 )
		);
	}
}
