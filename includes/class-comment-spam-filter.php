<?php
/**
 * Comment spam classifier.
 *
 * Scores an incoming comment against a set of link, body and identity signals
 * and marks the ones that add up as spam. Without it Hive had no opinion of its
 * own about a comment: it read the approval state WordPress had already decided
 * on, which on a site with moderation switched on says nothing about spam.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.52
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Signal-based comment spam filter.
 *
 * @since 2.1.52
 */
class ReportedIP_Hive_Comment_Spam_Filter {

	/**
	 * Action taken on a comment that scores at or above the threshold:
	 * off | spam | block.
	 */
	const OPT_ACTION = 'reportedip_hive_comment_spam_action';

	/**
	 * Score at which a comment counts as spam. Only two signals reach it on
	 * their own, a link with no message and a domain in the author name, and
	 * neither has a legitimate reading. Every other signal stays below it, so
	 * an ordinary comment needs at least two independent reasons.
	 */
	const THRESHOLD = 4;

	/**
	 * Body length under which a comment counts as a one-liner.
	 */
	const SHORT_BODY = 15;

	/**
	 * Body length under which the link-to-text ratio is meaningful.
	 */
	const DENSITY_BODY = 200;

	/**
	 * Share of the body that may consist of link characters before the comment
	 * reads as a link carrier rather than a message.
	 */
	const DENSITY_RATIO = 0.3;

	/**
	 * Top-level domains that carry almost no legitimate comment traffic but
	 * dominate throwaway link spam because they are given away or near free.
	 *
	 * @var string[]
	 */
	const RISKY_TLDS = array(
		'icu',
		'top',
		'vip',
		'xyz',
		'club',
		'click',
		'link',
		'loan',
		'work',
		'buzz',
		'monster',
		'quest',
		'bond',
		'cfd',
		'sbs',
		'rest',
		'lol',
		'gq',
		'cf',
		'ml',
		'tk',
		'ga',
	);

	/**
	 * Bodies that carry no message and exist only to hang a link on. Matched
	 * case-insensitively against the whole trimmed body.
	 */
	const FILLER_PATTERN = '/^(?:thanks*|thank\s?you|thx+|ty|nice(?:\s?(?:post|article|one))?|good(?:\s?(?:post|job))?|great(?:\s?(?:post|article))?|cool|wow|ok(?:ay)?|super|perfect|amazing|awesome|lovely|excellent|interesting|useful|helpful|hi|hello|bravo|congrats?)[\s!.,?*]*$/iu';

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Comment_Spam_Filter|null
	 */
	private static $instance = null;

	/**
	 * Verdict for the comment currently being processed, carried from
	 * `preprocess_comment` to `pre_comment_approved`.
	 *
	 * @var array{score:int, reasons:array<int,string>}|null
	 */
	private $verdict = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return ReportedIP_Hive_Comment_Spam_Filter
	 * @since  2.1.52
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Wire the two comment hooks. Scoring happens on `preprocess_comment`,
	 * after the honeypot has had its say, and the verdict is applied on
	 * `pre_comment_approved` so the comment reaches `comment_post` with the
	 * spam state already set.
	 *
	 * @since 2.1.52
	 */
	private function __construct() {
		add_filter( 'preprocess_comment', array( $this, 'inspect_comment' ), 5 );
		add_filter( 'pre_comment_approved', array( $this, 'apply_verdict' ), 99 );
	}

	/**
	 * Configured action.
	 *
	 * @return string One of off, spam, block.
	 * @since  2.1.52
	 */
	public function action() {
		$action = (string) ReportedIP_Hive_Option_Routing::get( self::OPT_ACTION, 'spam' );
		return in_array( $action, array( 'off', 'spam', 'block' ), true ) ? $action : 'spam';
	}

	/**
	 * Score the incoming comment and remember the verdict.
	 *
	 * Trackbacks and pingbacks are left alone, they carry no body to judge.
	 * Anyone who may edit posts is exempt, as in the honeypot.
	 *
	 * @param array<string,mixed> $commentdata Incoming comment data.
	 * @return array<string,mixed>
	 * @since  2.1.52
	 */
	public function inspect_comment( $commentdata ) {
		$this->verdict = null;

		if ( 'off' === $this->action() ) {
			return $commentdata;
		}
		if ( ! empty( $commentdata['comment_type'] ) && ! in_array( (string) $commentdata['comment_type'], array( '', 'comment' ), true ) ) {
			return $commentdata;
		}
		if ( is_user_logged_in() && current_user_can( 'edit_posts' ) ) {
			return $commentdata;
		}

		$verdict = self::score( (array) $commentdata, $this->context() );

		if ( $verdict['score'] < self::THRESHOLD ) {
			return $commentdata;
		}

		$this->verdict = $verdict;

		if ( 'block' === $this->action() ) {
			$this->record( $commentdata, 0 );
			$this->verdict = null;

			wp_die(
				esc_html__( 'Your comment could not be processed.', 'reportedip-hive' ),
				'',
				array( 'response' => 403 )
			);
		}

		return $commentdata;
	}

	/**
	 * Turn the remembered verdict into the spam approval state.
	 *
	 * @param string|int|WP_Error $approved Approval state decided so far.
	 * @return string|int|WP_Error
	 * @since  2.1.52
	 */
	public function apply_verdict( $approved ) {
		if ( null === $this->verdict || is_wp_error( $approved ) || 'spam' === $approved ) {
			return $approved;
		}
		return 'spam';
	}

	/**
	 * Whether the comment currently being processed was scored as spam, and
	 * with which reasons. Read by the `comment_post` handler so the log entry
	 * says why, instead of only how long the body was.
	 *
	 * @return array{score:int, reasons:array<int,string>}|null
	 * @since  2.1.52
	 */
	public function last_verdict() {
		return $this->verdict;
	}

	/**
	 * Build the scoring context from the WordPress configuration.
	 *
	 * @return array<string,mixed>
	 * @since  2.1.52
	 */
	private function context() {
		$rules = array();
		if ( class_exists( 'ReportedIP_Hive_Disposable_Email' ) ) {
			$rules = ReportedIP_Hive_Disposable_Email::get_instance()->get_disposable_rules();
		}

		$form_field_present = null;
		if ( class_exists( 'ReportedIP_Hive_Comment_Honeypot' )
			&& ReportedIP_Hive_Comment_Honeypot::get_instance()->is_enabled() ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Presence check on a decoy field, not a state change; the comment form carries its own nonce.
			$form_field_present = isset( $_POST[ ReportedIP_Hive_Comment_Honeypot::FIELD_NAME ] );
		}

		return array(
			'max_links'          => (int) get_option( 'comment_max_links', 2 ),
			'disposable_domains' => is_array( $rules ) ? $rules : array(),
			'form_field_present' => $form_field_present,
		);
	}

	/**
	 * Log the detection and feed the per-address counter.
	 *
	 * @param array<string,mixed> $commentdata Comment data.
	 * @param int                 $comment_id  Comment id, 0 when it never got one.
	 * @return void
	 * @since  2.1.52
	 */
	private function record( $commentdata, $comment_id ) {
		if ( null === $this->verdict || ! class_exists( 'ReportedIP_Hive' ) ) {
			return;
		}

		$hive = ReportedIP_Hive::get_instance();
		$ip   = ReportedIP_Hive::get_client_ip();

		$logger = $hive->get_logger();
		if ( $logger instanceof ReportedIP_Hive_Logger ) {
			$logger->log_security_event(
				'comment_spam',
				$ip,
				array(
					'comment_id'     => $comment_id,
					'score'          => $this->verdict['score'],
					'reasons'        => implode( ', ', $this->verdict['reasons'] ),
					'content_length' => strlen( (string) ( $commentdata['comment_content'] ?? '' ) ),
				)
			);
		}

		$monitor = $hive->get_security_monitor();
		if ( $monitor instanceof ReportedIP_Hive_Security_Monitor ) {
			$monitor->check_comment_spam_threshold( $ip );
		}
	}

	/**
	 * Score a comment. Pure: everything it reads comes in through the two
	 * arguments, so the whole rule set is unit-testable without WordPress.
	 *
	 * @param array<string,mixed> $comment Comment data (`comment_author`,
	 *                                     `comment_author_email`,
	 *                                     `comment_author_url`,
	 *                                     `comment_content`).
	 * @param array<string,mixed> $context `max_links`, `disposable_domains`,
	 *                                     `form_field_present`.
	 * @return array{score:int, reasons:array<int,string>}
	 * @since  2.1.52
	 */
	public static function score( array $comment, array $context = array() ) {
		$body       = trim( (string) ( $comment['comment_content'] ?? '' ) );
		$author     = trim( (string) ( $comment['comment_author'] ?? '' ) );
		$author_url = trim( (string) ( $comment['comment_author_url'] ?? '' ) );
		$email      = trim( (string) ( $comment['comment_author_email'] ?? '' ) );

		$max_links = isset( $context['max_links'] ) ? max( 0, (int) $context['max_links'] ) : 2;
		$rules     = isset( $context['disposable_domains'] ) && is_array( $context['disposable_domains'] )
			? $context['disposable_domains']
			: array();

		$body_links = self::links_in( $body );
		$hosts      = self::hosts( array_merge( $body_links, '' !== $author_url ? array( $author_url ) : array() ) );
		$link_count = count( $body_links ) + ( '' !== $author_url ? 1 : 0 );

		$score   = 0;
		$reasons = array();

		if ( '' !== $author_url && mb_strlen( $body ) < self::SHORT_BODY ) {
			$score    += 4;
			$reasons[] = 'url_with_no_message';
		}

		if ( $link_count > $max_links ) {
			$score    += 3;
			$reasons[] = 'link_flood';
		}

		$link_chars = 0;
		foreach ( $body_links as $link ) {
			$link_chars += mb_strlen( $link );
		}
		if ( $link_chars > 0
			&& mb_strlen( $body ) > 0
			&& mb_strlen( $body ) < self::DENSITY_BODY
			&& ( $link_chars / mb_strlen( $body ) ) > self::DENSITY_RATIO ) {
			$score    += 2;
			$reasons[] = 'link_density';
		}

		if ( count( $hosts ) > 1 ) {
			$score    += 2;
			$reasons[] = 'multiple_domains';
		}

		if ( '' !== $body && preg_match( self::FILLER_PATTERN, $body ) ) {
			$score    += 2;
			$reasons[] = 'filler_body';
		}

		foreach ( $hosts as $host ) {
			if ( self::has_risky_tld( $host ) ) {
				$score    += 2;
				$reasons[] = 'risky_tld';
				break;
			}
		}

		if ( self::looks_like_url( $author ) ) {
			$score    += 4;
			$reasons[] = 'url_in_author_name';
		}

		if ( '' !== $email && array() !== $rules && class_exists( 'ReportedIP_Hive_Disposable_Email' ) ) {
			$domain = ReportedIP_Hive_Disposable_Email::domain_of( $email );
			if ( '' !== $domain && 'disposable' === ReportedIP_Hive_Disposable_Email::classify_domain( $domain, $rules ) ) {
				$score    += 2;
				$reasons[] = 'disposable_email';
			}
		}

		if ( isset( $context['form_field_present'] ) && false === $context['form_field_present'] ) {
			++$score;
			$reasons[] = 'no_form_field';
		}

		return array(
			'score'   => $score,
			'reasons' => $reasons,
		);
	}

	/**
	 * Extract the links from a comment body, both bare and inside an anchor.
	 *
	 * @param string $body Comment body.
	 * @return string[]
	 * @since  2.1.52
	 */
	public static function links_in( $body ) {
		$found = array();
		if ( preg_match_all( '#\b(?:https?://|www\.)[^\s<>"\')]+#i', (string) $body, $matches ) ) {
			$found = $matches[0];
		}
		return $found;
	}

	/**
	 * Reduce a list of URLs to their distinct registrable-looking hosts.
	 *
	 * @param string[] $urls URLs.
	 * @return string[]
	 * @since  2.1.52
	 */
	public static function hosts( array $urls ) {
		$hosts = array();
		foreach ( $urls as $url ) {
			$url = (string) $url;
			if ( ! preg_match( '#^[a-z][a-z0-9+.-]*://#i', $url ) ) {
				$url = 'http://' . ltrim( $url, '/' );
			}
			$host = (string) wp_parse_url( $url, PHP_URL_HOST );
			$host = strtolower( ltrim( $host, '.' ) );
			if ( '' === $host ) {
				continue;
			}
			if ( 0 === strpos( $host, 'www.' ) ) {
				$host = substr( $host, 4 );
			}
			$hosts[ $host ] = true;
		}
		return array_keys( $hosts );
	}

	/**
	 * Whether a host sits on one of the giveaway top-level domains.
	 *
	 * @param string $host Host name.
	 * @return bool
	 * @since  2.1.52
	 */
	public static function has_risky_tld( $host ) {
		$parts = explode( '.', strtolower( (string) $host ) );
		$tld   = (string) end( $parts );
		return in_array( $tld, self::RISKY_TLDS, true );
	}

	/**
	 * Whether an author name is really a link. A person writes their name
	 * there, a link builder writes their domain.
	 *
	 * @param string $author Author name.
	 * @return bool
	 * @since  2.1.52
	 */
	public static function looks_like_url( $author ) {
		$author = strtolower( trim( (string) $author ) );
		if ( '' === $author ) {
			return false;
		}
		if ( false !== strpos( $author, 'http://' ) || false !== strpos( $author, 'https://' ) || 0 === strpos( $author, 'www.' ) ) {
			return true;
		}
		return (bool) preg_match( '#(?:^|\s)[a-z0-9-]+\.(?:com|net|org|info|biz|ru|io|co|shop|site|online|store|xyz|top|icu|vip|club)(?:$|[\s/])#', $author );
	}
}
