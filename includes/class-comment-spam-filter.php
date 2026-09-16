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
	 * Score at which a comment counts as spam. Only a filled decoy field
	 * reaches it on its own, and that has no legitimate reading. Every other
	 * signal stays below it, so an ordinary comment needs at least two
	 * independent reasons.
	 *
	 * Raised from 4 to 7 in 2.1.58. At 4 a missing execution proof was enough
	 * on its own, which filed every reader browsing without JavaScript as a
	 * spammer. Measured against 27796 real comments the higher bar costs
	 * nothing: with the signals added in the same release the hit rate rises
	 * from 9.1 to 95.6 per cent while false positives fall from 32 to 3.
	 */
	const THRESHOLD = 7;

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
	 * Body length from which the language of the text says anything. Below it
	 * a text is too short to be missing a stop word by anything but chance.
	 */
	const LANGUAGE_BODY = 40;

	/**
	 * Body length from which an identical text counts as a repeat. Shorter
	 * bodies collide by chance between unrelated readers.
	 */
	const DUPLICATE_BODY = 40;

	/**
	 * Prefix length compared when looking for an identical text. Campaigns
	 * vary the tail of a comment more often than its opening.
	 */
	const DUPLICATE_PREFIX = 120;

	/**
	 * Number of comments a link target may appear in before it reads as a
	 * campaign rather than as one person's own site.
	 */
	const REPEAT_TARGET = 5;

	/**
	 * Share of a name that may sit outside the Latin range before the name is
	 * read as foreign script. Measured per string, never per character: a
	 * single Katakana inside a shrug emoticon is not a foreign name.
	 */
	const FOREIGN_NAME_RATIO = 0.3;

	/**
	 * The same share for a body.
	 */
	const FOREIGN_BODY_RATIO = 0.2;

	/**
	 * Characters outside the Latin ranges that a link-building campaign writes
	 * and a reader of a Latin-script site does not.
	 */
	const FOREIGN_PATTERN = '/[\x{0400}-\x{04FF}\x{3040}-\x{30FF}\x{4E00}-\x{9FFF}\x{AC00}-\x{D7AF}\x{0600}-\x{06FF}\x{0E00}-\x{0E7F}]/u';

	/**
	 * Link markup a browser renders but nobody types into a comment box. Spam
	 * tools scrape rendered comments from other sites and post the result back
	 * as input, `rel` attribute and all.
	 */
	const PASTED_MARKUP_PATTERN = '/rel\s*=\s*["\']?(?:nofollow|ugc|sponsored|noopener)/i';

	/**
	 * A hand-written anchor, plain or escaped by the form.
	 */
	const ANCHOR_PATTERN = '/(?:<|&lt;)a\s+href/i';

	/**
	 * A browser that claims WebKit always carries this token. A tool that
	 * assembles a user-agent string from memory leaves it out.
	 */
	const WEBKIT_TOKEN = 'KHTML, like Gecko';

	/**
	 * Openings that praise the article without saying anything about it. On
	 * their own they are how a polite reader starts; together with a link in
	 * the author field they are the standard opening of link-building spam.
	 */
	const PRAISE_PATTERN = '/^(?:thank|thanks|great|nice|good|awesome|excellent|wonderful|amazing|very good|cool|perfect|i (?:really )?(?:like|love|enjoy))/i';

	/**
	 * Stop words per language, used to ask whether a text is written in the
	 * language of the site. A language that is not listed switches the signal
	 * off rather than making every comment suspicious.
	 *
	 * Err on the long side. Every word missing from a list is a reader whose
	 * short comment happens to avoid all the others, and the one genuine false
	 * positive in the 27796-comment measurement was exactly that: a German
	 * sentence built entirely from words the first draft had left out.
	 *
	 * @var array<string, string[]>
	 */
	const LANGUAGE_WORDS = array(
		'de' => array( 'und', 'der', 'die', 'das', 'ist', 'nicht', 'auch', 'ich', 'für', 'mit', 'ein', 'eine', 'aber', 'schon', 'doch', 'mehr', 'sehr', 'wird', 'sind', 'man', 'hat', 'wie', 'was', 'dass', 'noch', 'kann', 'habe', 'mich', 'wir', 'von', 'im', 'am', 'es', 'den', 'dem', 'auf', 'über', 'bei', 'nach', 'wenn', 'weil', 'oder', 'als', 'nur', 'wurde', 'hier', 'dann', 'gibt', 'ganz', 'gut', 'leider', 'danke', 'liebe', 'grüße', 'dieser', 'diese', 'dieses', 'sich', 'werden', 'haben', 'machen', 'gerne', 'schön', 'einfach', 'immer', 'alle', 'keine', 'viel', 'wieder', 'gegen', 'ohne', 'unter', 'zwischen', 'dürfte', 'würde', 'könnte', 'sollte', 'besser', 'toll', 'super', 'vielen', 'freue', 'finde', 'geht', 'war', 'waren', 'einen', 'einem', 'einer', 'ihr', 'sie', 'wer', 'wo', 'warum', 'damit', 'sowie', 'etwas', 'nichts', 'jetzt', 'heute', 'morgen', 'gestern', 'link', 'seite' ),
		'en' => array( 'the', 'and', 'you', 'your', 'this', 'that', 'for', 'are', 'with', 'have', 'from', 'will', 'would', 'about', 'great', 'very', 'really', 'article', 'post', 'good', 'please', 'help', 'know', 'like', 'just', 'more', 'some', 'what', 'when', 'which', 'there', 'their', 'been', 'much', 'many', 'also', 'content', 'blog', 'share', 'think', 'because', 'could', 'should', 'was', 'were', 'has', 'had', 'but', 'not', 'all', 'any', 'how', 'why', 'who', 'where', 'here', 'they', 'them', 'these', 'those', 'than', 'then', 'them', 'into', 'over', 'after', 'before', 'still', 'never', 'always', 'thanks', 'thank', 'love', 'nice', 'work', 'time', 'people', 'even', 'only', 'same', 'other', 'first', 'last', 'need', 'want', 'make', 'made', 'does', 'did', 'say', 'said', 'get', 'got', 'one', 'two', 'out', 'its' ),
	);

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
		if ( $this->ip_is_exempt() ) {
			return $commentdata;
		}

		$verdict = self::score( (array) $commentdata, $this->context( (array) $commentdata ) );

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
	 * Whether the visitor address is one the operator vouched for, or one that
	 * is already blocked and therefore judged elsewhere. Every other sensor
	 * makes this its first check; without it a whitelisted address could be
	 * filed as a spammer and, on the `block` action, blocked and reported.
	 *
	 * @return bool
	 * @since  2.1.53
	 */
	private function ip_is_exempt() {
		if ( ! class_exists( 'ReportedIP_Hive_IP_Manager' ) ) {
			return false;
		}

		$ip = class_exists( 'ReportedIP_Hive' ) ? ReportedIP_Hive::get_client_ip() : '';

		if ( '' === $ip || 'unknown' === $ip ) {
			return false;
		}

		$manager = ReportedIP_Hive_IP_Manager::get_instance();

		return $manager->is_whitelisted( $ip ) || $manager->is_blocked( $ip );
	}

	/**
	 * Whether a verdict may feed the per-address counter.
	 *
	 * A missing execution proof is the one reason a genuine reader can produce:
	 * someone browsing without JavaScript trips it on every comment they write.
	 * Filing those comments for review is the intended cost, blocking the
	 * address after five of them is not, so a verdict resting on that reason
	 * alone stops at the filing.
	 *
	 * @param array{score:int, reasons:array<int,string>}|null $verdict Verdict.
	 * @return bool
	 * @since  2.1.53
	 */
	public static function verdict_may_block( $verdict ) {
		if ( ! is_array( $verdict ) || empty( $verdict['reasons'] ) ) {
			return true;
		}

		return array( 'no_js_proof' ) !== array_values( (array) $verdict['reasons'] );
	}

	/**
	 * Build the scoring context from the request and the WordPress
	 * configuration. Everything {@see score()} reads passes through here, so
	 * the scoring itself stays pure and testable without WordPress.
	 *
	 * @param array<string,mixed> $commentdata Incoming comment data.
	 * @return array<string,mixed>
	 * @since  2.1.52
	 */
	private function context( array $commentdata = array() ) {
		$rules = array();
		if ( class_exists( 'ReportedIP_Hive_Disposable_Email' ) ) {
			$rules = ReportedIP_Hive_Disposable_Email::get_instance()->get_disposable_rules();
		}

		$proof   = null;
		$renders = false;
		$seconds = null;
		$fast    = 0;
		if ( class_exists( 'ReportedIP_Hive_Form_Proof' )
			&& class_exists( 'ReportedIP_Hive_Comment_Honeypot' )
			&& ReportedIP_Hive_Comment_Honeypot::get_instance()->is_enabled() ) {
			$form_proof = ReportedIP_Hive_Form_Proof::get_instance();
			$proof      = $form_proof->verdict_for_request( 'comment' );
			$renders    = $form_proof->renders_anchors();
			$seconds    = $form_proof->last_seconds();
			$fast       = $form_proof->fast_seconds();
		}

		$user_agent = '';
		if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
			$user_agent = (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Matched as an opaque token; never stored or echoed from here, and truncating it would cut the very token the check reads.
		}

		return array_merge(
			array(
				'max_links'          => (int) get_option( 'comment_max_links', 2 ),
				'disposable_domains' => is_array( $rules ) ? $rules : array(),
				'form_proof'         => $proof,
				'form_proof_seconds' => $seconds,
				'fast_seconds'       => $fast,
				'renders_anchors'    => $renders,
				'user_agent'         => $user_agent,
				'locale'             => get_locale(),
			),
			$this->history_for( $commentdata )
		);
	}

	/**
	 * Ask the comment table what it has seen before: whether this link target
	 * is one the site already published, how often it has been submitted at
	 * all, and whether this text has arrived once already.
	 *
	 * The published-before check is what keeps a regular commenter who always
	 * leaves the same website of their own out of the repeat count. Without it
	 * the repeat signal punishes exactly the people a blog wants.
	 *
	 * Two queries, run once per submitted comment. On a table with hundreds of
	 * thousands of rows they are a scan, which is acceptable for a form post
	 * and nowhere near a page view.
	 *
	 * @param array<string,mixed> $commentdata Incoming comment data.
	 * @return array<string,bool>
	 * @since  2.1.58
	 */
	private function history_for( array $commentdata ) {
		global $wpdb;

		$history = array(
			'link_target_trusted' => false,
			'link_target_repeats' => false,
			'body_seen_before'    => false,
		);

		if ( ! $wpdb instanceof wpdb ) {
			return $history;
		}

		$url   = trim( (string) ( $commentdata['comment_author_url'] ?? '' ) );
		$hosts = '' !== $url ? self::hosts( array( $url ) ) : array();

		if ( array() !== $hosts ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- One-off lookup on a form post; a cache would be stale by design.
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT comment_approved, COUNT(*) AS total FROM {$wpdb->comments} WHERE comment_author_url LIKE %s GROUP BY comment_approved",
					'%' . $wpdb->esc_like( $hosts[0] ) . '%'
				)
			);

			$total = 0;
			foreach ( (array) $rows as $row ) {
				$total += (int) $row->total;
				if ( '1' === (string) $row->comment_approved ) {
					$history['link_target_trusted'] = true;
				}
			}
			$history['link_target_repeats'] = $total >= self::REPEAT_TARGET;
		}

		$body = trim( (string) ( $commentdata['comment_content'] ?? '' ) );

		if ( mb_strlen( $body ) >= self::DUPLICATE_BODY ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- One-off lookup on a form post; a cache would be stale by design.
			$seen = $wpdb->get_var(
				$wpdb->prepare(
					"SELECT comment_ID FROM {$wpdb->comments} WHERE comment_content LIKE %s LIMIT 1",
					$wpdb->esc_like( mb_substr( $body, 0, self::DUPLICATE_PREFIX ) ) . '%'
				)
			);

			$history['body_seen_before'] = null !== $seen;
		}

		return $history;
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
		if ( $monitor instanceof ReportedIP_Hive_Security_Monitor && self::verdict_may_block( $this->verdict ) ) {
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
	 *                                     `form_proof`, `form_proof_seconds`,
	 *                                     `fast_seconds`, `renders_anchors`,
	 *                                     `user_agent`, `locale`,
	 *                                     `link_target_trusted`,
	 *                                     `link_target_repeats`,
	 *                                     `body_seen_before`. A key that is
	 *                                     absent switches its signal off, so a
	 *                                     caller that cannot answer a question
	 *                                     never has to guess.
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
			$score    += 7;
			$reasons[] = 'url_in_author_name';
		}

		if ( '' !== $email && array() !== $rules && class_exists( 'ReportedIP_Hive_Disposable_Email' ) ) {
			$domain = ReportedIP_Hive_Disposable_Email::domain_of( $email );
			if ( '' !== $domain && 'disposable' === ReportedIP_Hive_Disposable_Email::classify_domain( $domain, $rules ) ) {
				$score    += 2;
				$reasons[] = 'disposable_email';
			}
		}

		$user_agent = isset( $context['user_agent'] ) ? (string) $context['user_agent'] : null;

		if ( null !== $user_agent && ! self::looks_like_browser( $user_agent ) ) {
			$score    += 4;
			$reasons[] = 'no_browser_ua';
		}

		if ( preg_match( self::PASTED_MARKUP_PATTERN, $body ) ) {
			$score    += 5;
			$reasons[] = 'pasted_link_markup';
		} elseif ( preg_match( self::ANCHOR_PATTERN, $body ) ) {
			$score    += 3;
			$reasons[] = 'html_link_markup';
		}

		if ( '' !== $author && preg_match( '/\d/', $author ) ) {
			$score    += 2;
			$reasons[] = 'digits_in_author_name';
		}

		if ( self::foreign_ratio( $author ) > self::FOREIGN_NAME_RATIO
			|| self::foreign_ratio( $body ) > self::FOREIGN_BODY_RATIO ) {
			$score    += 2;
			$reasons[] = 'foreign_script';
		}

		if ( '' !== $author_url
			&& mb_strlen( $body ) >= self::LANGUAGE_BODY
			&& self::reads_as_foreign_language( $body, isset( $context['locale'] ) ? (string) $context['locale'] : '' ) ) {
			$score    += 2;
			$reasons[] = 'language_mismatch';
		}

		if ( '' !== $author_url && preg_match( self::PRAISE_PATTERN, $body ) ) {
			$score    += 2;
			$reasons[] = 'praise_opener_with_url';
		}

		if ( '' !== $author_url && empty( $context['link_target_trusted'] ) ) {
			++$score;
			$reasons[] = 'author_url';

			if ( ! empty( $context['link_target_repeats'] ) ) {
				$score    += 2;
				$reasons[] = 'repeat_link_target';
			}
		}

		if ( ! empty( $context['body_seen_before'] ) && mb_strlen( $body ) >= self::DUPLICATE_BODY ) {
			$score    += 3;
			$reasons[] = 'duplicate_body';
		}

		$proof = isset( $context['form_proof'] ) ? (string) $context['form_proof'] : '';

		if ( 'tripped' === $proof ) {
			$score    += 7;
			$reasons[] = 'form_decoy_filled';
		} elseif ( 'failed' === $proof ) {
			$score    += 4;
			$reasons[] = 'no_js_proof';
		} elseif ( 'absent' === $proof && ! empty( $context['renders_anchors'] ) ) {
			$score    += 4;
			$reasons[] = 'no_js_proof';
		} elseif ( 'absent' === $proof ) {
			++$score;
			$reasons[] = 'no_form_field';
		}

		$seconds = isset( $context['form_proof_seconds'] ) ? $context['form_proof_seconds'] : null;
		$fast    = isset( $context['fast_seconds'] ) ? (int) $context['fast_seconds'] : 0;

		if ( null !== $seconds && $fast > 0 && (int) $seconds < $fast ) {
			$score    += 2;
			$reasons[] = 'too_fast';
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
	 * Whether a user-agent string could have come from a browser.
	 *
	 * Two things disqualify it. An empty string, because every browser sends
	 * the header and a script often does not. And a string that claims WebKit
	 * without carrying the token every real WebKit build carries, because that
	 * is a user-agent assembled from memory rather than reported by an engine.
	 *
	 * Must be given the full header. The truncated copy the logger keeps cuts
	 * the string before the token and would fail every genuine browser.
	 *
	 * @param string $user_agent Raw user-agent header.
	 * @return bool
	 * @since  2.1.58
	 */
	public static function looks_like_browser( $user_agent ) {
		$user_agent = trim( (string) $user_agent );

		if ( '' === $user_agent ) {
			return false;
		}

		if ( false !== strpos( $user_agent, 'AppleWebKit/' )
			&& false === strpos( $user_agent, self::WEBKIT_TOKEN ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Share of a string that sits outside the Latin ranges.
	 *
	 * @param string $text Text to measure.
	 * @return float Between 0 and 1.
	 * @since  2.1.58
	 */
	public static function foreign_ratio( $text ) {
		$text   = (string) $text;
		$length = mb_strlen( $text );

		if ( 0 === $length ) {
			return 0.0;
		}

		$hits = preg_match_all( self::FOREIGN_PATTERN, $text );

		return $hits ? $hits / $length : 0.0;
	}

	/**
	 * Whether a body carries none of the stop words of the site language.
	 *
	 * A language without a word list answers false: an unknown language is not
	 * evidence of anything, and guessing would flag every comment on a site we
	 * have no list for.
	 *
	 * Words that exist in both languages (`was`, `war`, `man`, `die`, `also`)
	 * are deliberately left in. They make the check answer false more often
	 * than it strictly could, which errs towards the reader and away from the
	 * filter. That is the direction to err in here.
	 *
	 * @param string $body   Comment body.
	 * @param string $locale Site locale, e.g. `de_DE`.
	 * @return bool
	 * @since  2.1.58
	 */
	public static function reads_as_foreign_language( $body, $locale ) {
		$language = strtolower( substr( (string) $locale, 0, 2 ) );

		if ( ! isset( self::LANGUAGE_WORDS[ $language ] ) ) {
			return false;
		}

		$body = mb_strtolower( (string) $body );

		foreach ( self::LANGUAGE_WORDS[ $language ] as $word ) {
			if ( preg_match( '/(?<![\p{L}])' . preg_quote( $word, '/' ) . '(?![\p{L}])/u', $body ) ) {
				return false;
			}
		}

		return true;
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
	 * Carries the threshold on its own since 2.1.58: across 6515 comments a
	 * human approved over eleven years, not one had a domain in the name field,
	 * while 826 refused ones did.
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
