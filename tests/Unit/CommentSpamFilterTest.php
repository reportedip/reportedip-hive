<?php
/**
 * Unit tests for the comment spam classifier.
 *
 * The positive cases are real comments taken from a production site that was
 * receiving several hundred of them a day; the negative cases are the ordinary
 * reader comments the filter must never touch, including the one that leaves a
 * website address behind.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.52
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-comment-spam-filter.php';

	/**
	 * @covers \ReportedIP_Hive_Comment_Spam_Filter
	 */
	class CommentSpamFilterTest extends TestCase {

		/**
		 * Score a comment with the stock context.
		 *
		 * @param array<string,mixed> $comment Comment fields.
		 * @param array<string,mixed> $context Context overrides.
		 * @return array{score:int, reasons:array<int,string>}
		 */
		private function score( array $comment, array $context = array() ): array {
			return \ReportedIP_Hive_Comment_Spam_Filter::score(
				$comment,
				array_merge( array( 'max_links' => 2 ), $context )
			);
		}

		/**
		 * Whether the score reaches the spam threshold.
		 *
		 * @param array<string,mixed> $comment Comment fields.
		 * @param array<string,mixed> $context Context overrides.
		 * @return bool
		 */
		private function is_spam( array $comment, array $context = array() ): bool {
			return $this->score( $comment, $context )['score'] >= \ReportedIP_Hive_Comment_Spam_Filter::THRESHOLD;
		}

		public function test_link_with_no_message_is_spam(): void {
			$this->assertTrue(
				$this->is_spam(
					array(
						'comment_author'     => 'dolandirici numaralari',
						'comment_author_url' => 'https://m.casibombomgirisi.com',
						'comment_content'    => 'thanks',
					)
				)
			);
		}

		public function test_giveaway_tld_adds_to_the_score(): void {
			$verdict = $this->score(
				array(
					'comment_author'     => 'vajinada sigil neden olur',
					'comment_author_url' => 'https://casi.bom-google.icu',
					'comment_content'    => 'thxx',
				)
			);

			$this->assertContains( 'risky_tld', $verdict['reasons'] );
			$this->assertContains( 'url_with_no_message', $verdict['reasons'] );
			$this->assertContains( 'filler_body', $verdict['reasons'] );
		}

		/**
		 * A short advert carrying two domains. None of its signals is decisive
		 * on its own, which is the point: four small ones add up.
		 */
		public function test_short_advert_with_two_domains_is_spam(): void {
			$verdict = $this->score(
				array(
					'comment_author'     => 'Kylan Branch',
					'comment_author_url' => 'https://ethminer.pages.dev',
					'comment_content'    => 'Start Small Earn Big With ETH Mining https://ethminer.surge.sh',
				),
				array( 'locale' => 'de_DE' )
			);

			$this->assertContains( 'link_density', $verdict['reasons'] );
			$this->assertContains( 'multiple_domains', $verdict['reasons'] );
			$this->assertContains( 'language_mismatch', $verdict['reasons'] );
			$this->assertGreaterThanOrEqual( \ReportedIP_Hive_Comment_Spam_Filter::THRESHOLD, $verdict['score'] );
		}

		public function test_author_name_that_is_a_domain_is_spam(): void {
			$this->assertTrue(
				$this->is_spam(
					array(
						'comment_author'     => 'cheap-pills.com',
						'comment_author_url' => 'https://cheap-pills.com',
						'comment_content'    => 'Have a look at our offer, the prices are the lowest you will find anywhere today.',
					)
				)
			);
		}

		public function test_link_flood_is_spam(): void {
			$this->assertTrue(
				$this->is_spam(
					array(
						'comment_author'  => 'Marta',
						'comment_content' => 'Read https://a-example.com and https://b-example.com and also https://c-example.com for the full story about this topic.',
					)
				)
			);
		}

		public function test_plain_reader_comment_is_clean(): void {
			$verdict = $this->score(
				array(
					'comment_author'     => 'Sabine Wolters',
					'comment_author_url' => '',
					'comment_content'    => 'Ich war letzte Woche dort und kann den Artikel nur bestätigen. Der Innenhof ist wirklich einen Umweg wert.',
				)
			);

			$this->assertSame( 0, $verdict['score'] );
			$this->assertSame( array(), $verdict['reasons'] );
		}

		public function test_reader_who_leaves_their_website_is_clean(): void {
			$verdict = $this->score(
				array(
					'comment_author'     => 'Jonas Weber',
					'comment_author_url' => 'https://jonas-weber.de',
					'comment_content'    => 'Danke für den Hinweis, ich habe das Café gestern ausprobiert und war ziemlich begeistert.',
				)
			);

			$this->assertLessThan( \ReportedIP_Hive_Comment_Spam_Filter::THRESHOLD, $verdict['score'] );
		}

		public function test_short_comment_without_a_link_is_clean(): void {
			$verdict = $this->score(
				array(
					'comment_author'  => 'Tom',
					'comment_content' => 'Danke!',
				)
			);

			$this->assertLessThan( \ReportedIP_Hive_Comment_Spam_Filter::THRESHOLD, $verdict['score'] );
		}

		public function test_single_source_link_in_a_long_comment_is_clean(): void {
			$verdict = $this->score(
				array(
					'comment_author'  => 'Petra',
					'comment_content' => 'Die Zahlen stimmen so nicht, das Statistische Amt weist für 2025 andere Werte aus. Nachzulesen ist das hier: https://www.muenchen.de/statistik-2025 und dort sind auch die Vorjahre aufgeführt, falls jemand vergleichen möchte.',
				)
			);

			$this->assertLessThan( \ReportedIP_Hive_Comment_Spam_Filter::THRESHOLD, $verdict['score'] );
		}

		/**
		 * A plain reader comment on a site that is not known to plant anchors:
		 * the missing field keeps the lenient weight it had before 2.1.53, so a
		 * theme with hand-written comment markup is not punished for it.
		 */
		public function test_absent_proof_without_render_evidence_stays_lenient(): void {
			$verdict = $this->score(
				array(
					'comment_author'  => 'Tom',
					'comment_content' => 'Danke für den ausführlichen Bericht, das hat mir sehr geholfen.',
				),
				array( 'form_proof' => 'absent' )
			);

			$this->assertSame( 1, $verdict['score'] );
			$this->assertSame( array( 'no_form_field' ), $verdict['reasons'] );
			$this->assertLessThan( \ReportedIP_Hive_Comment_Spam_Filter::THRESHOLD, $verdict['score'] );
		}

		/**
		 * The same submission on a site that demonstrably renders anchors: the
		 * sender never loaded the form, which is the blind direct poster.
		 *
		 * It weighs heavily but not enough on its own. Someone browsing with
		 * JavaScript switched off produces this and nothing else, and filing
		 * their comment as spam for that alone is the false positive the
		 * threshold was raised to prevent in 2.1.58.
		 */
		public function test_absent_proof_with_render_evidence_needs_corroboration(): void {
			$verdict = $this->score(
				array(
					'comment_author'  => 'Tom',
					'comment_content' => 'Danke für den ausführlichen Bericht, das hat mir sehr geholfen.',
				),
				array(
					'form_proof'      => 'absent',
					'renders_anchors' => true,
				)
			);

			$this->assertSame( 4, $verdict['score'] );
			$this->assertSame( array( 'no_js_proof' ), $verdict['reasons'] );
			$this->assertLessThan( \ReportedIP_Hive_Comment_Spam_Filter::THRESHOLD, $verdict['score'] );
		}

		public function test_failed_proof_needs_corroboration(): void {
			$verdict = $this->score(
				array(
					'comment_author'  => 'Tom',
					'comment_content' => 'Danke für den ausführlichen Bericht, das hat mir sehr geholfen.',
				),
				array( 'form_proof' => 'failed' )
			);

			$this->assertSame( 4, $verdict['score'] );
			$this->assertSame( array( 'no_js_proof' ), $verdict['reasons'] );
			$this->assertLessThan( \ReportedIP_Hive_Comment_Spam_Filter::THRESHOLD, $verdict['score'] );
		}

		/**
		 * The reader without JavaScript, written out in full: a browser that
		 * identifies itself, a comment in the site language, no link, and a
		 * missing proof. This must stay clean, and it is the regression test
		 * for the whole point of raising the threshold.
		 */
		public function test_a_reader_without_javascript_stays_clean(): void {
			$verdict = $this->score(
				array(
					'comment_author'  => 'Tom',
					'comment_content' => 'Danke für den ausführlichen Bericht, das hat mir sehr geholfen.',
				),
				array(
					'form_proof'      => 'failed',
					'renders_anchors' => true,
					'user_agent'      => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
					'locale'          => 'de_DE',
				)
			);

			$this->assertLessThan( \ReportedIP_Hive_Comment_Spam_Filter::THRESHOLD, $verdict['score'] );
		}

		/**
		 * A filled decoy field has no innocent reading, so it carries the
		 * threshold on its own and must keep doing so whenever the threshold
		 * moves.
		 */
		public function test_tripped_decoy_reaches_the_threshold_on_its_own(): void {
			$verdict = $this->score(
				array(
					'comment_author'  => 'Tom',
					'comment_content' => 'Danke für den ausführlichen Bericht, das hat mir sehr geholfen.',
				),
				array( 'form_proof' => 'tripped' )
			);

			$this->assertSame( array( 'form_decoy_filled' ), $verdict['reasons'] );
			$this->assertGreaterThanOrEqual( \ReportedIP_Hive_Comment_Spam_Filter::THRESHOLD, $verdict['score'] );
		}

		public function test_proved_execution_scores_nothing(): void {
			$verdict = $this->score(
				array(
					'comment_author'  => 'Tom',
					'comment_content' => 'Danke für den ausführlichen Bericht, das hat mir sehr geholfen.',
				),
				array( 'form_proof' => 'proved' )
			);

			$this->assertSame( 0, $verdict['score'] );
		}

		/**
		 * Running the script is not absolution. A bot that executes JavaScript
		 * and then posts link spam is still caught by the content signals.
		 */
		public function test_proved_execution_does_not_suppress_content_signals(): void {
			$verdict = $this->score(
				array(
					'comment_author'     => 'dolandirici numaralari',
					'comment_author_url' => 'https://m.casibombomgirisi.com',
					'comment_content'    => 'thanks',
				),
				array( 'form_proof' => 'proved' )
			);

			$this->assertGreaterThanOrEqual( \ReportedIP_Hive_Comment_Spam_Filter::THRESHOLD, $verdict['score'] );
		}

		/**
		 * A verdict resting on the missing execution proof alone must not feed
		 * the per-address counter, or a reader browsing without JavaScript is
		 * blocked after five comments.
		 */
		public function test_a_lone_missing_proof_never_feeds_the_block_counter(): void {
			$this->assertFalse(
				\ReportedIP_Hive_Comment_Spam_Filter::verdict_may_block(
					array(
						'score'   => 4,
						'reasons' => array( 'no_js_proof' ),
					)
				)
			);
		}

		public function test_a_corroborated_verdict_feeds_the_block_counter(): void {
			$this->assertTrue(
				\ReportedIP_Hive_Comment_Spam_Filter::verdict_may_block(
					array(
						'score'   => 6,
						'reasons' => array( 'no_js_proof', 'risky_tld' ),
					)
				)
			);
			$this->assertTrue(
				\ReportedIP_Hive_Comment_Spam_Filter::verdict_may_block(
					array(
						'score'   => 6,
						'reasons' => array( 'form_decoy_filled' ),
					)
				)
			);
			$this->assertTrue( \ReportedIP_Hive_Comment_Spam_Filter::verdict_may_block( null ) );
		}

		public function test_links_in_finds_bare_and_prefixed_urls(): void {
			$links = \ReportedIP_Hive_Comment_Spam_Filter::links_in( 'see https://a.example and www.b.example for more' );

			$this->assertSame( array( 'https://a.example', 'www.b.example' ), $links );
		}

		public function test_hosts_deduplicates_and_strips_www(): void {
			$hosts = \ReportedIP_Hive_Comment_Spam_Filter::hosts(
				array( 'https://www.example.com/a', 'http://example.com/b', 'https://other.example.org' )
			);

			$this->assertSame( array( 'example.com', 'other.example.org' ), $hosts );
		}

		public function test_risky_tld_matches_the_last_label_only(): void {
			$this->assertTrue( \ReportedIP_Hive_Comment_Spam_Filter::has_risky_tld( 'shop.example.icu' ) );
			$this->assertFalse( \ReportedIP_Hive_Comment_Spam_Filter::has_risky_tld( 'icu.example.de' ) );
		}

		public function test_author_name_url_detection(): void {
			$this->assertTrue( \ReportedIP_Hive_Comment_Spam_Filter::looks_like_url( 'https://spam.example' ) );
			$this->assertTrue( \ReportedIP_Hive_Comment_Spam_Filter::looks_like_url( 'best-casino.com' ) );
			$this->assertTrue( \ReportedIP_Hive_Comment_Spam_Filter::looks_like_url( 'visit shop.online now' ) );
			$this->assertFalse( \ReportedIP_Hive_Comment_Spam_Filter::looks_like_url( 'Anna Schmidt' ) );
			$this->assertFalse( \ReportedIP_Hive_Comment_Spam_Filter::looks_like_url( 'Dr. Weber' ) );
		}

		/**
		 * A comment held for moderation is not spam. Until 2.1.52 the
		 * `comment_post` handler treated `$approved === 0` as a spam verdict,
		 * so on a site with moderation switched on every regular reader was
		 * logged, counted towards the block ladder and reported.
		 */
		public function test_comment_post_handler_only_reacts_to_a_spam_verdict(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/reportedip-hive.php' );
			$start  = strpos( $source, 'public function handle_comment_post(' );
			$this->assertNotFalse( $start, 'handle_comment_post() not found.' );
			$body = substr( $source, $start, 2200 );

			$this->assertStringNotContainsString( '$approved === 0', $body );
			$this->assertStringContainsString( "'spam' !== \$approved", $body );
		}

		/**
		 * One submitted comment counts once towards the block ladder. Two
		 * layers report the same comment, the honeypot at `preprocess_comment`
		 * and the `comment_post` handler once the verdict is set, so the guard
		 * belongs in the counter rather than in either caller.
		 */
		public function test_the_comment_counter_refuses_to_count_twice(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-security-monitor.php' );
			$start  = strpos( $source, 'public function check_comment_spam_threshold(' );
			$this->assertNotFalse( $start, 'check_comment_spam_threshold() not found.' );
			$body = substr( $source, $start, 600 );

			$this->assertStringContainsString( '$this->comment_counted', $body );
			$this->assertStringContainsString( 'private $comment_counted = false;', $source );
		}

		public function test_max_links_setting_is_honoured(): void {
			$comment = array(
				'comment_author'  => 'Marta',
				'comment_content' => 'Zwei Belege dazu: https://a-example.com und https://b-example.com, beide aus dem letzten Jahr und beide gut lesbar.',
			);

			$this->assertNotContains( 'link_flood', $this->score( $comment, array( 'max_links' => 2 ) )['reasons'] );
			$this->assertContains( 'link_flood', $this->score( $comment, array( 'max_links' => 1 ) )['reasons'] );
		}

		/**
		 * The user-agent check, which was the single most telling signal in the
		 * measurement: 14548 refused comments carried no usable one, and not a
		 * single approved comment in eleven years was missing it.
		 *
		 * @dataProvider user_agent_cases
		 */
		public function test_user_agent_is_read_as_browser_or_not( string $user_agent, bool $is_browser ): void {
			$this->assertSame( $is_browser, \ReportedIP_Hive_Comment_Spam_Filter::looks_like_browser( $user_agent ) );
		}

		/**
		 * @return array<string, array{0:string, 1:bool}>
		 */
		public function user_agent_cases(): array {
			return array(
				'chrome on windows' => array( 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36', true ),
				'safari on iphone'  => array( 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1', true ),
				'firefox'           => array( 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0', true ),
				'empty'             => array( '', false ),
				'whitespace only'   => array( "  \t ", false ),
				'webkit forgery'    => array( 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118.0.0.0 Safari/537.36', false ),
			);
		}

		/**
		 * The header must be read whole. Several places in the plugin keep a
		 * shortened copy for logging, and a cut that lands between the WebKit
		 * version and its token turns every genuine browser into a forgery.
		 */
		public function test_a_truncated_header_would_break_the_check(): void {
			$full = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

			$this->assertTrue( \ReportedIP_Hive_Comment_Spam_Filter::looks_like_browser( $full ) );
			$this->assertFalse(
				\ReportedIP_Hive_Comment_Spam_Filter::looks_like_browser( substr( $full, 0, 70 ) ),
				'A copy cut inside the WebKit token must never be fed to the check.'
			);
		}

		public function test_a_missing_user_agent_scores_but_does_not_convict(): void {
			$comment = array(
				'comment_author'  => 'Tom',
				'comment_content' => 'Danke für den ausführlichen Bericht, das hat mir sehr geholfen.',
			);

			$verdict = $this->score( $comment, array( 'user_agent' => '' ) );

			$this->assertContains( 'no_browser_ua', $verdict['reasons'] );
			$this->assertLessThan( \ReportedIP_Hive_Comment_Spam_Filter::THRESHOLD, $verdict['score'] );
			$this->assertNotContains( 'no_browser_ua', $this->score( $comment )['reasons'] );
		}

		/**
		 * Spam tools scrape rendered comments from other sites and post the
		 * result back as input. Nobody types a rel attribute into a comment box.
		 */
		public function test_pasted_link_markup_outweighs_a_hand_written_anchor(): void {
			$pasted = $this->score(
				array(
					'comment_author'  => 'Payday',
					'comment_content' => '<a href="https://example.com/loans" rel="nofollow ugc">quick and easy loans</a>',
				)
			);
			$plain  = $this->score(
				array(
					'comment_author'  => 'Tom',
					'comment_content' => 'Mehr dazu steht <a href="https://example.com">in diesem Beitrag</a>, sehr lesenswert.',
				)
			);

			$this->assertContains( 'pasted_link_markup', $pasted['reasons'] );
			$this->assertNotContains( 'html_link_markup', $pasted['reasons'] );
			$this->assertContains( 'html_link_markup', $plain['reasons'] );
			$this->assertGreaterThan( $plain['score'], $pasted['score'] );
		}

		public function test_an_escaped_anchor_counts_the_same(): void {
			$verdict = $this->score(
				array(
					'comment_author'  => 'Tom',
					'comment_content' => '&lt;a href="https://example.com"&gt;look here&lt;/a&gt;',
				)
			);

			$this->assertContains( 'html_link_markup', $verdict['reasons'] );
		}

		public function test_digits_in_the_author_name_are_a_signal(): void {
			$this->assertContains(
				'digits_in_author_name',
				$this->score( array( 'comment_author' => 'Smithd275' ) )['reasons']
			);
			$this->assertNotContains(
				'digits_in_author_name',
				$this->score( array( 'comment_author' => 'Stephanie Wittmann' ) )['reasons']
			);
		}

		/**
		 * Foreign script is measured as a share of the string. A shrug emoticon
		 * carries a single Katakana and is not a foreign name; that exact
		 * comment was a false positive while the check ran per character.
		 */
		public function test_a_shrug_emoticon_is_not_foreign_script(): void {
			$this->assertNotContains(
				'foreign_script',
				$this->score(
					array(
						'comment_author'  => 'Jan Krattiger',
						'comment_content' => '¯\_(ツ)_/¯',
					)
				)['reasons']
			);

			$this->assertContains(
				'foreign_script',
				$this->score(
					array(
						'comment_author'  => '수원출장마사지',
						'comment_content' => 'Danke für den Beitrag.',
					)
				)['reasons']
			);
		}

		/**
		 * The language check needs a link in the author field to fire at all,
		 * enough text to be meaningful, and a locale it has words for.
		 */
		public function test_language_mismatch_needs_a_link_text_and_a_known_locale(): void {
			$english = array(
				'comment_author'     => 'Alex',
				'comment_author_url' => 'https://example.com',
				'comment_content'    => 'Thank you for sharing this excellent guide, I will definitely try these tips on my project.',
			);

			$this->assertContains( 'language_mismatch', $this->score( $english, array( 'locale' => 'de_DE' ) )['reasons'] );
			$this->assertNotContains( 'language_mismatch', $this->score( $english, array( 'locale' => 'en_US' ) )['reasons'] );
			$this->assertNotContains( 'language_mismatch', $this->score( $english, array( 'locale' => 'fi' ) )['reasons'] );
			$this->assertNotContains( 'language_mismatch', $this->score( $english )['reasons'] );

			$without_link = $english;
			unset( $without_link['comment_author_url'] );
			$this->assertNotContains( 'language_mismatch', $this->score( $without_link, array( 'locale' => 'de_DE' ) )['reasons'] );
		}

		public function test_a_short_german_aside_is_not_a_language_mismatch(): void {
			$this->assertNotContains(
				'language_mismatch',
				$this->score(
					array(
						'comment_author'     => 'Genevieve Cory',
						'comment_author_url' => 'https://example.com',
						'comment_content'    => 'Dieser Maps-Link dürfte besser funktionieren.',
					),
					array( 'locale' => 'de_DE' )
				)['reasons']
			);
		}

		/**
		 * A link target the site has already published is somebody's own site,
		 * not a campaign. Without this exemption the repeat signal punishes the
		 * regular commenters a blog wants to keep.
		 */
		public function test_a_published_link_target_is_exempt(): void {
			$comment = array(
				'comment_author'     => 'Jan Krattiger',
				'comment_author_url' => 'https://jankrattiger.example',
				'comment_content'    => 'Liebe Maya, wir können dir leider selber nicht weiterhelfen, da wir nur den Kalender pflegen.',
			);

			$stranger = $this->score( $comment, array( 'link_target_repeats' => true ) );
			$regular  = $this->score(
				$comment,
				array(
					'link_target_repeats' => true,
					'link_target_trusted' => true,
				)
			);

			$this->assertContains( 'repeat_link_target', $stranger['reasons'] );
			$this->assertNotContains( 'repeat_link_target', $regular['reasons'] );
			$this->assertNotContains( 'author_url', $regular['reasons'] );
			$this->assertSame( 0, $regular['score'] );
		}

		public function test_a_repeated_body_counts_only_when_long_enough(): void {
			$long  = array(
				'comment_author'  => 'Tom',
				'comment_content' => 'Thank you for your sharing. I am worried that I lack creative ideas.',
			);
			$short = array(
				'comment_author'  => 'Tom',
				'comment_content' => 'Ritournelle!',
			);

			$this->assertContains( 'duplicate_body', $this->score( $long, array( 'body_seen_before' => true ) )['reasons'] );
			$this->assertNotContains( 'duplicate_body', $this->score( $short, array( 'body_seen_before' => true ) )['reasons'] );
		}

		/**
		 * The praise opener only counts next to a link. On its own it is how a
		 * polite reader starts a sentence.
		 */
		public function test_praise_counts_only_next_to_a_link(): void {
			$body = 'Thank you for your sharing, I found the whole piece genuinely useful.';

			$this->assertContains(
				'praise_opener_with_url',
				$this->score(
					array(
						'comment_author'     => 'Alex',
						'comment_author_url' => 'https://example.com',
						'comment_content'    => $body,
					)
				)['reasons']
			);
			$this->assertNotContains(
				'praise_opener_with_url',
				$this->score(
					array(
						'comment_author'  => 'Alex',
						'comment_content' => $body,
					)
				)['reasons']
			);
		}

		/**
		 * The author name that is a domain carries the threshold on its own:
		 * 826 refused comments had one, none of the 6515 approved ones did.
		 */
		public function test_a_domain_in_the_author_name_convicts_on_its_own(): void {
			$verdict = $this->score( array( 'comment_author' => 'cheap-pills.com' ) );

			$this->assertSame( array( 'url_in_author_name' ), $verdict['reasons'] );
			$this->assertGreaterThanOrEqual( \ReportedIP_Hive_Comment_Spam_Filter::THRESHOLD, $verdict['score'] );
		}
	}
}
