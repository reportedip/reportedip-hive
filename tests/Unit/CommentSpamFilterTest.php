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

		public function test_short_advert_with_two_domains_is_spam(): void {
			$verdict = $this->score(
				array(
					'comment_author'     => 'Kylan Branch',
					'comment_author_url' => 'https://ethminer.pages.dev',
					'comment_content'    => 'Start Small Earn Big With ETH Mining https://ethminer.surge.sh',
				)
			);

			$this->assertContains( 'link_density', $verdict['reasons'] );
			$this->assertContains( 'multiple_domains', $verdict['reasons'] );
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
		 */
		public function test_absent_proof_with_render_evidence_reaches_the_threshold(): void {
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
		}

		public function test_failed_proof_reaches_the_threshold_on_its_own(): void {
			$verdict = $this->score(
				array(
					'comment_author'  => 'Tom',
					'comment_content' => 'Danke für den ausführlichen Bericht, das hat mir sehr geholfen.',
				),
				array( 'form_proof' => 'failed' )
			);

			$this->assertSame( 4, $verdict['score'] );
			$this->assertSame( array( 'no_js_proof' ), $verdict['reasons'] );
		}

		public function test_tripped_decoy_scores_above_the_threshold(): void {
			$verdict = $this->score(
				array(
					'comment_author'  => 'Tom',
					'comment_content' => 'Danke für den ausführlichen Bericht, das hat mir sehr geholfen.',
				),
				array( 'form_proof' => 'tripped' )
			);

			$this->assertSame( 6, $verdict['score'] );
			$this->assertSame( array( 'form_decoy_filled' ), $verdict['reasons'] );
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

		public function test_max_links_setting_is_honoured(): void {
			$comment = array(
				'comment_author'  => 'Marta',
				'comment_content' => 'Zwei Belege dazu: https://a-example.com und https://b-example.com, beide aus dem letzten Jahr und beide gut lesbar.',
			);

			$this->assertNotContains( 'link_flood', $this->score( $comment, array( 'max_links' => 2 ) )['reasons'] );
			$this->assertContains( 'link_flood', $this->score( $comment, array( 'max_links' => 1 ) )['reasons'] );
		}
	}
}
