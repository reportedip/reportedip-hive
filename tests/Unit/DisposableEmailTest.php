<?php
/**
 * Unit tests for the disposable-email registration sensor.
 *
 * Locks the classification core: throwaway domains are caught (including
 * sub-domains, label-boundary aware), privacy relays are recognised as a
 * distinct legitimate category, and ordinary addresses pass through.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.2
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-disposable-email.php';

	/**
	 * @covers \ReportedIP_Hive_Disposable_Email
	 */
	class DisposableEmailTest extends TestCase {

		private const RULES = array( 'mailinator.com', 'temp-mail.org', 'yopmail.com' );

		public function test_domain_of_extracts_lowercased_domain(): void {
			$this->assertSame( 'example.com', \ReportedIP_Hive_Disposable_Email::domain_of( 'Jane@Example.COM' ) );
		}

		public function test_domain_of_handles_missing_at(): void {
			$this->assertSame( '', \ReportedIP_Hive_Disposable_Email::domain_of( 'not-an-email' ) );
		}

		public function test_domain_of_uses_last_at(): void {
			$this->assertSame( 'c.com', \ReportedIP_Hive_Disposable_Email::domain_of( 'a@b@c.com' ) );
		}

		public function test_classify_flags_disposable(): void {
			$this->assertSame( 'disposable', \ReportedIP_Hive_Disposable_Email::classify_domain( 'mailinator.com', self::RULES ) );
		}

		public function test_classify_flags_disposable_subdomain(): void {
			$this->assertSame( 'disposable', \ReportedIP_Hive_Disposable_Email::classify_domain( 'mail.mailinator.com', self::RULES ) );
		}

		public function test_classify_respects_label_boundary(): void {
			$this->assertSame( 'clean', \ReportedIP_Hive_Disposable_Email::classify_domain( 'notmailinator.com', self::RULES ) );
		}

		public function test_classify_passes_clean_domain(): void {
			$this->assertSame( 'clean', \ReportedIP_Hive_Disposable_Email::classify_domain( 'gmail.com', self::RULES ) );
		}

		public function test_classify_recognises_baked_relay(): void {
			$this->assertSame( 'relay', \ReportedIP_Hive_Disposable_Email::classify_domain( 'abc.privaterelay.appleid.com', self::RULES ) );
		}

		public function test_classify_recognises_tagged_relay_rule(): void {
			$rules = array(
				array( 'domain' => 'fwd.example.net', 'category' => 'relay' ),
			);
			$this->assertSame( 'relay', \ReportedIP_Hive_Disposable_Email::classify_domain( 'fwd.example.net', $rules ) );
		}

		public function test_classify_tagged_disposable_rule(): void {
			$rules = array(
				array( 'domain' => 'throwaway.test', 'category' => 'disposable' ),
			);
			$this->assertSame( 'disposable', \ReportedIP_Hive_Disposable_Email::classify_domain( 'throwaway.test', $rules ) );
		}

		public function test_emails_in_finds_nested_addresses_once(): void {
			$post = array(
				'your-email' => 'Jane@Mailinator.com',
				'form_fields' => array( 'email' => 'jane@mailinator.com', 'name' => 'Jane' ),
				'wpforms'     => array( 'fields' => array( 3 => ' bob@example.org ' ) ),
				'message'     => 'mail me at no-address',
				'count'       => 7,
			);
			$this->assertSame(
				array( 'jane@mailinator.com', 'bob@example.org' ),
				\ReportedIP_Hive_Disposable_Email::emails_in( $post )
			);
		}

		public function test_emails_in_ignores_free_text_with_an_at_sign(): void {
			$this->assertSame( array(), \ReportedIP_Hive_Disposable_Email::emails_in( array( 'message' => 'write to jane@mailinator.com please' ) ) );
		}

		public function test_forms_action_defaults_to_block(): void {
			global $wp_options;
			unset( $wp_options[ \ReportedIP_Hive_Disposable_Email::OPT_FORMS_ACTION ] );
			$this->assertSame( 'block', \ReportedIP_Hive_Disposable_Email::get_instance()->forms_action() );
			$wp_options[ \ReportedIP_Hive_Disposable_Email::OPT_FORMS_ACTION ] = 'nonsense';
			$this->assertSame( 'block', \ReportedIP_Hive_Disposable_Email::get_instance()->forms_action() );
			unset( $wp_options[ \ReportedIP_Hive_Disposable_Email::OPT_FORMS_ACTION ] );
		}

		public function test_check_submission_is_silent_when_off(): void {
			global $wp_options;
			$wp_options[ \ReportedIP_Hive_Disposable_Email::OPT_FORMS_ACTION ] = 'off';
			$this->assertSame( '', \ReportedIP_Hive_Disposable_Email::get_instance()->check_submission( 'cf7', array( 'a@mailinator.com' ) ) );
			unset( $wp_options[ \ReportedIP_Hive_Disposable_Email::OPT_FORMS_ACTION ] );
		}
	}
}
