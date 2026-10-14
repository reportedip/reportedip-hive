<?php
/**
 * Multisite tests for the account block enforcement of the free plugin and
 * for the session reader it keeps.
 *
 * A block record written by a 2.x release, or by the add-on before it was
 * removed, must keep the account out with the free plugin alone: on every
 * sub-site, through the full `authenticate` chain, for cookies and
 * application passwords, and on every plan. Lifting it needs neither the
 * add-on nor a plan. These tests run against a real WordPress + database.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.0
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Account_Block_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Password of the blocked account.
	 */
	const PASSWORD = 'Legacy-Block-2174';

	/**
	 * Account carrying the block record.
	 *
	 * @var int
	 */
	private $target = 0;

	/**
	 * Acting administrator.
	 *
	 * @var int
	 */
	private $actor = 0;

	/**
	 * Skip on single-site runs; create the accounts and write a block record
	 * the way 2.1.74 stored it.
	 */
	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}

		$this->target = self::factory()->user->create(
			array(
				'role'       => 'subscriber',
				'user_login' => 'legacyblocked',
				'user_pass'  => self::PASSWORD,
			)
		);
		$this->actor  = self::factory()->user->create( array( 'role' => 'administrator' ) );
		wp_set_current_user( $this->actor );

		update_user_meta(
			$this->target,
			ReportedIP_Hive_Account_Block::META,
			array(
				'blocked_at' => '2026-09-08 10:00:00',
				'blocked_by' => $this->actor,
				'message'    => 'Offboarded.',
				'note'       => 'HR ticket',
			)
		);
		ReportedIP_Hive_Account_Block::flush_count_memo();
	}

	/**
	 * Drop the block record and the current user.
	 */
	public function tear_down() {
		delete_user_meta( $this->target, ReportedIP_Hive_Account_Block::META );
		ReportedIP_Hive_Option_Routing::delete( 'reportedip_hive_known_tier' );
		ReportedIP_Hive_Mode_Manager::get_instance()->flush_cached_tier();
		ReportedIP_Hive_Account_Block::flush_count_memo();
		wp_set_current_user( 0 );
		parent::tear_down();
	}

	/**
	 * The free plugin runs alone here and still owns the three hooks.
	 */
	public function test_the_free_plugin_alone_registers_the_enforcement() {
		$this->assertFalse( defined( 'REPORTEDIP_HIVE_PRO_VERSION' ), 'the free suite runs without the add-on' );
		$this->assertSame( 30, has_filter( 'authenticate', array( 'ReportedIP_Hive_Account_Block', 'deny_authenticate' ) ) );
		$this->assertSame( 99, has_filter( 'determine_current_user', array( 'ReportedIP_Hive_Account_Block', 'deny_current_user' ) ) );
		$this->assertSame( 4, has_action( 'validate_password_reset', array( 'ReportedIP_Hive_Account_Block', 'deny_password_reset' ) ) );
	}

	/**
	 * The correct password of a blocked account ends in the block error
	 * through the full sign-in chain, on the main site and on a sub-site,
	 * on any plan.
	 */
	public function test_a_stored_block_refuses_the_sign_in_everywhere() {
		$result = wp_authenticate( 'legacyblocked', self::PASSWORD );
		$this->assertWPError( $result );
		$this->assertSame( ReportedIP_Hive_Account_Block::ERROR_CODE, $result->get_error_code() );
		$this->assertStringContainsString( 'Offboarded.', $result->get_error_message() );

		$blog_id = self::factory()->blog->create();
		switch_to_blog( $blog_id );
		$on_subsite = wp_authenticate( 'legacyblocked', self::PASSWORD );
		restore_current_blog();
		$this->assertWPError( $on_subsite );

		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_known_tier', 'business' );
		ReportedIP_Hive_Mode_Manager::get_instance()->flush_cached_tier();
		$this->assertWPError( wp_authenticate( 'legacyblocked', self::PASSWORD ), 'the plan does not change enforcement' );
	}

	/**
	 * Cookies and application passwords resolve to nobody.
	 */
	public function test_a_stored_block_resolves_the_account_to_nobody() {
		$this->assertSame( 0, ReportedIP_Hive_Account_Block::deny_current_user( $this->target ) );
		$this->assertSame( $this->actor, ReportedIP_Hive_Account_Block::deny_current_user( $this->actor ) );
	}

	/**
	 * Lifting the block needs no plan and no add-on, and restores the
	 * sign-in.
	 */
	public function test_unblock_without_the_add_on_restores_the_sign_in() {
		$this->assertSame( 1, ReportedIP_Hive_Account_Block::count_blocked( 0 ) );
		$this->assertTrue( ReportedIP_Hive_Account_Block::unblock( $this->target ) );

		$this->assertFalse( ReportedIP_Hive_Account_Block::is_blocked( $this->target ) );
		$this->assertSame( 0, ReportedIP_Hive_Account_Block::count_blocked( 0 ) );
		$this->assertInstanceOf( 'WP_User', wp_authenticate( 'legacyblocked', self::PASSWORD ) );
	}

	/**
	 * On the user edit screen the free plugin shows a blocked account with
	 * its state and an unblock button; the button lifts the block behind
	 * the profile nonce. The add-on takes the card over through the filter.
	 */
	public function test_the_profile_card_shows_the_block_and_lifts_it() {
		grant_super_admin( $this->actor );
		$user = get_userdata( $this->target );

		ob_start();
		ReportedIP_Hive_Account_Block::render_profile_card( $user );
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'name="rip_account_unblock"', $html );
		$this->assertStringContainsString( 'Offboarded.', $html );
		$this->assertStringContainsString( 'HR ticket', $html );
		$this->assertStringNotContainsString( 'Business', $html, 'no plan named on the card' );
		$this->assertStringNotContainsString( 'nlock', str_replace( array( 'Unblock', 'unblock' ), '', $html ) );

		add_filter( 'reportedip_hive_account_block_card', '__return_false' );
		ob_start();
		ReportedIP_Hive_Account_Block::render_profile_card( $user );
		$this->assertSame( '', (string) ob_get_clean(), 'the add-on draws its own card' );
		remove_filter( 'reportedip_hive_account_block_card', '__return_false' );

		$_POST['rip_account_unblock'] = '1';
		$_REQUEST['_wpnonce']         = wp_create_nonce( 'update-user_' . $this->target );
		try {
			ReportedIP_Hive_Account_Block::save_profile_card( $this->target );
		} finally {
			unset( $_POST['rip_account_unblock'], $_REQUEST['_wpnonce'] );
			revoke_super_admin( $this->actor );
		}
		$this->assertFalse( ReportedIP_Hive_Account_Block::is_blocked( $this->target ) );
	}

	/**
	 * No card for an account without a block, and no unblock for a caller
	 * who may not edit the account.
	 */
	public function test_the_profile_card_needs_a_block_and_the_right_to_edit() {
		$other = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		grant_super_admin( $this->actor );
		ob_start();
		ReportedIP_Hive_Account_Block::render_profile_card( get_userdata( $other ) );
		$this->assertSame( '', (string) ob_get_clean() );
		revoke_super_admin( $this->actor );

		$_POST['rip_account_unblock'] = '1';
		try {
			ReportedIP_Hive_Account_Block::save_profile_card( $this->target );
		} finally {
			unset( $_POST['rip_account_unblock'] );
		}
		$this->assertTrue( ReportedIP_Hive_Account_Block::is_blocked( $this->target ), 'a plain site administrator may not edit a network account' );
	}

	/**
	 * The session manager never cuts the branch it is sitting on.
	 */
	public function test_terminate_refuses_the_callers_own_current_session() {
		$manager = WP_Session_Tokens::get_instance( $this->actor );
		$token   = $manager->create( time() + HOUR_IN_SECONDS );
		wp_set_current_user( $this->actor );
		$verifier = ReportedIP_Hive_User_Sessions::hash_verifier( $token );

		$sessions = ReportedIP_Hive_User_Sessions::for_user( $this->actor );
		$this->assertArrayHasKey( $verifier, $sessions );

		$_COOKIE[ LOGGED_IN_COOKIE ] = wp_generate_auth_cookie( $this->actor, time() + HOUR_IN_SECONDS, 'logged_in', $token );

		$this->assertFalse( ReportedIP_Hive_User_Sessions::terminate( $this->actor, $verifier ) );
		$this->assertArrayHasKey( $verifier, ReportedIP_Hive_User_Sessions::for_user( $this->actor ) );

		unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
	}

	/**
	 * Ending all sessions of another user empties the meta.
	 */
	public function test_terminate_all_empties_the_session_meta() {
		$manager = WP_Session_Tokens::get_instance( $this->target );
		$manager->create( time() + HOUR_IN_SECONDS );
		$manager->create( time() + HOUR_IN_SECONDS );

		$this->assertSame( 2, ReportedIP_Hive_User_Sessions::terminate_all( $this->target ) );
		$this->assertSame( array(), ReportedIP_Hive_User_Sessions::for_user( $this->target ) );
	}
}
