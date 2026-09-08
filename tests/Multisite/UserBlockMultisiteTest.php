<?php
/**
 * Multisite tests for account blocking and the session manager.
 *
 * Users and their sessions are network-global, so a block written on the main
 * site must be in force on every sub-site, and the record must live in user
 * meta rather than in any option store. These tests run against a real
 * WordPress + database so the enforcement path is exercised, not mocked.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.51
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_User_Block_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Account used as the block target.
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
	 * Skip on single-site runs, ensure tables, pretend Business.
	 */
	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}

		ReportedIP_Hive_Schema::ensure_tables();

		$this->target = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->actor  = self::factory()->user->create( array( 'role' => 'administrator' ) );
		wp_set_current_user( $this->actor );

		$this->pretend_tier( 'business' );
	}

	/**
	 * Drop the pretended tier and the block record.
	 */
	public function tear_down() {
		delete_user_meta( $this->target, ReportedIP_Hive_User_Block::META );
		ReportedIP_Hive_Option_Routing::delete( 'reportedip_hive_known_tier' );
		ReportedIP_Hive_Mode_Manager::get_instance()->flush_cached_tier();
		ReportedIP_Hive_User_Block::flush_count_memo();
		wp_set_current_user( 0 );
		parent::tear_down();
	}

	/**
	 * Force the plan the mode manager reports.
	 *
	 * @param string $tier Tier slug.
	 */
	private function pretend_tier( $tier ) {
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_known_tier', $tier );
		delete_site_transient( 'reportedip_hive_api_status' );
		delete_transient( 'reportedip_hive_api_status' );
		delete_site_transient( 'reportedip_hive_relay_quota' );
		delete_transient( 'reportedip_hive_relay_quota' );
		ReportedIP_Hive_Mode_Manager::get_instance()->flush_cached_tier();
	}

	/**
	 * A block written on the main site is in force on every sub-site, and the
	 * record lives in user meta only.
	 */
	public function test_block_is_network_wide_and_stored_in_user_meta() {
		$this->assertTrue( ReportedIP_Hive_User_Block::block( $this->target ) );

		$blog_id = self::factory()->blog->create();
		switch_to_blog( $blog_id );
		$blocked_on_subsite = ReportedIP_Hive_User_Block::is_blocked( $this->target );
		restore_current_blog();

		$this->assertTrue( $blocked_on_subsite );
		$this->assertFalse( get_option( ReportedIP_Hive_User_Block::META ), 'the record must not live in wp_options' );
		$this->assertFalse( get_site_option( ReportedIP_Hive_User_Block::META ), 'the record must not live in sitemeta' );
	}

	/**
	 * Blocking ends every session immediately.
	 */
	public function test_block_destroys_every_session() {
		$manager = WP_Session_Tokens::get_instance( $this->target );
		$manager->create( time() + HOUR_IN_SECONDS );
		$this->assertNotEmpty( ReportedIP_Hive_User_Sessions::for_user( $this->target ) );

		ReportedIP_Hive_User_Block::block( $this->target );

		$this->assertSame( array(), ReportedIP_Hive_User_Sessions::for_user( $this->target ) );
	}

	/**
	 * The sign-in refusal only fires for a blocked account and carries the
	 * plugin's own error code.
	 */
	public function test_deny_authenticate_refuses_only_blocked_accounts() {
		$user = get_userdata( $this->target );

		$this->assertSame( $user, ReportedIP_Hive_User_Block::deny_authenticate( $user, '', '' ) );

		ReportedIP_Hive_User_Block::block( $this->target );
		$denied = ReportedIP_Hive_User_Block::deny_authenticate( $user, '', '' );

		$this->assertInstanceOf( 'WP_Error', $denied );
		$this->assertSame( ReportedIP_Hive_User_Block::ERROR_CODE, $denied->get_error_code() );

		ReportedIP_Hive_User_Block::unblock( $this->target );
		$this->assertSame( $user, ReportedIP_Hive_User_Block::deny_authenticate( $user, '', '' ) );
	}

	/**
	 * Application passwords and cookies resolve to nobody.
	 */
	public function test_deny_current_user_returns_zero_for_blocked_accounts() {
		$this->assertSame( $this->target, ReportedIP_Hive_User_Block::deny_current_user( $this->target ) );

		ReportedIP_Hive_User_Block::block( $this->target );

		$this->assertSame( 0, ReportedIP_Hive_User_Block::deny_current_user( $this->target ) );
	}

	/**
	 * Self-blocks and super admins are refused.
	 */
	public function test_refusals_protect_the_actor_and_super_admins() {
		$self = ReportedIP_Hive_User_Block::block( $this->actor );
		$this->assertInstanceOf( 'WP_Error', $self );
		$this->assertSame( 'self', $self->get_error_code() );

		grant_super_admin( $this->target );
		$super = ReportedIP_Hive_User_Block::block( $this->target );
		revoke_super_admin( $this->target );

		$this->assertInstanceOf( 'WP_Error', $super );
		$this->assertSame( 'super_admin', $super->get_error_code() );
	}

	/**
	 * The last-administrator guard does not fire on a network: the count would
	 * answer for whichever blog the screen sits on, and super admins are the
	 * recovery path that makes the guard unnecessary here.
	 */
	public function test_last_administrator_guard_is_single_site_only() {
		$target = get_userdata( $this->target );
		$target->set_role( 'administrator' );

		foreach ( (array) get_users(
			array(
				'role'   => 'administrator',
				'fields' => 'ID',
			)
		) as $admin_id ) {
			if ( (int) $admin_id !== $this->target ) {
				update_user_meta(
					(int) $admin_id,
					ReportedIP_Hive_User_Block::META,
					array( 'blocked_at' => current_time( 'mysql', true ) )
				);
			}
		}

		$this->assertSame( '', ReportedIP_Hive_User_Block::refusal( $this->target ) );
		$this->assertTrue( ReportedIP_Hive_User_Block::block( $this->target ) );
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

	/**
	 * On a lapsed plan a new block is refused, but an existing one can still
	 * be lifted — the licence must never hand access back on its own.
	 */
	public function test_free_tier_locks_blocking_but_never_unblocking() {
		ReportedIP_Hive_User_Block::block( $this->target );
		$this->assertTrue( ReportedIP_Hive_User_Block::is_blocked( $this->target ) );

		$this->pretend_tier( 'free' );

		$this->assertTrue( ReportedIP_Hive_User_Block::is_blocked( $this->target ), 'an existing block stays in force' );
		$this->assertTrue( ReportedIP_Hive_User_Block::unblock( $this->target ) );
		$this->assertFalse( ReportedIP_Hive_User_Block::is_blocked( $this->target ) );

		$refused = ReportedIP_Hive_User_Block::block( $this->target );
		$this->assertInstanceOf( 'WP_Error', $refused );
		$this->assertSame( 'tier_locked', $refused->get_error_code() );
	}
}
