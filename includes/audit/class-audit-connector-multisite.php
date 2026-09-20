<?php
/**
 * Audit connector for the network.
 *
 * Sites created, changed and deleted, users added to or removed from a
 * site, and super admin grants. Network rows carry `blog_id = 0` so they
 * are visible from the network admin and survive the per-site cleanup that
 * runs when a site is deleted; the site's own id is in `object_id`.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.62
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Network capture.
 *
 * @since 2.1.62
 */
class ReportedIP_Hive_Audit_Connector_Multisite extends ReportedIP_Hive_Audit_Connector {

	/**
	 * Site fields whose change is a row.
	 *
	 * @var string[]
	 */
	private const SITE_FIELDS = array( 'domain', 'path', 'public', 'archived', 'mature', 'spam', 'deleted' );

	/**
	 * Hooks of this connector.
	 *
	 * @return array<string, array{0:string, 1:int, 2:int}>
	 * @since  2.1.62
	 */
	protected function hooks() {
		return array(
			'wp_initialize_site'    => array( 'on_site_created', 10, 2 ),
			'wp_update_site'        => array( 'on_site_updated', 10, 2 ),
			'wp_delete_site'        => array( 'on_site_deleted', 5, 1 ),
			'add_user_to_blog'      => array( 'on_user_added', 10, 3 ),
			'remove_user_from_blog' => array( 'on_user_removed', 10, 3 ),
			'granted_super_admin'   => array( 'on_super_admin_granted', 10, 1 ),
			'revoked_super_admin'   => array( 'on_super_admin_revoked', 10, 1 ),
		);
	}

	/**
	 * Pure diff of two site objects over the watched fields.
	 *
	 * @param object $old Previous site.
	 * @param object $new New site.
	 * @return array<string, array{old:string, new:string}>
	 * @since  2.1.62
	 */
	public static function diff_site( $old, $new ) {
		$changes = array();
		foreach ( self::SITE_FIELDS as $field ) {
			$before = (string) ( $old->$field ?? '' );
			$after  = (string) ( $new->$field ?? '' );
			if ( $before !== $after ) {
				$changes[ $field ] = array(
					'old' => $before,
					'new' => $after,
				);
			}
		}
		return $changes;
	}

	/**
	 * Site created.
	 *
	 * @param WP_Site             $site Site.
	 * @param array<string,mixed> $args Creation args.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_site_created( $site, $args = array() ) {
		$this->log( 'site', 'created', array(), self::site_object( $site ), 0 );
	}

	/**
	 * Site fields changed.
	 *
	 * @param WP_Site $new New site.
	 * @param WP_Site $old Previous site.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_site_updated( $new, $old ) {
		$changes = self::diff_site( $old, $new );
		if ( empty( $changes ) ) {
			return;
		}
		$this->log( 'site', 'updated', array( 'changes' => $changes ), self::site_object( $new ), 0 );
	}

	/**
	 * Site deleted. Runs before the per-site cleanup on the same hook.
	 *
	 * @param WP_Site $site Site.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_site_deleted( $site ) {
		$this->log( 'site', 'deleted', array(), self::site_object( $site ), 0 );
	}

	/**
	 * User added to a site. `add_user_to_blog()` fires `set_user_role`
	 * inside, which the users group would report as a role change.
	 *
	 * @param int    $user_id User id.
	 * @param string $role    Role on the site.
	 * @param int    $blog_id Site id.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_user_added( $user_id, $role, $blog_id ) {
		self::suppress( 'set_user_role' );
		$user = get_userdata( (int) $user_id );
		$this->log(
			'site_user',
			'added',
			array(
				'role'    => (string) $role,
				'blog_id' => (int) $blog_id,
			),
			self::user_object( $user, (int) $user_id ),
			(int) $blog_id
		);
	}

	/**
	 * User removed from a site.
	 *
	 * @param int $user_id  User id.
	 * @param int $blog_id  Site id.
	 * @param int $reassign User the content goes to.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_user_removed( $user_id, $blog_id, $reassign = 0 ) {
		$user = get_userdata( (int) $user_id );
		$this->log(
			'site_user',
			'removed',
			array(
				'blog_id'  => (int) $blog_id,
				'reassign' => (int) $reassign,
			),
			self::user_object( $user, (int) $user_id ),
			(int) $blog_id
		);
	}

	/**
	 * Super admin granted.
	 *
	 * @param int $user_id User id.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_super_admin_granted( $user_id ) {
		$this->log( 'super_admin', 'granted', array(), self::user_object( get_userdata( (int) $user_id ), (int) $user_id ), 0 );
	}

	/**
	 * Super admin revoked.
	 *
	 * @param int $user_id User id.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_super_admin_revoked( $user_id ) {
		$this->log( 'super_admin', 'revoked', array(), self::user_object( get_userdata( (int) $user_id ), (int) $user_id ), 0 );
	}

	/**
	 * Object descriptor of a site.
	 *
	 * @param object $site Site.
	 * @return array{type:string, id:int, label:string}
	 * @since  2.1.62
	 */
	private static function site_object( $site ) {
		return array(
			'type'  => 'site',
			'id'    => (int) ( $site->blog_id ?? $site->id ?? 0 ),
			'label' => (string) ( $site->domain ?? '' ) . (string) ( $site->path ?? '' ),
		);
	}

	/**
	 * Object descriptor of a user.
	 *
	 * @param WP_User|false $user    User, or false when gone.
	 * @param int           $user_id Id fallback.
	 * @return array{type:string, id:int, label:string}
	 * @since  2.1.62
	 */
	private static function user_object( $user, $user_id ) {
		return array(
			'type'  => 'user',
			'id'    => $user_id,
			'label' => $user instanceof WP_User ? (string) $user->user_login : '#' . $user_id,
		);
	}
}
