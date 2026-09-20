<?php
/**
 * The one registry of audit trigger groups, audit events and watched options.
 *
 * Every row the audit trail writes has a `type/action` pair that must appear
 * in {@see ReportedIP_Hive_Audit_Registry::events()}; every capture surface
 * belongs to one trigger group of {@see ReportedIP_Hive_Audit_Registry::groups()}.
 * The Protection page draws the trigger switches from the groups, the audit
 * table draws its filter, badges and sentences from the events, and the
 * settings connector reads the watched core options from here. A unit test
 * keeps writers and registry in step, the same way the event taxonomy guards
 * the security log.
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
 * Static registry of audit groups, events and watched options.
 *
 * @since 2.1.62
 */
final class ReportedIP_Hive_Audit_Registry {

	/**
	 * Option holding the enabled trigger groups as a JSON list.
	 */
	public const OPTION_TRIGGERS = 'reportedip_hive_audit_triggers';

	/**
	 * Prefix that marks a filter value as a whole group.
	 */
	public const GROUP_PREFIX = 'group:';

	/**
	 * Longest stored old/new value, in characters.
	 */
	public const VALUE_MAX_LENGTH = 500;

	/**
	 * Group order, also the render order of the trigger switches.
	 *
	 * @var string[]
	 */
	private const GROUP_ORDER = array( 'logins', 'users', 'content', 'installer', 'settings', 'menus_widgets', 'editor', 'multisite' );

	/**
	 * Memoised event table.
	 *
	 * @var array<string, array<string, string>>|null
	 */
	private static $events = null;

	/**
	 * Trigger groups with label, description, default state and scope.
	 *
	 * `logins` is off by default: successful sign-ins are the loudest row
	 * type by far and failed attempts already live in the security log. The
	 * multisite group is only offered on a network.
	 *
	 * @return array<string, array{label:string, description:string, default:bool, multisite_only:bool}>
	 * @since  2.1.62
	 */
	public static function groups() {
		return array(
			'logins'        => array(
				'label'          => __( 'Sign-ins and sign-outs', 'reportedip-hive' ),
				'description'    => __( 'Every successful sign-in, sign-out and failed attempt with the address it came from. High volume; failed attempts are in the event log regardless.', 'reportedip-hive' ),
				'default'        => false,
				'multisite_only' => false,
			),
			'users'         => array(
				'label'          => __( 'User accounts', 'reportedip-hive' ),
				'description'    => __( 'Registrations, deletions, role and e-mail changes with the acting user, password changes and resets, account blocks, ended sessions, edited role capabilities.', 'reportedip-hive' ),
				'default'        => true,
				'multisite_only' => false,
			),
			'content'       => array(
				'label'          => __( 'Pages and posts', 'reportedip-hive' ),
				'description'    => __( 'Published, unpublished, trashed, restored and deleted entries, and changed URL slugs. Autosaves and revisions are ignored.', 'reportedip-hive' ),
				'default'        => true,
				'multisite_only' => false,
			),
			'installer'     => array(
				'label'          => __( 'Plugins, themes and core', 'reportedip-hive' ),
				'description'    => __( 'Installed, updated, activated, deactivated and deleted plugins and themes, theme switches and WordPress core updates, including automatic ones.', 'reportedip-hive' ),
				'default'        => true,
				'multisite_only' => false,
			),
			'settings'      => array(
				'label'          => __( 'Site settings', 'reportedip-hive' ),
				'description'    => __( 'Changes to the site address, permalinks, reading, discussion, registration and update settings, and to every ReportedIP Hive setting, with the old and the new value.', 'reportedip-hive' ),
				'default'        => true,
				'multisite_only' => false,
			),
			'menus_widgets' => array(
				'label'          => __( 'Menus and widgets', 'reportedip-hive' ),
				'description'    => __( 'Created, changed and deleted menus, menu locations, and widgets added to or removed from a sidebar. The content of a widget is not recorded.', 'reportedip-hive' ),
				'default'        => true,
				'multisite_only' => false,
			),
			'editor'        => array(
				'label'          => __( 'Theme and plugin file editor', 'reportedip-hive' ),
				'description'    => __( 'Files saved through the built-in theme and plugin editor. Has no effect while DISALLOW_FILE_EDIT is set.', 'reportedip-hive' ),
				'default'        => true,
				'multisite_only' => false,
			),
			'multisite'     => array(
				'label'          => __( 'Network', 'reportedip-hive' ),
				'description'    => __( 'Sites created, changed, archived or deleted, users added to or removed from a site, and super admin grants.', 'reportedip-hive' ),
				'default'        => true,
				'multisite_only' => true,
			),
		);
	}

	/**
	 * Group slugs in render order.
	 *
	 * @return string[]
	 * @since  2.1.62
	 */
	public static function group_slugs() {
		return self::GROUP_ORDER;
	}

	/**
	 * Groups enabled by default, as stored in the option.
	 *
	 * @return string[]
	 * @since  2.1.62
	 */
	public static function default_groups() {
		$out = array();
		foreach ( self::groups() as $slug => $group ) {
			if ( $group['default'] ) {
				$out[] = $slug;
			}
		}
		return $out;
	}

	/**
	 * Drop unknown group slugs from a stored list. Pure, no WordPress calls,
	 * so the sanitizer can run it on every channel.
	 *
	 * @param string[] $slugs Raw list.
	 * @return string[]
	 * @since  2.1.62
	 */
	public static function filter_groups( array $slugs ) {
		return array_values( array_unique( array_intersect( array_map( 'strval', $slugs ), self::GROUP_ORDER ) ) );
	}

	/**
	 * Groups the site has switched on, minus the ones its topology cannot use.
	 *
	 * @return string[]
	 * @since  2.1.62
	 */
	public static function enabled_groups() {
		$stored  = ReportedIP_Hive_Option_Routing::get( self::OPTION_TRIGGERS, wp_json_encode( self::default_groups() ) );
		$enabled = self::filter_groups( ReportedIP_Hive_Option_Routing::to_array( $stored ) );
		if ( ! is_multisite() ) {
			$enabled = array_values( array_diff( $enabled, array( 'multisite' ) ) );
		}
		return $enabled;
	}

	/**
	 * Whether a group is enabled.
	 *
	 * @param string $group Group slug.
	 * @return bool
	 * @since  2.1.62
	 */
	public static function group_enabled( $group ) {
		return in_array( (string) $group, self::enabled_groups(), true );
	}

	/**
	 * Every audit event keyed `type/action`, with label, badge tone and group.
	 *
	 * @return array<string, array{label:string, badge:string, group:string}>
	 * @since  2.1.62
	 */
	public static function events() {
		if ( null !== self::$events ) {
			return self::$events;
		}

		self::$events = array(
			'login/success'                   => array(
				'label' => __( 'Signed in', 'reportedip-hive' ),
				'badge' => 'success',
				'group' => 'logins',
			),
			'login/new_ip'                    => array(
				'label' => __( 'Signed in from a new address', 'reportedip-hive' ),
				'badge' => 'warning',
				'group' => 'logins',
			),
			'login/failed'                    => array(
				'label' => __( 'Sign-in failed', 'reportedip-hive' ),
				'badge' => 'danger',
				'group' => 'logins',
			),
			'logout/success'                  => array(
				'label' => __( 'Signed out', 'reportedip-hive' ),
				'badge' => 'neutral',
				'group' => 'logins',
			),

			'registration/success'            => array(
				'label' => __( 'User registered', 'reportedip-hive' ),
				'badge' => 'info',
				'group' => 'users',
			),
			'user/deleted'                    => array(
				'label' => __( 'User deleted', 'reportedip-hive' ),
				'badge' => 'danger',
				'group' => 'users',
			),
			'profile_change/updated'          => array(
				'label' => __( 'Profile updated', 'reportedip-hive' ),
				'badge' => 'info',
				'group' => 'users',
			),
			'profile_change/email_changed'    => array(
				'label' => __( 'E-mail address changed', 'reportedip-hive' ),
				'badge' => 'warning',
				'group' => 'users',
			),
			'profile_change/password_changed' => array(
				'label' => __( 'Password changed', 'reportedip-hive' ),
				'badge' => 'warning',
				'group' => 'users',
			),
			'profile_change/role_changed'     => array(
				'label' => __( 'Role changed', 'reportedip-hive' ),
				'badge' => 'warning',
				'group' => 'users',
			),
			'password_reset/requested'        => array(
				'label' => __( 'Password reset requested', 'reportedip-hive' ),
				'badge' => 'info',
				'group' => 'users',
			),
			'password_reset/completed'        => array(
				'label' => __( 'Password reset completed', 'reportedip-hive' ),
				'badge' => 'success',
				'group' => 'users',
			),
			'user_block/blocked'              => array(
				'label' => __( 'Account blocked', 'reportedip-hive' ),
				'badge' => 'danger',
				'group' => 'users',
			),
			'user_block/unblocked'            => array(
				'label' => __( 'Account unblocked', 'reportedip-hive' ),
				'badge' => 'success',
				'group' => 'users',
			),
			'session/terminated'              => array(
				'label' => __( 'Session ended', 'reportedip-hive' ),
				'badge' => 'warning',
				'group' => 'users',
			),
			'session/terminated_all'          => array(
				'label' => __( 'All sessions ended', 'reportedip-hive' ),
				'badge' => 'warning',
				'group' => 'users',
			),
			'role/caps_changed'               => array(
				'label' => __( 'Role capabilities changed', 'reportedip-hive' ),
				'badge' => 'warning',
				'group' => 'users',
			),

			'content/published'               => array(
				'label' => __( 'Published', 'reportedip-hive' ),
				'badge' => 'success',
				'group' => 'content',
			),
			'content/unpublished'             => array(
				'label' => __( 'Unpublished', 'reportedip-hive' ),
				'badge' => 'warning',
				'group' => 'content',
			),
			'content/trashed'                 => array(
				'label' => __( 'Moved to trash', 'reportedip-hive' ),
				'badge' => 'warning',
				'group' => 'content',
			),
			'content/untrashed'               => array(
				'label' => __( 'Restored from trash', 'reportedip-hive' ),
				'badge' => 'info',
				'group' => 'content',
			),
			'content/deleted'                 => array(
				'label' => __( 'Deleted permanently', 'reportedip-hive' ),
				'badge' => 'danger',
				'group' => 'content',
			),
			'content/slug_changed'            => array(
				'label' => __( 'URL slug changed', 'reportedip-hive' ),
				'badge' => 'warning',
				'group' => 'content',
			),

			'plugin/installed'                => array(
				'label' => __( 'Plugin installed', 'reportedip-hive' ),
				'badge' => 'info',
				'group' => 'installer',
			),
			'plugin/updated'                  => array(
				'label' => __( 'Plugin updated', 'reportedip-hive' ),
				'badge' => 'info',
				'group' => 'installer',
			),
			'plugin/activated'                => array(
				'label' => __( 'Plugin activated', 'reportedip-hive' ),
				'badge' => 'success',
				'group' => 'installer',
			),
			'plugin/deactivated'              => array(
				'label' => __( 'Plugin deactivated', 'reportedip-hive' ),
				'badge' => 'warning',
				'group' => 'installer',
			),
			'plugin/deleted'                  => array(
				'label' => __( 'Plugin deleted', 'reportedip-hive' ),
				'badge' => 'danger',
				'group' => 'installer',
			),
			'theme/installed'                 => array(
				'label' => __( 'Theme installed', 'reportedip-hive' ),
				'badge' => 'info',
				'group' => 'installer',
			),
			'theme/updated'                   => array(
				'label' => __( 'Theme updated', 'reportedip-hive' ),
				'badge' => 'info',
				'group' => 'installer',
			),
			'theme/switched'                  => array(
				'label' => __( 'Theme switched', 'reportedip-hive' ),
				'badge' => 'warning',
				'group' => 'installer',
			),
			'theme/deleted'                   => array(
				'label' => __( 'Theme deleted', 'reportedip-hive' ),
				'badge' => 'danger',
				'group' => 'installer',
			),
			'core/updated'                    => array(
				'label' => __( 'WordPress updated', 'reportedip-hive' ),
				'badge' => 'info',
				'group' => 'installer',
			),

			'setting/updated'                 => array(
				'label' => __( 'Setting changed', 'reportedip-hive' ),
				'badge' => 'warning',
				'group' => 'settings',
			),

			'menu/created'                    => array(
				'label' => __( 'Menu created', 'reportedip-hive' ),
				'badge' => 'info',
				'group' => 'menus_widgets',
			),
			'menu/updated'                    => array(
				'label' => __( 'Menu changed', 'reportedip-hive' ),
				'badge' => 'info',
				'group' => 'menus_widgets',
			),
			'menu/deleted'                    => array(
				'label' => __( 'Menu deleted', 'reportedip-hive' ),
				'badge' => 'danger',
				'group' => 'menus_widgets',
			),
			'menu/locations_changed'          => array(
				'label' => __( 'Menu locations changed', 'reportedip-hive' ),
				'badge' => 'warning',
				'group' => 'menus_widgets',
			),
			'widget/added'                    => array(
				'label' => __( 'Widget added', 'reportedip-hive' ),
				'badge' => 'info',
				'group' => 'menus_widgets',
			),
			'widget/removed'                  => array(
				'label' => __( 'Widget removed', 'reportedip-hive' ),
				'badge' => 'warning',
				'group' => 'menus_widgets',
			),

			'file/edited'                     => array(
				'label' => __( 'File edited', 'reportedip-hive' ),
				'badge' => 'danger',
				'group' => 'editor',
			),

			'site/created'                    => array(
				'label' => __( 'Site created', 'reportedip-hive' ),
				'badge' => 'info',
				'group' => 'multisite',
			),
			'site/updated'                    => array(
				'label' => __( 'Site changed', 'reportedip-hive' ),
				'badge' => 'warning',
				'group' => 'multisite',
			),
			'site/deleted'                    => array(
				'label' => __( 'Site deleted', 'reportedip-hive' ),
				'badge' => 'danger',
				'group' => 'multisite',
			),
			'site_user/added'                 => array(
				'label' => __( 'User added to site', 'reportedip-hive' ),
				'badge' => 'info',
				'group' => 'multisite',
			),
			'site_user/removed'               => array(
				'label' => __( 'User removed from site', 'reportedip-hive' ),
				'badge' => 'warning',
				'group' => 'multisite',
			),
			'super_admin/granted'             => array(
				'label' => __( 'Super admin granted', 'reportedip-hive' ),
				'badge' => 'danger',
				'group' => 'multisite',
			),
			'super_admin/revoked'             => array(
				'label' => __( 'Super admin revoked', 'reportedip-hive' ),
				'badge' => 'warning',
				'group' => 'multisite',
			),
		);

		return self::$events;
	}

	/**
	 * Registry row for one stored event, or null when the pair is unknown.
	 *
	 * @param string $type   Event type column.
	 * @param string $action Event action column.
	 * @return array{label:string, badge:string, group:string}|null
	 * @since  2.1.62
	 */
	public static function event( $type, $action ) {
		$events = self::events();
		$key    = (string) $type . '/' . (string) $action;
		return isset( $events[ $key ] ) ? $events[ $key ] : null;
	}

	/**
	 * Display label for an event, humanised when unregistered.
	 *
	 * @param string $type   Event type.
	 * @param string $action Event action.
	 * @return string
	 * @since  2.1.62
	 */
	public static function label( $type, $action ) {
		$row = self::event( $type, $action );
		if ( $row ) {
			return $row['label'];
		}
		return ucwords( str_replace( '_', ' ', (string) $type . ' ' . (string) $action ) );
	}

	/**
	 * Badge tone for an event (`success|warning|danger|info|neutral`).
	 *
	 * @param string $type   Event type.
	 * @param string $action Event action.
	 * @return string
	 * @since  2.1.62
	 */
	public static function badge( $type, $action ) {
		$row = self::event( $type, $action );
		return $row ? $row['badge'] : 'info';
	}

	/**
	 * Grouped option list for the audit filter: group slug to `type/action`
	 * keys with labels.
	 *
	 * @return array<string, array<string, string>>
	 * @since  2.1.62
	 */
	public static function filter_options() {
		$groups = array();
		foreach ( self::GROUP_ORDER as $slug ) {
			if ( 'multisite' === $slug && ! is_multisite() ) {
				continue;
			}
			$groups[ $slug ] = array();
		}
		foreach ( self::events() as $key => $row ) {
			if ( isset( $groups[ $row['group'] ] ) ) {
				$groups[ $row['group'] ][ $key ] = $row['label'];
			}
		}
		return array_filter( $groups );
	}

	/**
	 * Turn one filter value into the `type/action` pairs it selects.
	 *
	 * A plain key selects itself, `group:<slug>` selects every event of the
	 * group. An unknown value comes back as itself so the query stays well
	 * formed and finds nothing.
	 *
	 * @param string $value Raw filter value.
	 * @return string[] `type/action` keys.
	 * @since  2.1.62
	 */
	public static function expand_filter_value( $value ) {
		$value = (string) $value;
		if ( 0 !== strpos( $value, self::GROUP_PREFIX ) ) {
			return array( $value );
		}
		$group = substr( $value, strlen( self::GROUP_PREFIX ) );
		$keys  = array();
		foreach ( self::events() as $key => $row ) {
			if ( $row['group'] === $group ) {
				$keys[] = $key;
			}
		}
		return empty( $keys ) ? array( $value ) : $keys;
	}

	/**
	 * Core options worth a row, with their labels.
	 *
	 * Site-level keys only; network-level keys live in
	 * {@see network_options()}. Keys that core rewrites on its own (cron,
	 * rewrite rules, transients) are deliberately absent, as are the ones
	 * another connector covers (`active_plugins`, `template`, `stylesheet`).
	 *
	 * @return array<string, string>
	 * @since  2.1.62
	 */
	public static function core_options() {
		return array(
			'siteurl'                    => __( 'WordPress address (URL)', 'reportedip-hive' ),
			'home'                       => __( 'Site address (URL)', 'reportedip-hive' ),
			'blogname'                   => __( 'Site title', 'reportedip-hive' ),
			'blogdescription'            => __( 'Tagline', 'reportedip-hive' ),
			'admin_email'                => __( 'Administration e-mail address', 'reportedip-hive' ),
			'users_can_register'         => __( 'Anyone can register', 'reportedip-hive' ),
			'default_role'               => __( 'New user default role', 'reportedip-hive' ),
			'timezone_string'            => __( 'Timezone', 'reportedip-hive' ),
			'gmt_offset'                 => __( 'Timezone offset', 'reportedip-hive' ),
			'WPLANG'                     => __( 'Site language', 'reportedip-hive' ),
			'permalink_structure'        => __( 'Permalink structure', 'reportedip-hive' ),
			'category_base'              => __( 'Category base', 'reportedip-hive' ),
			'tag_base'                   => __( 'Tag base', 'reportedip-hive' ),
			'show_on_front'              => __( 'Homepage displays', 'reportedip-hive' ),
			'page_on_front'              => __( 'Homepage', 'reportedip-hive' ),
			'page_for_posts'             => __( 'Posts page', 'reportedip-hive' ),
			'posts_per_page'             => __( 'Posts per page', 'reportedip-hive' ),
			'blog_public'                => __( 'Search engine visibility', 'reportedip-hive' ),
			'default_comment_status'     => __( 'Allow comments on new posts', 'reportedip-hive' ),
			'comment_registration'       => __( 'Users must be registered to comment', 'reportedip-hive' ),
			'comment_moderation'         => __( 'Comment must be manually approved', 'reportedip-hive' ),
			'wp_page_for_privacy_policy' => __( 'Privacy policy page', 'reportedip-hive' ),
			'auto_update_core_major'     => __( 'Automatic major core updates', 'reportedip-hive' ),
			'auto_update_core_minor'     => __( 'Automatic minor core updates', 'reportedip-hive' ),
			'auto_update_plugins'        => __( 'Plugins with automatic updates', 'reportedip-hive' ),
			'auto_update_themes'         => __( 'Themes with automatic updates', 'reportedip-hive' ),
		);
	}

	/**
	 * Network options worth a row, with their labels.
	 *
	 * @return array<string, string>
	 * @since  2.1.62
	 */
	public static function network_options() {
		return array(
			'registration'     => __( 'Allow new registrations', 'reportedip-hive' ),
			'add_new_users'    => __( 'Site admins may add users', 'reportedip-hive' ),
			'upload_filetypes' => __( 'Upload file types', 'reportedip-hive' ),
		);
	}

	/**
	 * Human sentence for one stored row, built at display time from the
	 * registry and the JSON data so the trail follows the site language.
	 *
	 * @param object $row Audit row with event_type, event_action, event_data, object_label, username.
	 * @return string Plain text, unescaped.
	 * @since  2.1.62
	 */
	public static function summary( $row ) {
		$data   = json_decode( (string) ( $row->event_data ?? '' ), true );
		$data   = is_array( $data ) ? $data : array();
		$type   = (string) ( $row->event_type ?? '' );
		$action = (string) ( $row->event_action ?? '' );
		$label  = (string) ( $row->object_label ?? '' );

		switch ( $type ) {
			case 'setting':
				return self::change_sentence( $label, $data );
			case 'content':
				if ( 'slug_changed' === $action ) {
					return self::change_sentence(
						$label,
						array(
							'old' => $data['old_slug'] ?? '',
							'new' => $data['new_slug'] ?? '',
						)
					);
				}
				if ( isset( $data['old_status'], $data['new_status'] ) ) {
					/* translators: 1: entry title, 2: old status, 3: new status */
					return sprintf( __( '%1$s: %2$s to %3$s', 'reportedip-hive' ), $label, $data['old_status'], $data['new_status'] );
				}
				return $label;
			case 'plugin':
			case 'theme':
				if ( ! empty( $data['from_version'] ) && ! empty( $data['to_version'] ) ) {
					/* translators: 1: plugin or theme name, 2: old version, 3: new version */
					return sprintf( __( '%1$s: %2$s to %3$s', 'reportedip-hive' ), $label, $data['from_version'], $data['to_version'] );
				}
				if ( ! empty( $data['to_version'] ) ) {
					return $label . ' ' . $data['to_version'];
				}
				return $label;
			case 'core':
				return self::change_sentence(
					$label,
					array(
						'old' => $data['from_version'] ?? '',
						'new' => $data['to_version'] ?? '',
					)
				);
			case 'profile_change':
				if ( 'role_changed' === $action ) {
					$old = isset( $data['old_roles'] ) ? implode( ', ', (array) $data['old_roles'] ) : '';
					return self::change_sentence(
						$label,
						array(
							'old' => $old,
							'new' => $data['new_role'] ?? '',
						)
					);
				}
				return $label;
			case 'menu':
				if ( 'locations_changed' === $action && ! empty( $data['changes'] ) ) {
					$parts = array();
					foreach ( (array) $data['changes'] as $location => $change ) {
						$parts[] = $location . ': ' . self::arrow( (string) ( $change['old'] ?? '' ), (string) ( $change['new'] ?? '' ) );
					}
					return implode( '; ', $parts );
				}
				return $label;
			case 'widget':
				/* translators: 1: widget id, 2: sidebar name */
				return sprintf( __( '%1$s in %2$s', 'reportedip-hive' ), $label, (string) ( $data['sidebar'] ?? '' ) );
			case 'role':
				$parts = array();
				if ( ! empty( $data['added'] ) ) {
					/* translators: %s: comma separated role names */
					$parts[] = sprintf( __( 'added %s', 'reportedip-hive' ), implode( ', ', (array) $data['added'] ) );
				}
				if ( ! empty( $data['removed'] ) ) {
					/* translators: %s: comma separated role names */
					$parts[] = sprintf( __( 'removed %s', 'reportedip-hive' ), implode( ', ', (array) $data['removed'] ) );
				}
				if ( ! empty( $data['caps_changed'] ) ) {
					/* translators: %s: comma separated role names */
					$parts[] = sprintf( __( 'capabilities of %s', 'reportedip-hive' ), implode( ', ', (array) $data['caps_changed'] ) );
				}
				return implode( '; ', $parts );
			case 'site':
				if ( 'updated' === $action && ! empty( $data['changes'] ) ) {
					$parts = array();
					foreach ( (array) $data['changes'] as $field => $change ) {
						$parts[] = $field . ': ' . self::arrow( (string) ( $change['old'] ?? '' ), (string) ( $change['new'] ?? '' ) );
					}
					return $label . ' (' . implode( '; ', $parts ) . ')';
				}
				return $label;
			default:
				return $label;
		}
	}

	/**
	 * "Label: old to new" with a fallback when only one side is known.
	 *
	 * @param string              $label Subject.
	 * @param array<string,mixed> $data  Data holding `old` and `new`.
	 * @return string
	 * @since  2.1.62
	 */
	private static function change_sentence( $label, array $data ) {
		$old = self::scalar( $data['old'] ?? '' );
		$new = self::scalar( $data['new'] ?? '' );
		if ( '' === $old && '' === $new ) {
			return $label;
		}
		return trim( $label . ': ' . self::arrow( $old, $new ) );
	}

	/**
	 * "old to new" fragment.
	 *
	 * @param string $old Old value.
	 * @param string $new New value.
	 * @return string
	 * @since  2.1.62
	 */
	private static function arrow( $old, $new ) {
		/* translators: 1: old value, 2: new value */
		return sprintf( __( '%1$s to %2$s', 'reportedip-hive' ), '' === $old ? '(empty)' : $old, '' === $new ? '(empty)' : $new );
	}

	/**
	 * Flatten a stored value for display.
	 *
	 * @param mixed $value Scalar, list or diff map.
	 * @return string
	 * @since  2.1.62
	 */
	private static function scalar( $value ) {
		if ( is_array( $value ) ) {
			return wp_json_encode( $value );
		}
		if ( is_bool( $value ) ) {
			return $value ? '1' : '0';
		}
		return (string) $value;
	}
}
