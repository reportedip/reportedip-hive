<?php
/**
 * Audit connector for menus and widgets.
 *
 * Menus are created, changed and deleted through their own hooks. Menu
 * locations and widget placement live inside two options that core rewrites
 * as a whole on every save, several times per Customizer session, so both
 * are captured as a diff and deduplicated on that diff.
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
 * Menu and widget capture.
 *
 * @since 2.1.62
 */
class ReportedIP_Hive_Audit_Connector_Menus extends ReportedIP_Hive_Audit_Connector {

	/**
	 * Hooks of this connector.
	 *
	 * @return array<string, array{0:string, 1:int, 2:int}>
	 * @since  2.1.62
	 */
	protected function hooks() {
		return array(
			'wp_create_nav_menu' => array( 'on_created', 10, 2 ),
			'wp_update_nav_menu' => array( 'on_updated', 10, 2 ),
			'pre_delete_term'    => array( 'remember_name', 10, 2 ),
			'wp_delete_nav_menu' => array( 'on_deleted', 10, 1 ),
			'updated_option'     => array( 'on_option', 10, 3 ),
		);
	}

	/**
	 * Names of menus about to be deleted, keyed by term id.
	 *
	 * @var array<int, string>
	 */
	private static $names = array();

	/**
	 * Keep the menu name: `wp_delete_nav_menu` fires after the term is gone.
	 *
	 * @param int    $term_id  Term id.
	 * @param string $taxonomy Taxonomy.
	 * @return void
	 * @since  2.1.62
	 */
	public function remember_name( $term_id, $taxonomy ) {
		if ( 'nav_menu' !== $taxonomy ) {
			return;
		}
		$menu = wp_get_nav_menu_object( (int) $term_id );
		if ( $menu instanceof WP_Term ) {
			self::$names[ (int) $term_id ] = (string) $menu->name;
		}
	}

	/**
	 * Menu created.
	 *
	 * @param int                 $menu_id Term id.
	 * @param array<string,mixed> $data    Menu data.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_created( $menu_id, $data = array() ) {
		$this->log( 'menu', 'created', array(), self::menu_object( (int) $menu_id ) );
	}

	/**
	 * Menu changed. Fires once per save with the id only; the per-item hook
	 * is deliberately not used.
	 *
	 * @param int                 $menu_id Term id.
	 * @param array<string,mixed> $data    Menu data when saved from the screen.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_updated( $menu_id, $data = array() ) {
		if ( self::seen( 'menu:' . (int) $menu_id . ':updated' ) ) {
			return;
		}
		$this->log( 'menu', 'updated', array(), self::menu_object( (int) $menu_id ) );
	}

	/**
	 * Menu deleted. Core fires this after the term is gone; the name comes from {@see remember_name()}.
	 *
	 * @param int $menu_id Term id.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_deleted( $menu_id ) {
		$this->log( 'menu', 'deleted', array(), self::menu_object( (int) $menu_id ) );
	}

	/**
	 * Option writes that carry menu locations or widget placement.
	 *
	 * @param string $option Option name.
	 * @param mixed  $old    Previous value.
	 * @param mixed  $new    New value.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_option( $option, $old, $new ) {
		$option = (string) $option;
		if ( 'sidebars_widgets' === $option ) {
			$this->log_widgets( is_array( $old ) ? $old : array(), is_array( $new ) ? $new : array() );
			return;
		}
		if ( 0 === strpos( $option, 'theme_mods_' ) ) {
			$this->log_locations( is_array( $old ) ? $old : array(), is_array( $new ) ? $new : array() );
		}
	}

	/**
	 * Pure diff of `nav_menu_locations` inside two theme-mod arrays.
	 *
	 * @param array<string,mixed> $old Old theme mods.
	 * @param array<string,mixed> $new New theme mods.
	 * @return array<string, array{old:int, new:int}> Location to old/new menu id.
	 * @since  2.1.62
	 */
	public static function diff_locations( array $old, array $new ) {
		$old_loc = (array) ( $old['nav_menu_locations'] ?? array() );
		$new_loc = (array) ( $new['nav_menu_locations'] ?? array() );
		$changes = array();
		foreach ( array_unique( array_merge( array_keys( $old_loc ), array_keys( $new_loc ) ) ) as $location ) {
			$before = (int) ( $old_loc[ $location ] ?? 0 );
			$after  = (int) ( $new_loc[ $location ] ?? 0 );
			if ( $before !== $after ) {
				$changes[ (string) $location ] = array(
					'old' => $before,
					'new' => $after,
				);
			}
		}
		return $changes;
	}

	/**
	 * Pure diff of two `sidebars_widgets` arrays: which widget ids were added
	 * to or removed from which named sidebar. `array_version` and the
	 * inactive/orphaned buckets are ignored.
	 *
	 * @param array<string,mixed> $old Old sidebars.
	 * @param array<string,mixed> $new New sidebars.
	 * @return array<int, array{sidebar:string, widget:string, action:string}>
	 * @since  2.1.62
	 */
	public static function diff_sidebars( array $old, array $new ) {
		$skip    = array( 'array_version', 'wp_inactive_widgets', 'orphaned_widgets' );
		$changes = array();
		foreach ( array_unique( array_merge( array_keys( $old ), array_keys( $new ) ) ) as $sidebar ) {
			$sidebar = (string) $sidebar;
			if ( in_array( $sidebar, $skip, true ) || 0 === strpos( $sidebar, 'orphaned_widgets' ) ) {
				continue;
			}
			$before = array_map( 'strval', (array) ( $old[ $sidebar ] ?? array() ) );
			$after  = array_map( 'strval', (array) ( $new[ $sidebar ] ?? array() ) );
			foreach ( array_diff( $after, $before ) as $widget ) {
				$changes[] = array(
					'sidebar' => $sidebar,
					'widget'  => $widget,
					'action'  => 'added',
				);
			}
			foreach ( array_diff( $before, $after ) as $widget ) {
				$changes[] = array(
					'sidebar' => $sidebar,
					'widget'  => $widget,
					'action'  => 'removed',
				);
			}
		}
		return $changes;
	}

	/**
	 * Menu locations changed.
	 *
	 * @param array<string,mixed> $old Old theme mods.
	 * @param array<string,mixed> $new New theme mods.
	 * @return void
	 * @since  2.1.62
	 */
	private function log_locations( array $old, array $new ) {
		$changes = self::diff_locations( $old, $new );
		if ( empty( $changes ) || self::seen( 'menu-locations:' . md5( wp_json_encode( $changes ) ) ) ) {
			return;
		}
		$named = array();
		foreach ( $changes as $location => $change ) {
			$named[ $location ] = array(
				'old' => self::menu_name( $change['old'] ),
				'new' => self::menu_name( $change['new'] ),
			);
		}
		$this->log(
			'menu',
			'locations_changed',
			array( 'changes' => $named ),
			array(
				'type'  => 'menu_locations',
				'id'    => 0,
				'label' => __( 'Menu locations', 'reportedip-hive' ),
			)
		);
	}

	/**
	 * Widgets added to or removed from sidebars.
	 *
	 * @param array<string,mixed> $old Old sidebars.
	 * @param array<string,mixed> $new New sidebars.
	 * @return void
	 * @since  2.1.62
	 */
	private function log_widgets( array $old, array $new ) {
		foreach ( self::diff_sidebars( $old, $new ) as $change ) {
			if ( self::seen( 'widget:' . $change['sidebar'] . ':' . $change['widget'] . ':' . $change['action'] ) ) {
				continue;
			}
			$this->log(
				'widget',
				$change['action'],
				array( 'sidebar' => self::sidebar_name( $change['sidebar'] ) ),
				array(
					'type'  => 'widget',
					'id'    => 0,
					'label' => $change['widget'],
				)
			);
		}
	}

	/**
	 * Object descriptor of a menu.
	 *
	 * @param int $menu_id Term id.
	 * @return array{type:string, id:int, label:string}
	 * @since  2.1.62
	 */
	private static function menu_object( $menu_id ) {
		return array(
			'type'  => 'menu',
			'id'    => $menu_id,
			'label' => self::menu_name( $menu_id ),
		);
	}

	/**
	 * Menu name, or the id when the term is gone.
	 *
	 * @param int $menu_id Term id.
	 * @return string
	 * @since  2.1.62
	 */
	private static function menu_name( $menu_id ) {
		if ( $menu_id <= 0 ) {
			return '';
		}
		if ( isset( self::$names[ $menu_id ] ) ) {
			return self::$names[ $menu_id ];
		}
		$menu = wp_get_nav_menu_object( $menu_id );
		return $menu instanceof WP_Term ? (string) $menu->name : '#' . $menu_id;
	}

	/**
	 * Registered sidebar name, or the id when unknown.
	 *
	 * @param string $sidebar_id Sidebar id.
	 * @return string
	 * @since  2.1.62
	 */
	private static function sidebar_name( $sidebar_id ) {
		$sidebars = $GLOBALS['wp_registered_sidebars'] ?? array();
		return isset( $sidebars[ $sidebar_id ]['name'] ) ? (string) $sidebars[ $sidebar_id ]['name'] : $sidebar_id;
	}
}
