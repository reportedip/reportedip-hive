<?php
/**
 * Audit connector for plugins, themes and WordPress core.
 *
 * Every install, update, activation, deactivation and deletion, the theme
 * switch and the core update, with the version before and after where the
 * upgrader lets us know it. Automatic updates from the cron are rows too;
 * they carry `agent = cron` instead of a user.
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
 * Installer capture.
 *
 * @since 2.1.62
 */
class ReportedIP_Hive_Audit_Connector_Installer extends ReportedIP_Hive_Audit_Connector {

	/**
	 * Plugin versions before an upgrade, keyed by plugin file.
	 *
	 * @var array<string, string>
	 */
	private $plugin_versions_before = array();

	/**
	 * Theme versions before an upgrade, keyed by stylesheet.
	 *
	 * @var array<string, string>
	 */
	private $theme_versions_before = array();

	/**
	 * Hooks of this connector.
	 *
	 * @return array<string, array{0:string, 1:int, 2:int}>
	 * @since  2.1.62
	 */
	protected function hooks() {
		return array(
			'activated_plugin'           => array( 'on_activated', 10, 2 ),
			'deactivated_plugin'         => array( 'on_deactivated', 10, 2 ),
			'deleted_plugin'             => array( 'on_plugin_deleted', 10, 2 ),
			'deleted_theme'              => array( 'on_theme_deleted', 10, 2 ),
			'switch_theme'               => array( 'on_theme_switched', 10, 3 ),
			'upgrader_pre_install'       => array( 'snapshot_versions', 10, 2 ),
			'upgrader_process_complete'  => array( 'on_upgrade_complete', 10, 2 ),
			'_core_updated_successfully' => array( 'on_core_updated', 10, 1 ),
		);
	}

	/**
	 * Plugin activated.
	 *
	 * @param string $plugin       Plugin file.
	 * @param bool   $network_wide Network activation.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_activated( $plugin, $network_wide = false ) {
		$this->log_plugin( 'activated', (string) $plugin, array( 'network_wide' => $network_wide ? 1 : 0 ), $network_wide ? 0 : null );
	}

	/**
	 * Plugin deactivated.
	 *
	 * @param string $plugin  Plugin file.
	 * @param bool   $network Network deactivation.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_deactivated( $plugin, $network = false ) {
		$this->log_plugin( 'deactivated', (string) $plugin, array( 'network_wide' => $network ? 1 : 0 ), $network ? 0 : null );
	}

	/**
	 * Plugin deleted from disk.
	 *
	 * @param string $plugin  Plugin file.
	 * @param bool   $deleted Whether the deletion succeeded.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_plugin_deleted( $plugin, $deleted ) {
		if ( ! $deleted ) {
			return;
		}
		$this->log( 'plugin', 'deleted', array( 'slug' => (string) $plugin ), self::plugin_object( (string) $plugin ), self::network_scope() );
	}

	/**
	 * Theme deleted from disk.
	 *
	 * @param string $stylesheet Theme directory.
	 * @param bool   $deleted    Whether the deletion succeeded.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_theme_deleted( $stylesheet, $deleted ) {
		if ( ! $deleted ) {
			return;
		}
		$this->log( 'theme', 'deleted', array( 'slug' => (string) $stylesheet ), self::theme_object( (string) $stylesheet ), self::network_scope() );
	}

	/**
	 * Active theme switched.
	 *
	 * @param string   $new_name  New theme name.
	 * @param WP_Theme $new_theme New theme.
	 * @param WP_Theme $old_theme Previous theme.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_theme_switched( $new_name, $new_theme, $old_theme ) {
		$this->log(
			'theme',
			'switched',
			array(
				'slug'     => $new_theme->get_stylesheet(),
				'old_slug' => $old_theme->get_stylesheet(),
				'old_name' => (string) $old_theme->get( 'Name' ),
			),
			array(
				'type'  => 'theme',
				'id'    => 0,
				'label' => (string) $new_name,
			)
		);
	}

	/**
	 * Remember the versions on disk before the upgrader replaces them.
	 *
	 * @param bool|WP_Error       $response   Upgrader response so far.
	 * @param array<string,mixed> $hook_extra Upgrader context.
	 * @return bool|WP_Error Unchanged response.
	 * @since  2.1.62
	 */
	public function snapshot_versions( $response, $hook_extra ) {
		$hook_extra = is_array( $hook_extra ) ? $hook_extra : array();
		if ( ! empty( $hook_extra['plugin'] ) && function_exists( 'get_plugins' ) ) {
			$all = get_plugins();
			$key = (string) $hook_extra['plugin'];
			if ( isset( $all[ $key ]['Version'] ) ) {
				$this->plugin_versions_before[ $key ] = (string) $all[ $key ]['Version'];
			}
		}
		if ( ! empty( $hook_extra['theme'] ) ) {
			$theme = wp_get_theme( (string) $hook_extra['theme'] );
			if ( $theme->exists() ) {
				$this->theme_versions_before[ (string) $hook_extra['theme'] ] = (string) $theme->get( 'Version' );
			}
		}
		return $response;
	}

	/**
	 * Installs and updates of plugins and themes.
	 *
	 * @param WP_Upgrader         $upgrader   Upgrader instance.
	 * @param array<string,mixed> $hook_extra Context: action, type, plugin(s)/theme(s), bulk.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_upgrade_complete( $upgrader, $hook_extra ) {
		foreach ( self::from_hook_extra( is_array( $hook_extra ) ? $hook_extra : array(), $upgrader ) as $item ) {
			$before = 'plugin' === $item['type']
				? ( $this->plugin_versions_before[ $item['slug'] ] ?? '' )
				: ( $this->theme_versions_before[ $item['slug'] ] ?? '' );

			$object = 'plugin' === $item['type'] ? self::plugin_object( $item['slug'] ) : self::theme_object( $item['slug'] );
			$after  = self::current_version( $item['type'], $item['slug'] );

			if ( self::seen( $item['type'] . ':' . $item['action'] . ':' . $item['slug'] . ':' . $after ) ) {
				continue;
			}
			$this->log(
				$item['type'],
				$item['action'],
				array(
					'slug'         => $item['slug'],
					'from_version' => $before,
					'to_version'   => $after,
				),
				$object,
				self::network_scope()
			);
		}
	}

	/**
	 * Normalise the upgrader context into a list of (type, action, slug).
	 *
	 * Pure apart from the upgrader lookups for a fresh install, which is
	 * the only case where the context carries no slug.
	 *
	 * @param array<string,mixed> $hook_extra Upgrader context.
	 * @param object|null         $upgrader   Upgrader, for `new_plugin_data` / `new_theme_data`.
	 * @return array<int, array{type:string, action:string, slug:string}>
	 * @since  2.1.62
	 */
	public static function from_hook_extra( array $hook_extra, $upgrader = null ) {
		$type = (string) ( $hook_extra['type'] ?? '' );
		if ( ! in_array( $type, array( 'plugin', 'theme' ), true ) ) {
			return array();
		}
		$action = 'install' === ( $hook_extra['action'] ?? '' ) ? 'installed' : 'updated';
		$slugs  = array();

		if ( 'installed' === $action ) {
			$slug = '';
			if ( 'plugin' === $type && is_object( $upgrader ) && method_exists( $upgrader, 'plugin_info' ) ) {
				$slug = (string) ( $upgrader->plugin_info() ?: ( $upgrader->new_plugin_data['Name'] ?? '' ) );
			} elseif ( 'theme' === $type && is_object( $upgrader ) && method_exists( $upgrader, 'theme_info' ) ) {
				$info = $upgrader->theme_info();
				$slug = $info instanceof WP_Theme ? $info->get_stylesheet() : (string) ( $upgrader->new_theme_data['Name'] ?? '' );
			}
			if ( '' !== $slug ) {
				$slugs[] = $slug;
			}
		} else {
			$single = 'plugin' === $type ? 'plugin' : 'theme';
			$many   = 'plugin' === $type ? 'plugins' : 'themes';
			if ( ! empty( $hook_extra[ $single ] ) ) {
				$slugs[] = (string) $hook_extra[ $single ];
			}
			foreach ( (array) ( $hook_extra[ $many ] ?? array() ) as $slug ) {
				$slugs[] = (string) $slug;
			}
		}

		$out = array();
		foreach ( array_unique( $slugs ) as $slug ) {
			$out[] = array(
				'type'   => $type,
				'action' => $action,
				'slug'   => $slug,
			);
		}
		return $out;
	}

	/**
	 * Core updated.
	 *
	 * @param string $new_version Version just installed.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_core_updated( $new_version ) {
		$this->log(
			'core',
			'updated',
			array(
				'from_version' => (string) ( $GLOBALS['wp_version'] ?? '' ),
				'to_version'   => (string) $new_version,
			),
			array(
				'type'  => 'core',
				'id'    => 0,
				'label' => 'WordPress',
			),
			self::network_scope()
		);
	}

	/**
	 * Activation and deactivation share one shape.
	 *
	 * @param string              $action  Audit action.
	 * @param string              $plugin  Plugin file.
	 * @param array<string,mixed> $data    Extra data.
	 * @param int|null            $blog_id Scope.
	 * @return void
	 * @since  2.1.62
	 */
	private function log_plugin( $action, $plugin, array $data, $blog_id ) {
		$data['slug']         = $plugin;
		$data['from_version'] = '';
		$data['to_version']   = self::current_version( 'plugin', $plugin );
		$this->log( 'plugin', $action, $data, self::plugin_object( $plugin ), $blog_id );
	}

	/**
	 * Version currently on disk.
	 *
	 * @param string $type `plugin` or `theme`.
	 * @param string $slug Plugin file or stylesheet.
	 * @return string
	 * @since  2.1.62
	 */
	private static function current_version( $type, $slug ) {
		if ( 'theme' === $type ) {
			$theme = wp_get_theme( $slug );
			return $theme->exists() ? (string) $theme->get( 'Version' ) : '';
		}
		$file = WP_PLUGIN_DIR . '/' . $slug;
		if ( ! function_exists( 'get_plugin_data' ) || ! is_file( $file ) ) {
			return '';
		}
		$data = get_plugin_data( $file, false, false );
		return (string) ( $data['Version'] ?? '' );
	}

	/**
	 * Object descriptor of a plugin, name from the header when still on disk.
	 *
	 * @param string $plugin Plugin file.
	 * @return array{type:string, id:int, label:string}
	 * @since  2.1.62
	 */
	private static function plugin_object( $plugin ) {
		$label = $plugin;
		$file  = WP_PLUGIN_DIR . '/' . $plugin;
		if ( function_exists( 'get_plugin_data' ) && is_file( $file ) ) {
			$data  = get_plugin_data( $file, false, false );
			$label = '' !== (string) ( $data['Name'] ?? '' ) ? (string) $data['Name'] : $plugin;
		}
		return array(
			'type'  => 'plugin',
			'id'    => 0,
			'label' => $label,
		);
	}

	/**
	 * Object descriptor of a theme.
	 *
	 * @param string $stylesheet Theme directory.
	 * @return array{type:string, id:int, label:string}
	 * @since  2.1.62
	 */
	private static function theme_object( $stylesheet ) {
		$theme = wp_get_theme( $stylesheet );
		return array(
			'type'  => 'theme',
			'id'    => 0,
			'label' => $theme->exists() ? (string) $theme->get( 'Name' ) : $stylesheet,
		);
	}

	/**
	 * Installer rows are network state on a network.
	 *
	 * @return int|null 0 on multisite, null (current site) otherwise.
	 * @since  2.1.62
	 */
	private static function network_scope() {
		return is_multisite() ? 0 : null;
	}
}
