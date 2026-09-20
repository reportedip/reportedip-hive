<?php
/**
 * Audit connector for the built-in theme and plugin file editor.
 *
 * Hooks the editor's AJAX action ahead of core, resolves the target file
 * the way core does, remembers its hash, and compares again on shutdown.
 * Only a changed hash produces a row: a rejected or failed save leaves no
 * trace, a real one names the file that changed.
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
 * File editor capture.
 *
 * @since 2.1.62
 */
class ReportedIP_Hive_Audit_Connector_Editor extends ReportedIP_Hive_Audit_Connector {

	/**
	 * Hooks of this connector.
	 *
	 * @return array<string, array{0:string, 1:int, 2:int}>
	 * @since  2.1.62
	 */
	protected function hooks() {
		return array(
			'wp_ajax_edit-theme-plugin-file' => array( 'before_edit', 0, 0 ),
		);
	}

	/**
	 * Resolve the file the editor is about to write, as core does.
	 *
	 * @param array<string,mixed> $request POST fields `file`, `theme`, `plugin`.
	 * @return array{path:string, label:string, kind:string, slug:string}|null
	 * @since  2.1.62
	 */
	public static function resolve( array $request ) {
		$file = (string) ( $request['file'] ?? '' );
		if ( '' === $file || 0 !== validate_file( $file ) ) {
			return null;
		}
		if ( ! empty( $request['theme'] ) ) {
			$stylesheet = (string) $request['theme'];
			if ( 0 !== validate_file( $stylesheet ) ) {
				return null;
			}
			$theme = wp_get_theme( $stylesheet );
			if ( ! $theme->exists() ) {
				return null;
			}
			return array(
				'path'  => $theme->get_stylesheet_directory() . '/' . $file,
				'label' => $stylesheet . '/' . $file,
				'kind'  => 'theme',
				'slug'  => $stylesheet,
			);
		}
		if ( ! empty( $request['plugin'] ) ) {
			$plugin = (string) $request['plugin'];
			if ( 0 !== validate_file( $plugin ) ) {
				return null;
			}
			return array(
				'path'  => WP_PLUGIN_DIR . '/' . dirname( $plugin ) . '/' . $file,
				'label' => dirname( $plugin ) . '/' . $file,
				'kind'  => 'plugin',
				'slug'  => $plugin,
			);
		}
		return null;
	}

	/**
	 * Remember the file hash, then check again once core has answered.
	 *
	 * @return void
	 * @since  2.1.62
	 */
	public function before_edit() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Read-only snapshot; core verifies the nonce and the capability before writing.
		$target = self::resolve( wp_unslash( $_POST ) );
		if ( null === $target || ! is_file( $target['path'] ) ) {
			return;
		}
		$before = md5_file( $target['path'] );
		add_action(
			'shutdown',
			function () use ( $target, $before ) {
				$after = is_file( $target['path'] ) ? md5_file( $target['path'] ) : false;
				if ( false === $after || $after === $before ) {
					return;
				}
				$this->log(
					'file',
					'edited',
					array(
						'kind' => $target['kind'],
						'slug' => $target['slug'],
					),
					array(
						'type'  => $target['kind'] . '_file',
						'id'    => 0,
						'label' => $target['label'],
					)
				);
			}
		);
	}
}
