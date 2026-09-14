<?php
/**
 * Settings export/import singleton for ReportedIP Hive.
 *
 * Lets administrators download a JSON snapshot of every persisted plugin
 * setting and re-apply it on another site. Designed for agencies that
 * manage many WordPress installs and need to roll their preferred
 * configuration out without retyping every field.
 *
 * Sensitive credentials (API key, encrypted SMS provider config) are
 * excluded by default, there is an explicit opt-in checkbox guarded by
 * a warning. Per-user 2FA secrets (TOTP, WebAuthn, SMS number) are never
 * exported regardless of the toggle, because they are encrypted with a
 * site-specific key and would be useless on the target site anyway.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Owns the export, preview and apply pipeline for plugin settings.
 *
 * @since 1.2.0
 */
class ReportedIP_Hive_Settings_Import_Export {

	/**
	 * Schema version of the JSON envelope. Bump on breaking changes.
	 *
	 * @var int
	 */
	const SCHEMA_VERSION = 1;

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Settings_Import_Export|null
	 */
	private static $instance = null;

	/**
	 * Get singleton.
	 *
	 * @since  1.2.0
	 * @return ReportedIP_Hive_Settings_Import_Export
	 */
	public static function get_instance(): ReportedIP_Hive_Settings_Import_Export {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Wires AJAX endpoints. All endpoints are admin-only and nonce-protected.
	 *
	 * @since 1.2.0
	 */
	private function __construct() {
		add_action( 'wp_ajax_reportedip_hive_export_settings', array( $this, 'ajax_export' ) );
		add_action( 'wp_ajax_reportedip_hive_import_settings_preview', array( $this, 'ajax_preview' ) );
		add_action( 'wp_ajax_reportedip_hive_import_settings_apply', array( $this, 'ajax_apply' ) );
	}

	/**
	 * Section catalogue mapping each user-facing area to its option keys.
	 *
	 * Derived from the settings registry rather than hand-maintained. The two
	 * used to drift: fifty-five registry keys were missing from the export,
	 * some of them since long before the registry existed, so an exported file
	 * quietly left out half the configuration it claimed to contain.
	 *
	 * Only the two entries the registry cannot describe are added here: the
	 * connection identity, which is deliberately not a setting, and the IP
	 * lists, which are rows rather than options.
	 *
	 * @since  1.2.0
	 * @return array<string, array{label:string, description:string, options:array<int,string>}>
	 */
	public static function sections(): array {
		$sections = array(
			'general' => array(
				'label'       => __( 'General & connection', 'reportedip-hive' ),
				'description' => __( 'Operation mode, API endpoint and the Community Access Key. Only these travel outside the settings registry.', 'reportedip-hive' ),
				'options'     => array(
					'reportedip_hive_operation_mode',
					'reportedip_hive_api_endpoint',
				),
			),
		);

		if ( class_exists( 'ReportedIP_Hive_Settings_Registry' ) ) {
			$grouped = array();
			foreach ( ReportedIP_Hive_Settings_Registry::remote_spec() as $key => $entry ) {
				$grouped[ (string) $entry['section'] ][] = $key;
			}

			foreach ( ReportedIP_Hive_Settings_Registry::sections() as $slug => $section ) {
				if ( empty( $grouped[ $slug ] ) ) {
					continue;
				}
				$sections[ $slug ] = array(
					'label'       => $section['label'],
					'description' => $section['description'],
					'options'     => $grouped[ $slug ],
				);
			}
		}

		$sections['ip_lists'] = array(
			'label'       => __( 'IP lists', 'reportedip-hive' ),
			'description' => __( 'Whitelist + blocked IPs (manual entries only, runtime-blocked IPs stay site-local).', 'reportedip-hive' ),
			'options'     => array(),
		);

		return $sections;
	}

	/**
	 * Secret keys, exported only when the explicit opt-in is set.
	 *
	 * @since  1.2.0
	 * @return array<int, string>
	 */
	public static function secret_options(): array {
		return array(
			'reportedip_hive_api_key',
		);
	}

	/**
	 * Importable keys that are deliberately outside the settings registry,
	 * each with the sanitiser it needs.
	 *
	 * These three are connection identity rather than settings: they decide
	 * which account and which endpoint the site talks to. A fleet must never
	 * push them, which is why they are not registry keys, but a local export
	 * has always carried them and cloning a site would be pointless without
	 * them. They get this narrow, typed path instead of the blanket raw write
	 * the import used to perform for every unknown key.
	 *
	 * @since  2.1.51
	 * @return array<string, callable>
	 */
	private static function connection_keys(): array {
		return array(
			'reportedip_hive_api_key'        => 'sanitize_text_field',
			'reportedip_hive_api_endpoint'   => 'esc_url_raw',
			'reportedip_hive_operation_mode' => static function ( $value ) {
				$value = sanitize_key( (string) $value );
				return in_array( $value, array( 'local', 'community' ), true ) ? $value : '';
			},
		);
	}

	/**
	 * Flat allowlist of every importable option key (sections + secrets).
	 *
	 * @since  1.2.0
	 * @return array<int, string>
	 */
	public static function importable_keys(): array {
		$keys = array();
		foreach ( self::sections() as $section ) {
			foreach ( $section['options'] as $key ) {
				$keys[] = $key;
			}
		}
		foreach ( self::secret_options() as $key ) {
			$keys[] = $key;
		}
		return array_values( array_unique( $keys ) );
	}

	/**
	 * Renders the import/export panel inside the Performance tab.
	 *
	 * @since 1.2.0
	 */
	public function render_panel(): void {
		?>
		<div class="rip-settings-section" id="rip-settings-portability">
			<h2 class="rip-settings-section__title">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
				<?php esc_html_e( 'Settings import & export', 'reportedip-hive' ); ?>
			</h2>
			<p class="rip-settings-section__desc">
				<?php esc_html_e( 'Save your current configuration as a JSON file, or load configuration that was exported elsewhere. Useful for replicating settings across multiple sites.', 'reportedip-hive' ); ?>
			</p>

			<div class="rip-grid rip-grid-cols-2 rip-gap-4">
				<div class="rip-card">
					<div class="rip-card__header">
						<h3 class="rip-card__title"><?php esc_html_e( 'Export', 'reportedip-hive' ); ?></h3>
					</div>
					<div class="rip-card__body">
						<p class="rip-mb-3"><?php esc_html_e( 'Choose what to include. All sections are selected by default.', 'reportedip-hive' ); ?></p>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-ajax.php' ) ); ?>" id="rip-export-form" class="rip-stack">
							<input type="hidden" name="action" value="reportedip_hive_export_settings" />
							<?php wp_nonce_field( 'reportedip_hive_settings_import', '_rip_ie_nonce' ); ?>

							<?php foreach ( self::sections() as $slug => $section ) : ?>
								<label class="rip-section-pick">
									<input type="checkbox" name="sections[]" value="<?php echo esc_attr( $slug ); ?>" checked />
									<span>
										<strong><?php echo esc_html( $section['label'] ); ?></strong>
										<span class="rip-help-text"><?php echo esc_html( $section['description'] ); ?></span>
									</span>
								</label>
							<?php endforeach; ?>

							<label class="rip-section-pick rip-section-pick--secret rip-mt-3">
								<input type="checkbox" name="include_secrets" value="1" />
								<span>
									<strong><?php esc_html_e( 'Include credentials', 'reportedip-hive' ); ?></strong>
									<span class="rip-help-text"><?php esc_html_e( 'Adds the API key and encrypted SMS-provider config. Treat the resulting file like a password, do not share or email it.', 'reportedip-hive' ); ?></span>
								</span>
							</label>

							<button type="submit" class="rip-button rip-button--primary rip-mt-3">
								<?php esc_html_e( 'Download JSON', 'reportedip-hive' ); ?>
							</button>
						</form>
					</div>
				</div>

				<div class="rip-card">
					<div class="rip-card__header">
						<h3 class="rip-card__title"><?php esc_html_e( 'Import', 'reportedip-hive' ); ?></h3>
					</div>
					<div class="rip-card__body">
						<p class="rip-mb-3"><?php esc_html_e( 'Upload a previously exported JSON file. We show a preview of every change before anything is written.', 'reportedip-hive' ); ?></p>
						<form method="post" enctype="multipart/form-data" id="rip-import-form" class="rip-stack">
							<?php wp_nonce_field( 'reportedip_hive_settings_import', '_rip_ie_nonce' ); ?>
							<input type="file" name="settings_file" accept="application/json,.json" id="rip-import-file" required />
							<button type="submit" class="rip-button rip-button--secondary rip-mt-3">
								<?php esc_html_e( 'Preview changes', 'reportedip-hive' ); ?>
							</button>
						</form>
						<div id="rip-import-preview" class="rip-mt-4"></div>
					</div>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Verifies admin capability and AJAX nonce. Aborts with HTTP 403 otherwise.
	 *
	 * The import writes network-wide options on Multisite, so the capability
	 * follows the option-writing AJAX handlers: `manage_network_options` on
	 * Multisite, `manage_options` on single-site.
	 *
	 * @since 1.2.0
	 */
	private function require_authorised_admin(): void {
		if ( ! ReportedIP_Hive_Option_Routing::current_user_can_manage() ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'reportedip-hive' ) ), 403 );
		}
		check_ajax_referer( 'reportedip_hive_settings_import', '_rip_ie_nonce' );
	}

	/**
	 * AJAX: streams a settings export as a JSON file download.
	 *
	 * @since 1.2.0
	 */
	public function ajax_export(): void {
		$this->require_authorised_admin();

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Nonce verified by require_authorised_admin() above.
		$requested_sections = isset( $_POST['sections'] ) && is_array( $_POST['sections'] )
			? array_map( 'sanitize_key', wp_unslash( $_POST['sections'] ) )
			: array_keys( self::sections() );

		$include_secrets = ! empty( $_POST['include_secrets'] );
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		$payload = $this->build_export_payload( $requested_sections, $include_secrets );

		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="reportedip-hive-settings-' . gmdate( 'Y-m-d-Hi' ) . '.json"' );
		echo wp_json_encode( $payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
		exit;
	}

	/**
	 * The value a site actually runs on: the stored option, or the canonical
	 * default while nothing is stored.
	 *
	 * The export used to read unset options as `null`. Re-importing such a
	 * file then ran `null` through the registry sanitizer, which turns it
	 * into `0` for switches, the minimum for numbers and a rejection for
	 * choices and lists, so a site on its defaults became a site with most
	 * protections switched off.
	 *
	 * @param string $key Option key.
	 * @return mixed
	 * @since  2.1.57
	 */
	private static function effective_value( string $key ) {
		$defaults = class_exists( 'ReportedIP_Hive_Defaults' ) ? ReportedIP_Hive_Defaults::all_option_defaults() : array();
		return ReportedIP_Hive_Option_Routing::get( $key, $defaults[ $key ] ?? null );
	}

	/**
	 * Builds the export envelope for the requested sections.
	 *
	 * @param array<int, string> $requested_sections Section slugs to include.
	 * @param bool               $include_secrets    Whether to emit credential keys.
	 * @return array<string, mixed>
	 * @since 1.2.0
	 */
	public function build_export_payload( array $requested_sections, bool $include_secrets ): array {
		$valid_sections = array_intersect( $requested_sections, array_keys( self::sections() ) );

		$options = array();
		foreach ( $valid_sections as $section_slug ) {
			$section = self::sections()[ $section_slug ];
			foreach ( $section['options'] as $key ) {
				$options[ $key ] = self::effective_value( $key );
			}
		}

		if ( $include_secrets ) {
			foreach ( self::secret_options() as $key ) {
				$options[ $key ] = self::effective_value( $key );
			}
		}

		$ip_lists = array();
		if ( in_array( 'ip_lists', $valid_sections, true ) && class_exists( 'ReportedIP_Hive_IP_Manager' ) ) {
			$ip_manager            = ReportedIP_Hive_IP_Manager::get_instance();
			$ip_lists['whitelist'] = array_map(
				static fn( $row ) => array(
					'ip_address' => is_object( $row ) ? $row->ip_address : ( $row['ip_address'] ?? '' ),
					'reason'     => is_object( $row ) ? ( $row->reason ?? '' ) : ( $row['reason'] ?? '' ),
					'expires_at' => is_object( $row ) ? ( $row->expires_at ?? null ) : ( $row['expires_at'] ?? null ),
				),
				(array) $ip_manager->get_whitelist( true )
			);
			$ip_lists['blocked']   = array_map(
				static fn( $row ) => array(
					'ip_address'    => is_object( $row ) ? $row->ip_address : ( $row['ip_address'] ?? '' ),
					'reason'        => is_object( $row ) ? ( $row->reason ?? '' ) : ( $row['reason'] ?? '' ),
					'block_type'    => is_object( $row ) ? ( $row->block_type ?? 'manual' ) : ( $row['block_type'] ?? 'manual' ),
					'blocked_until' => is_object( $row ) ? ( $row->blocked_until ?? null ) : ( $row['blocked_until'] ?? null ),
				),
				(array) $ip_manager->get_blocked_ips( true )
			);
			$blocked_manual        = array();
			foreach ( $ip_lists['blocked'] as $row ) {
				if ( 'manual' === $row['block_type'] ) {
					$blocked_manual[] = $row;
				}
			}
			$ip_lists['blocked'] = $blocked_manual;
		}

		return array(
			'_meta'    => array(
				'plugin'           => 'reportedip-hive',
				'plugin_version'   => defined( 'REPORTEDIP_HIVE_VERSION' ) ? REPORTEDIP_HIVE_VERSION : 'unknown',
				'site_url'         => home_url(),
				'exported_at'      => gmdate( 'c' ),
				'schema_version'   => self::SCHEMA_VERSION,
				'sections'         => array_values( $valid_sections ),
				'includes_secrets' => $include_secrets,
			),
			'options'  => $options,
			'ip_lists' => (object) $ip_lists,
		);
	}

	/**
	 * AJAX: parses an uploaded JSON, returns a diff summary.
	 *
	 * @since 1.2.0
	 */
	public function ajax_preview(): void {
		$this->require_authorised_admin();

		$payload = $this->read_uploaded_payload();
		if ( is_wp_error( $payload ) ) {
			wp_send_json_error( array( 'message' => $payload->get_error_message() ), 400 );
		}

		wp_send_json_success(
			array(
				'meta'  => $payload['_meta'] ?? array(),
				'diffs' => $this->compute_diffs( $payload ),
			)
		);
	}

	/**
	 * AJAX: applies a previously previewed payload.
	 *
	 * Expects the same JSON file uploaded again (so the server never trusts
	 * client-side state). The user can pick which sections to commit.
	 *
	 * @since 1.2.0
	 */
	public function ajax_apply(): void {
		$this->require_authorised_admin();

		$payload = $this->read_uploaded_payload();
		if ( is_wp_error( $payload ) ) {
			wp_send_json_error( array( 'message' => $payload->get_error_message() ), 400 );
		}

		// phpcs:disable WordPress.Security.NonceVerification.Missing,WordPress.Security.NonceVerification.Recommended -- Nonce verified by require_authorised_admin() above.
		$selected_sections = isset( $_POST['sections'] ) && is_array( $_POST['sections'] )
			? array_map( 'sanitize_key', wp_unslash( $_POST['sections'] ) )
			: array_keys( self::sections() );
		// phpcs:enable WordPress.Security.NonceVerification.Missing,WordPress.Security.NonceVerification.Recommended

		$result = $this->apply_payload( $payload, $selected_sections );

		wp_send_json_success( $result );
	}

	/**
	 * Validates the uploaded JSON envelope and returns its decoded array form.
	 *
	 * Public so the setup wizard can reuse the same validation pipeline
	 * instead of duplicating size/JSON/schema checks.
	 *
	 * @param string $field_name Form field name (default 'settings_file').
	 * @return array<string, mixed>|WP_Error
	 * @since  1.2.0
	 */
	public function read_uploaded_payload( string $field_name = 'settings_file' ) {
		// phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- Caller (ajax_preview/ajax_apply) verifies nonce upstream via require_authorised_admin(); $_FILES tmp_name path is validated through is_uploaded_file() before any filesystem read.
		if ( empty( $_FILES[ $field_name ]['tmp_name'] ) || ! is_uploaded_file( (string) $_FILES[ $field_name ]['tmp_name'] ) ) {
			return new WP_Error( 'no_file', __( 'No file uploaded.', 'reportedip-hive' ) );
		}

		if ( (int) $_FILES[ $field_name ]['size'] > self::max_upload_bytes() ) {
			return new WP_Error( 'too_large', __( 'Settings file is larger than the allowed limit.', 'reportedip-hive' ) );
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading a freshly-uploaded local PHP-tmp file (size and type already validated above); wp_remote_get is for remote URLs and would be wrong here.
		$raw = file_get_contents( (string) $_FILES[ $field_name ]['tmp_name'] );
		// phpcs:enable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.InputNotValidated
		if ( false === $raw || '' === $raw ) {
			return new WP_Error( 'empty_file', __( 'Settings file is empty or unreadable.', 'reportedip-hive' ) );
		}

		$decoded = json_decode( $raw, true );
		if ( ! is_array( $decoded ) ) {
			return new WP_Error( 'invalid_json', __( 'Settings file is not valid JSON.', 'reportedip-hive' ) );
		}

		$meta = $decoded['_meta'] ?? array();
		if ( ( $meta['plugin'] ?? '' ) !== 'reportedip-hive' ) {
			return new WP_Error( 'wrong_plugin', __( 'This file does not belong to ReportedIP Hive.', 'reportedip-hive' ) );
		}
		if ( (int) ( $meta['schema_version'] ?? 0 ) !== self::SCHEMA_VERSION ) {
			return new WP_Error( 'schema_mismatch', __( 'Settings file uses an unsupported schema version.', 'reportedip-hive' ) );
		}

		return $decoded;
	}

	/**
	 * Returns the upload-size cap, falling back to a class-level default
	 * when the bootstrap constant has not been loaded (test harness).
	 *
	 * @since  1.2.0
	 * @return int
	 */
	private static function max_upload_bytes(): int {
		return defined( 'REPORTEDIP_MAX_SETTINGS_UPLOAD_SIZE' )
			? (int) REPORTEDIP_MAX_SETTINGS_UPLOAD_SIZE
			: 524288;
	}

	/**
	 * Builds a per-section diff between the payload and the current site.
	 *
	 * @param array<string, mixed> $payload Decoded JSON envelope.
	 * @return array<string, array<int, array{key:string, current:mixed, incoming:mixed, status:string}>>
	 * @since 1.2.0
	 */
	private function compute_diffs( array $payload ): array {
		$incoming = $payload['options'] ?? array();
		$diffs    = array();

		foreach ( self::sections() as $slug => $section ) {
			$rows = array();
			foreach ( $section['options'] as $key ) {
				if ( ! array_key_exists( $key, $incoming ) ) {
					continue;
				}
				$current = self::effective_value( $key );
				$status  = $this->values_equal( $current, $incoming[ $key ] ) ? 'unchanged' : 'changed';
				$rows[]  = array(
					'key'      => $key,
					'current'  => $current,
					'incoming' => $incoming[ $key ],
					'status'   => $status,
				);
			}
			if ( $rows ) {
				$diffs[ $slug ] = $rows;
			}
		}

		if ( isset( $payload['ip_lists'] ) ) {
			$ip                = (array) ( is_object( $payload['ip_lists'] ) ? get_object_vars( $payload['ip_lists'] ) : $payload['ip_lists'] );
			$diffs['ip_lists'] = array(
				array(
					'key'      => 'whitelist',
					'current'  => '',
					'incoming' => count( (array) ( $ip['whitelist'] ?? array() ) ),
					'status'   => 'changed',
				),
				array(
					'key'      => 'blocked',
					'current'  => '',
					'incoming' => count( (array) ( $ip['blocked'] ?? array() ) ),
					'status'   => 'changed',
				),
			);
		}

		return $diffs;
	}

	/**
	 * Loose equality that survives the boolean / "0" / "" round-trip
	 * WordPress does on options.
	 *
	 * @param mixed $a Left value.
	 * @param mixed $b Right value.
	 * @return bool
	 * @since 1.2.0
	 */
	private function values_equal( $a, $b ): bool {
		if ( is_bool( $a ) || is_bool( $b ) ) {
			return (bool) $a === (bool) $b;
		}
		if ( is_scalar( $a ) && is_scalar( $b ) ) {
			return (string) $a === (string) $b;
		}
		return $a === $b;
	}

	/**
	 * Applies a validated payload, honouring the user's section selection.
	 *
	 * A `null` value means the source site had nothing stored for that key.
	 * Files written before 2.1.57 carry such entries; they are skipped so
	 * the target keeps its own value instead of the sanitized form of
	 * nothing.
	 *
	 * Public so the setup wizard can re-use the same code path.
	 *
	 * @param array<string, mixed> $payload           Decoded JSON envelope.
	 * @param array<int, string>   $selected_sections Section slugs to commit.
	 * @return array{written:int, skipped:int, ip_added:int, ip_skipped:int, errors:array<int,string>}
	 * @since 1.2.0
	 */
	public function apply_payload( array $payload, array $selected_sections ): array {
		$valid_sections   = array_intersect( $selected_sections, array_keys( self::sections() ) );
		$incoming         = $payload['options'] ?? array();
		$includes_secrets = ! empty( $payload['_meta']['includes_secrets'] );

		$allowed_keys = array();
		foreach ( $valid_sections as $section_slug ) {
			foreach ( self::sections()[ $section_slug ]['options'] as $key ) {
				$allowed_keys[ $key ] = true;
			}
		}
		if ( $includes_secrets ) {
			foreach ( self::secret_options() as $key ) {
				$allowed_keys[ $key ] = true;
			}
		}

		$written = 0;
		$skipped = 0;
		$errors  = array();

		$registry_spec    = class_exists( 'ReportedIP_Hive_Settings_Registry' ) ? ReportedIP_Hive_Settings_Registry::remote_spec() : array();
		$connection_spec  = self::connection_keys();
		$registry_batch   = array();
		$connection_batch = array();

		foreach ( $incoming as $key => $value ) {
			if ( ! is_string( $key ) || ! isset( $allowed_keys[ $key ] ) || null === $value ) {
				++$skipped;
				continue;
			}
			if ( isset( $registry_spec[ $key ] ) ) {
				$registry_batch[ $key ] = $value;
				continue;
			}
			if ( isset( $connection_spec[ $key ] ) ) {
				$connection_batch[ $key ] = $value;
				continue;
			}
			++$skipped;
		}

		if ( ! empty( $registry_batch ) ) {
			$apply = ReportedIP_Hive_Settings_Apply::apply( $registry_batch, 'import' );
			foreach ( $apply['results'] as $key => $result ) {
				if ( in_array( $result['status'], array( ReportedIP_Hive_Settings_Apply::STATUS_APPLIED, ReportedIP_Hive_Settings_Apply::STATUS_UNCHANGED ), true ) ) {
					++$written;
					continue;
				}
				++$skipped;
				if ( ! empty( $result['message'] ) ) {
					$errors[] = sprintf( '%s: %s', $key, $result['message'] );
				}
			}
		}

		foreach ( $connection_batch as $key => $value ) {
			$clean = call_user_func( $connection_spec[ $key ], is_scalar( $value ) ? (string) $value : '' );
			if ( '' === $clean ) {
				++$skipped;
				continue;
			}
			ReportedIP_Hive_Option_Routing::set( $key, $clean );
			++$written;
		}

		$ip_added   = 0;
		$ip_skipped = 0;

		if ( in_array( 'ip_lists', $valid_sections, true ) && isset( $payload['ip_lists'] ) && class_exists( 'ReportedIP_Hive_IP_Manager' ) ) {
			$ip_manager = ReportedIP_Hive_IP_Manager::get_instance();
			$lists      = is_object( $payload['ip_lists'] ) ? get_object_vars( $payload['ip_lists'] ) : (array) $payload['ip_lists'];

			foreach ( (array) ( $lists['whitelist'] ?? array() ) as $row ) {
				$ip = is_array( $row ) ? ( $row['ip_address'] ?? '' ) : '';
				if ( '' === $ip || $ip_manager->is_whitelisted( $ip ) ) {
					++$ip_skipped;
					continue;
				}
				$ip_manager->whitelist_ip( $ip, isset( $row['reason'] ) ? (string) $row['reason'] : '', $row['expires_at'] ?? null );
				++$ip_added;
			}

			foreach ( (array) ( $lists['blocked'] ?? array() ) as $row ) {
				$ip = is_array( $row ) ? ( $row['ip_address'] ?? '' ) : '';
				if ( '' === $ip || $ip_manager->is_blocked( $ip ) ) {
					++$ip_skipped;
					continue;
				}
				$ip_manager->block_ip( $ip, isset( $row['reason'] ) ? (string) $row['reason'] : '', null, 'manual' );
				++$ip_added;
			}
		}

		if ( class_exists( 'ReportedIP_Hive_Logger' ) ) {
			$admin_ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
			ReportedIP_Hive_Logger::get_instance()->log_security_event(
				'settings_imported',
				$admin_ip,
				array(
					'sections' => array_values( $valid_sections ),
					'written'  => $written,
					'ip_added' => $ip_added,
					'user_id'  => get_current_user_id(),
					'source'   => isset( $payload['_meta']['site_url'] ) ? (string) $payload['_meta']['site_url'] : '',
				),
				'low'
			);
		}

		return array(
			'written'    => $written,
			'skipped'    => $skipped,
			'ip_added'   => $ip_added,
			'ip_skipped' => $ip_skipped,
			'errors'     => $errors,
		);
	}
}
