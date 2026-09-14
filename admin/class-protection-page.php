<?php
/**
 * Protection page: every registry section rendered as one card, one form.
 *
 * Simple and expert are the same page with a different depth: the simple
 * view shows the keys flagged `simple` in the registry, the expert view
 * shows everything. Saving posts one section to admin-post.php and writes
 * through `ReportedIP_Hive_Settings_Apply`, the same path MainWP, the cloud
 * fleet, the import and the quickstart use.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.56
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Renders and saves the protection page.
 *
 * @since 2.1.56
 */
class ReportedIP_Hive_Protection_Page {

	/**
	 * Page slug.
	 *
	 * @var string
	 */
	const PAGE_SLUG = 'reportedip-hive-protection';

	/**
	 * admin-post action of the per-section save.
	 *
	 * @var string
	 */
	const ACTION_SAVE = 'reportedip_hive_protection_save';

	/**
	 * admin-post action of the expert-mode toggle.
	 *
	 * @var string
	 */
	const ACTION_EXPERT = 'reportedip_hive_set_expert_mode';

	/**
	 * Nonce action.
	 *
	 * @var string
	 */
	const NONCE = 'reportedip_hive_protection';

	/**
	 * User meta that switches the expert view on.
	 *
	 * @var string
	 */
	const META_EXPERT = 'reportedip_hive_expert_mode';

	/**
	 * Transient prefix carrying the last save result back to the page.
	 *
	 * @var string
	 */
	const RESULT_TRANSIENT = 'reportedip_hive_protection_result_';

	/**
	 * Name of the preset pseudo field.
	 *
	 * @var string
	 */
	const PRESET_FIELD = 'rip_protection_level';

	/**
	 * Registry keys the preset pseudo field writes.
	 *
	 * @var string[]
	 */
	const PRESET_KEYS = array(
		'reportedip_hive_failed_login_threshold',
		'reportedip_hive_failed_login_timeframe',
		'reportedip_hive_block_duration',
		'reportedip_hive_block_threshold',
	);

	/**
	 * The instance the bootstrap created.
	 *
	 * @var ReportedIP_Hive_Protection_Page|null
	 */
	private static $instance = null;

	/**
	 * Wire hooks.
	 */
	public function __construct() {
		self::$instance = $this;
		add_action( 'admin_post_' . self::ACTION_SAVE, array( $this, 'handle_save' ) );
		add_action( 'admin_post_' . self::ACTION_EXPERT, array( $this, 'handle_expert_toggle' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
	}

	/**
	 * The bootstrap instance.
	 *
	 * @return ReportedIP_Hive_Protection_Page
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Whether the current user sees the expert depth.
	 *
	 * Site admins on Multisite never reach this page, so no extra guard.
	 *
	 * @return bool
	 */
	public static function is_expert() {
		return (bool) get_user_meta( get_current_user_id(), self::META_EXPERT, true );
	}

	/**
	 * Registry keys of one section in registry order, filtered to the
	 * simple set unless the expert view is on.
	 *
	 * @param string $section Section id.
	 * @param bool   $expert  Expert view.
	 * @return string[]
	 */
	public static function visible_keys( $section, $expert ) {
		$keys = array();
		foreach ( ReportedIP_Hive_Settings_Registry::spec() as $key => $entry ) {
			if ( ( $entry['section'] ?? '' ) !== $section ) {
				continue;
			}
			if ( ! $expert && empty( $entry['simple'] ) ) {
				continue;
			}
			$keys[] = $key;
		}
		return $keys;
	}

	/**
	 * Whether a section has no simple key at all.
	 *
	 * @param string $section Section id.
	 * @return bool
	 */
	public static function section_is_expert_only( $section ) {
		return array() === self::visible_keys( $section, false );
	}

	/**
	 * Turn the POST of one section into a registry value map.
	 *
	 * Every key of the section is present in the result: a missing switch
	 * is `'0'`, a missing checkbox group is `array()`, a missing text field
	 * is `''`. The preset pseudo field expands into its four keys; the
	 * marker `custom` leaves them alone.
	 *
	 * @param array<string,mixed> $post    Raw POST (already unslashed).
	 * @param string              $section Section id.
	 * @return array<string,mixed>
	 */
	public static function collect_values( array $post, $section ) {
		$values = array();
		foreach ( ReportedIP_Hive_Settings_Registry::spec() as $key => $entry ) {
			if ( ( $entry['section'] ?? '' ) !== $section ) {
				continue;
			}
			if ( array_key_exists( $key, $post ) ) {
				$values[ $key ] = $post[ $key ];
				continue;
			}
			switch ( $entry['kind'] ) {
				case 'bool':
					$values[ $key ] = '0';
					break;
				case 'json_list':
					$values[ $key ] = array();
					break;
				default:
					$values[ $key ] = '';
			}
		}
		if ( 'detection' === $section && isset( $post[ self::PRESET_FIELD ] ) ) {
			$presets = ReportedIP_Hive_Defaults::protection_presets();
			$level   = (string) $post[ self::PRESET_FIELD ];
			if ( isset( $presets[ $level ] ) ) {
				foreach ( $presets[ $level ] as $short => $value ) {
					$values[ 'reportedip_hive_' . $short ] = (int) $value;
				}
			}
		}
		return $values;
	}

	/**
	 * Name of the preset whose four values match the current ones.
	 *
	 * @param array<string,mixed> $current Current registry values.
	 * @return string Preset id or `custom`.
	 */
	public static function current_preset( array $current ) {
		foreach ( ReportedIP_Hive_Defaults::protection_presets() as $level => $values ) {
			$match = true;
			foreach ( $values as $short => $value ) {
				if ( (int) ( $current[ 'reportedip_hive_' . $short ] ?? -1 ) !== (int) $value ) {
					$match = false;
					break;
				}
			}
			if ( $match ) {
				return (string) $level;
			}
		}
		return 'custom';
	}

	/**
	 * Markup of one field: label, control, description, lock.
	 *
	 * @param string               $key     Registry key.
	 * @param array<string,mixed>  $entry   Registry entry.
	 * @param mixed                $value   Current value.
	 * @param array<string,mixed>  $status  `feature_status()` result (`available` true when no gate).
	 * @param array<string,string> $choices Choice map for `json_list` (value => label).
	 * @return string
	 */
	public static function field_markup( $key, array $entry, $value, array $status, array $choices = array() ) {
		$locked   = empty( $status['available'] );
		$id       = 'rip-field-' . str_replace( 'reportedip_hive_', '', $key );
		$label    = (string) ( $entry['label'] ?? $key );
		$desc     = (string) ( $entry['description'] ?? '' );
		$search   = strtolower( $label . ' ' . $desc . ' ' . str_replace( array( 'reportedip_hive_', '_' ), array( '', ' ' ), $key ) );
		$disabled = $locked ? ' disabled' : '';
		$classes  = 'rip-protection__field' . ( $locked ? ' rip-protection__field--locked' : '' );
		$kind     = (string) $entry['kind'];

		switch ( $kind ) {
			case 'bool':
				$control = sprintf(
					'<label class="rip-toggle"><input type="checkbox" class="rip-toggle__input" id="%1$s" name="%2$s" value="1"%3$s%4$s /><span class="rip-toggle__slider"></span></label>',
					esc_attr( $id ),
					esc_attr( $key ),
					! empty( $value ) ? ' checked' : '',
					$disabled
				);
				break;
			case 'int':
				$control = sprintf(
					'<input type="number" class="rip-input rip-input--sm" id="%1$s" name="%2$s" value="%3$s" min="%4$s" max="%5$s"%6$s />',
					esc_attr( $id ),
					esc_attr( $key ),
					esc_attr( (string) $value ),
					esc_attr( (string) ( $entry['min'] ?? 0 ) ),
					esc_attr( (string) ( $entry['max'] ?? PHP_INT_MAX ) ),
					$disabled
				);
				break;
			case 'enum':
				$options = '';
				foreach ( (array) ( $entry['allowed'] ?? array() ) as $allowed ) {
					$options .= sprintf(
						'<option value="%1$s"%2$s>%3$s</option>',
						esc_attr( (string) $allowed ),
						(string) $allowed === (string) $value ? ' selected' : '',
						esc_html( self::enum_label( (string) $allowed ) )
					);
				}
				$control = sprintf( '<select class="rip-select" id="%1$s" name="%2$s"%3$s>%4$s</select>', esc_attr( $id ), esc_attr( $key ), $disabled, $options );
				break;
			case 'json_list':
				$current = array_map( 'strval', (array) $value );
				$boxes   = '';
				foreach ( $choices as $choice => $choice_label ) {
					$boxes .= sprintf(
						'<label class="rip-checkbox"><input type="checkbox" name="%1$s[]" value="%2$s" %3$s%4$s /> %5$s</label>',
						esc_attr( $key ),
						esc_attr( (string) $choice ),
						in_array( (string) $choice, $current, true ) ? 'checked' : '',
						$disabled,
						esc_html( (string) $choice_label )
					);
				}
				$control = '<div class="rip-checkbox-group" id="' . esc_attr( $id ) . '">' . $boxes . '</div>';
				break;
			case 'textarea':
				$control = sprintf(
					'<textarea class="rip-textarea" id="%1$s" name="%2$s" rows="4"%3$s>%4$s</textarea>',
					esc_attr( $id ),
					esc_attr( $key ),
					$disabled,
					esc_textarea( (string) $value )
				);
				break;
			default:
				$type    = 'email' === $kind ? 'email' : ( 'url' === $kind ? 'url' : 'text' );
				$control = sprintf(
					'<input type="%1$s" class="rip-input" id="%2$s" name="%3$s" value="%4$s"%5$s />',
					$type,
					esc_attr( $id ),
					esc_attr( $key ),
					esc_attr( (string) $value ),
					$disabled
				);
		}

		$lock = '';
		if ( $locked && class_exists( 'ReportedIP_Hive_Admin_Settings' ) ) {
			ob_start();
			ReportedIP_Hive_Admin_Settings::render_tier_marker( $status );
			$lock = (string) ob_get_clean();
		}

		return sprintf(
			'<div class="%1$s" data-search="%2$s" data-key="%3$s"><div class="rip-protection__field-head"><label class="rip-label" for="%4$s">%5$s</label>%6$s</div><div class="rip-protection__control">%7$s</div>%8$s</div>',
			esc_attr( $classes ),
			esc_attr( $search ),
			esc_attr( $key ),
			esc_attr( $id ),
			esc_html( $label ),
			$lock,
			$control,
			'' !== $desc ? '<p class="rip-help-text">' . esc_html( $desc ) . '</p>' : ''
		);
	}

	/**
	 * Human label for an enum value.
	 *
	 * @param string $value Allowed value.
	 * @return string
	 */
	private static function enum_label( $value ) {
		$labels = array(
			''            => __( 'None (REMOTE_ADDR)', 'reportedip-hive' ),
			'off'         => __( 'Off', 'reportedip-hive' ),
			'flag'        => __( 'Flag only', 'reportedip-hive' ),
			'block'       => __( 'Block', 'reportedip-hive' ),
			'monitor'     => __( 'Monitor', 'reportedip-hive' ),
			'allow'       => __( 'Allow list', 'reportedip-hive' ),
			'spam'        => __( 'Mark as spam', 'reportedip-hive' ),
			'open'        => __( 'Open', 'reportedip-hive' ),
			'logged_in'   => __( 'Signed-in users only', 'reportedip-hive' ),
			'restricted'  => __( 'Restricted', 'reportedip-hive' ),
			'block_page'  => __( 'Block page', 'reportedip-hive' ),
			'404'         => __( '404', 'reportedip-hive' ),
			'enroll'      => __( 'Force enrolment', 'reportedip-hive' ),
			'lockout'     => __( 'Block sign-in', 'reportedip-hive' ),
			'report_only' => __( 'Report only', 'reportedip-hive' ),
			'enforce'     => __( 'Enforce', 'reportedip-hive' ),
			'badge'       => __( 'Badge', 'reportedip-hive' ),
			'shield'      => __( 'Shield', 'reportedip-hive' ),
			'left'        => __( 'Left', 'reportedip-hive' ),
			'center'      => __( 'Centre', 'reportedip-hive' ),
			'right'       => __( 'Right', 'reportedip-hive' ),
			'below'       => __( 'Below', 'reportedip-hive' ),
			'debug'       => __( 'Debug', 'reportedip-hive' ),
			'info'        => __( 'Info', 'reportedip-hive' ),
			'warning'     => __( 'Warning', 'reportedip-hive' ),
			'error'       => __( 'Error', 'reportedip-hive' ),
			'critical'    => __( 'Critical', 'reportedip-hive' ),
		);
		return $labels[ $value ] ?? $value;
	}

	/**
	 * Choice map for a `json_list` key.
	 *
	 * @param array<string,mixed> $entry Registry entry.
	 * @return array<string,string>
	 */
	public static function choices_for( array $entry ) {
		if ( 'methods' === ( $entry['choices'] ?? '' ) ) {
			return array(
				'totp'     => __( 'Authenticator app (TOTP)', 'reportedip-hive' ),
				'email'    => __( 'E-mail code', 'reportedip-hive' ),
				'sms'      => __( 'SMS code', 'reportedip-hive' ),
				'webauthn' => __( 'Security key / passkey', 'reportedip-hive' ),
			);
		}
		if ( 'roles' === ( $entry['choices'] ?? '' ) && function_exists( 'wp_roles' ) ) {
			return array_map( 'strval', wp_roles()->get_names() );
		}
		return array();
	}

	/**
	 * Short status shown in the card head.
	 *
	 * @param string              $section Section id.
	 * @param array<string,mixed> $current Current values.
	 * @return string
	 */
	public static function section_status( $section, array $current ) {
		$on  = __( 'on', 'reportedip-hive' );
		$off = __( 'off', 'reportedip-hive' );
		switch ( $section ) {
			case 'detection':
				$sensors = 0;
				foreach ( $current as $key => $value ) {
					if ( 0 === strpos( (string) $key, 'reportedip_hive_monitor_' ) && ! empty( $value ) ) {
						++$sensors;
					}
				}
				$preset_labels = self::preset_labels();
				/* translators: 1: preset name, 2: number of active sensors */
				return sprintf( __( '%1$s · %2$d sensors', 'reportedip-hive' ), $preset_labels[ self::current_preset( $current ) ], $sensors );
			case 'blocking':
				if ( ! empty( $current['reportedip_hive_report_only_mode'] ) ) {
					return __( 'report only', 'reportedip-hive' );
				}
				return ! empty( $current['reportedip_hive_auto_block'] ) ? $on : $off;
			case 'waf':
				return ! empty( $current['reportedip_hive_waf_enabled'] ) ? $on : $off;
			case 'hide_login':
				return ! empty( $current['reportedip_hive_hide_login_enabled'] ) ? '/' . (string) ( $current['reportedip_hive_hide_login_slug'] ?? '' ) : $off;
			case 'headers':
				return ! empty( $current['reportedip_hive_headers_enabled'] ) ? $on : $off;
			case 'account_security':
				if ( empty( $current['reportedip_hive_2fa_enabled_global'] ) ) {
					return $off;
				}
				$roles = count( (array) ( $current['reportedip_hive_2fa_enforce_roles'] ?? array() ) );
				/* translators: %d: number of roles */
				return sprintf( _n( '%d role enforced', '%d roles enforced', $roles, 'reportedip-hive' ), $roles );
			case 'privacy_logs':
				/* translators: %d: days */
				return sprintf( __( '%d days', 'reportedip-hive' ), (int) ( $current['reportedip_hive_data_retention_days'] ?? 0 ) );
			case 'notifications':
				return ! empty( $current['reportedip_hive_notify_admin'] ) ? $on : $off;
			case 'performance':
				return ! empty( $current['reportedip_hive_auto_footer_enabled'] ) ? __( 'badge on', 'reportedip-hive' ) : __( 'badge off', 'reportedip-hive' );
			case 'registration':
				return 'off' === (string) ( $current['reportedip_hive_disposable_email_action'] ?? 'off' ) ? $off : $on;
			case 'lockdown':
				return self::enum_label( (string) ( $current['reportedip_hive_rest_access_mode'] ?? 'open' ) );
			case 'account_password':
				return ! empty( $current['reportedip_hive_password_policy_enabled'] ) ? $on : $off;
			case 'hardening_mode':
				return ! empty( $current['reportedip_hive_hardening_realtime_detection'] ) ? $on : $off;
			case 'twofa_policies':
				$active = 0;
				foreach ( $current as $key => $value ) {
					if ( 0 === strpos( (string) $key, 'reportedip_hive_2fa_policy_' ) && is_array( $value ) && array() !== $value ) {
						++$active;
					}
				}
				/* translators: %d: number of triggers */
				return sprintf( __( '%d triggers', 'reportedip-hive' ), $active );
		}
		return '';
	}

	/**
	 * Preset id => label.
	 *
	 * @return array<string,string>
	 */
	private static function preset_labels() {
		return array(
			'low'      => __( 'Relaxed', 'reportedip-hive' ),
			'medium'   => __( 'Balanced', 'reportedip-hive' ),
			'high'     => __( 'Strict', 'reportedip-hive' ),
			'paranoid' => __( 'Paranoid', 'reportedip-hive' ),
			'custom'   => __( 'Custom', 'reportedip-hive' ),
		);
	}

	/**
	 * Enqueue the page script on the protection page only.
	 *
	 * @param string $hook Current admin page hook.
	 * @return void
	 */
	public function enqueue_assets( $hook ) {
		if ( false === strpos( (string) $hook, self::PAGE_SLUG ) ) {
			return;
		}
		wp_enqueue_script(
			'reportedip-hive-protection',
			REPORTEDIP_HIVE_PLUGIN_URL . 'assets/js/protection.js',
			array(),
			REPORTEDIP_HIVE_VERSION,
			true
		);
		wp_localize_script(
			'reportedip-hive-protection',
			'reportedipProtection',
			array(
				'expert'    => self::is_expert(),
				'noResults' => self::is_expert()
					? __( 'No setting matches.', 'reportedip-hive' )
					: __( 'No setting matches. Expert mode shows every field.', 'reportedip-hive' ),
			)
		);
	}

	/**
	 * The header toggle.
	 *
	 * @return void
	 */
	public static function render_expert_toggle() {
		if ( ! ReportedIP_Hive_Option_Routing::current_user_can_manage() ) {
			return;
		}
		$on = self::is_expert();
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="rip-expert-toggle">
			<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION_EXPERT ); ?>" />
			<input type="hidden" name="expert" value="<?php echo $on ? '0' : '1'; ?>" />
			<?php wp_nonce_field( self::ACTION_EXPERT ); ?>
			<label class="rip-toggle rip-toggle--inline">
				<input type="checkbox" class="rip-toggle__input" id="rip-expert-mode" <?php echo $on ? 'checked' : ''; ?> onchange="this.form.submit()" />
				<span class="rip-toggle__slider"></span>
				<span class="rip-toggle__label"><?php esc_html_e( 'Expert mode', 'reportedip-hive' ); ?></span>
			</label>
			<noscript><button type="submit" class="rip-button rip-button--ghost rip-button--sm"><?php esc_html_e( 'Apply', 'reportedip-hive' ); ?></button></noscript>
		</form>
		<?php
	}

	/**
	 * Render the page.
	 *
	 * @return void
	 */
	public function render_page() {
		$expert  = self::is_expert();
		$current = ReportedIP_Hive_Settings_Registry::current_values();
		$user_id = get_current_user_id();
		$result  = get_transient( self::RESULT_TRANSIENT . $user_id );
		$result  = is_array( $result ) ? $result : array();
		delete_transient( self::RESULT_TRANSIENT . $user_id );
		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		$spec         = ReportedIP_Hive_Settings_Registry::spec();
		$tools_url    = ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive-tools' );

		ReportedIP_Hive_Admin_Settings::render_page_header(
			__( 'Protection', 'reportedip-hive' ),
			$expert ? __( 'Every setting, grouped by area', 'reportedip-hive' ) : __( 'The settings that matter day to day; everything else runs on the recommendation', 'reportedip-hive' )
		);
		?>
		<div class="rip-content rip-protection" data-expert="<?php echo $expert ? '1' : '0'; ?>">
			<div class="rip-protection__search">
				<input type="search" id="rip-protection-search" class="rip-input" placeholder="<?php esc_attr_e( 'Search settings, e.g. Tor, HSTS, retention', 'reportedip-hive' ); ?>" autocomplete="off" />
				<p class="rip-help-text rip-protection__no-results rip-hidden" id="rip-protection-no-results"></p>
			</div>
			<?php if ( ! empty( $result['section'] ) && isset( $result['applied'] ) ) : ?>
				<div class="rip-alert <?php echo empty( $result['errors'] ) ? 'rip-alert--success' : 'rip-alert--warning'; ?>">
					<?php
					if ( empty( $result['errors'] ) ) {
						/* translators: %d: number of changed settings */
						echo esc_html( sprintf( _n( '%d setting saved.', '%d settings saved.', (int) $result['applied'], 'reportedip-hive' ), (int) $result['applied'] ) );
					} else {
						/* translators: %d: number of rejected settings */
						echo esc_html( sprintf( _n( '%d field was not saved, see the card.', '%d fields were not saved, see the card.', count( $result['errors'] ), 'reportedip-hive' ), count( $result['errors'] ) ) );
					}
					?>
				</div>
			<?php endif; ?>
			<?php foreach ( ReportedIP_Hive_Settings_Registry::sections() as $section => $meta ) : ?>
				<?php
				$keys        = self::visible_keys( $section, $expert );
				$expert_only = ! $expert && array() === $keys;
				$errors      = ( isset( $result['section'] ) && $result['section'] === $section && ! empty( $result['errors'] ) ) ? $result['errors'] : array();
				$open        = isset( $result['section'] ) && $result['section'] === $section;
				?>
				<details class="rip-card rip-protection__section" id="<?php echo esc_attr( $section ); ?>" data-section="<?php echo esc_attr( $section ); ?>" <?php echo $open ? 'open' : ''; ?>>
					<summary class="rip-protection__summary">
						<span class="rip-protection__title"><?php echo esc_html( (string) $meta['label'] ); ?></span>
						<span class="rip-protection__desc"><?php echo esc_html( (string) $meta['description'] ); ?></span>
						<span class="rip-badge rip-badge--neutral rip-protection__status"><?php echo esc_html( self::section_status( $section, $current ) ); ?></span>
					</summary>
					<div class="rip-card__body">
						<?php if ( $expert_only ) : ?>
							<p class="rip-help-text"><?php esc_html_e( 'Runs on the recommendation. Switch to expert mode to change the details.', 'reportedip-hive' ); ?></p>
						<?php else : ?>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="rip-protection__form">
								<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION_SAVE ); ?>" />
								<input type="hidden" name="rip_section" value="<?php echo esc_attr( $section ); ?>" />
								<?php wp_nonce_field( self::NONCE ); ?>
								<?php if ( 'detection' === $section ) : ?>
									<?php $this->render_preset_field( self::current_preset( $current ) ); ?>
								<?php endif; ?>
								<?php foreach ( $keys as $key ) : ?>
									<?php
									$entry  = $spec[ $key ];
									$status = ! empty( $entry['tier'] ) ? $mode_manager->feature_status( (string) $entry['tier'] ) : array( 'available' => true );
									echo self::field_markup( $key, $entry, $current[ $key ] ?? '', $status, self::choices_for( $entry ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside
									if ( isset( $errors[ $key ] ) ) {
										echo '<p class="rip-alert rip-alert--error rip-protection__error" data-for="' . esc_attr( $key ) . '">' . esc_html( (string) $errors[ $key ] ) . '</p>';
									}
									?>
								<?php endforeach; ?>
								<div class="rip-card__footer rip-protection__footer">
									<button type="submit" class="rip-button rip-button--primary"><?php esc_html_e( 'Save', 'reportedip-hive' ); ?></button>
									<?php $this->render_section_tools_link( $section, $tools_url ); ?>
								</div>
							</form>
						<?php endif; ?>
					</div>
				</details>
			<?php endforeach; ?>
		</div>
		<?php
		ReportedIP_Hive_Admin_Settings::render_page_footer();
	}

	/**
	 * The preset radio group at the top of the detection card.
	 *
	 * @param string $current Current preset id.
	 * @return void
	 */
	private function render_preset_field( $current ) {
		$levels = self::preset_labels();
		unset( $levels['custom'] );
		?>
		<div class="rip-protection__field rip-protection__field--preset" data-search="<?php echo esc_attr( strtolower( __( 'protection level preset relaxed balanced strict paranoid', 'reportedip-hive' ) ) ); ?>" data-key="<?php echo esc_attr( self::PRESET_FIELD ); ?>">
			<div class="rip-protection__field-head">
				<span class="rip-label"><?php esc_html_e( 'Protection level', 'reportedip-hive' ); ?></span>
				<?php if ( 'custom' === $current ) : ?>
					<span class="rip-badge rip-badge--info"><?php esc_html_e( 'Custom', 'reportedip-hive' ); ?></span>
				<?php endif; ?>
			</div>
			<div class="rip-protection__control rip-protection__presets">
				<?php foreach ( $levels as $level => $label ) : ?>
					<label class="rip-radio"><input type="radio" name="<?php echo esc_attr( self::PRESET_FIELD ); ?>" value="<?php echo esc_attr( $level ); ?>" <?php echo $level === $current ? 'checked' : ''; ?> /> <?php echo esc_html( $label ); ?></label>
				<?php endforeach; ?>
				<label class="rip-radio"><input type="radio" name="<?php echo esc_attr( self::PRESET_FIELD ); ?>" value="custom" <?php echo 'custom' === $current ? 'checked' : ''; ?> /> <?php esc_html_e( 'Custom', 'reportedip-hive' ); ?></label>
			</div>
			<p class="rip-help-text"><?php esc_html_e( 'Sets the failed-login threshold and window, the block duration and the community protection level in one go. Choose Custom to edit them one by one.', 'reportedip-hive' ); ?></p>
		</div>
		<?php
	}

	/**
	 * Link from a section card to the matching tools tab.
	 *
	 * @param string $section   Section id.
	 * @param string $tools_url Tools page URL.
	 * @return void
	 */
	private function render_section_tools_link( $section, $tools_url ) {
		$links = array(
			'waf'            => array( 'rules', __( 'Manage rules and exceptions', 'reportedip-hive' ) ),
			'headers'        => array( 'server', __( 'Server setup', 'reportedip-hive' ) ),
			'lockdown'       => array( 'server', __( 'Server setup', 'reportedip-hive' ) ),
			'privacy_logs'   => array( 'data', __( 'Export and reset', 'reportedip-hive' ) ),
			'notifications'  => array( 'diagnose', __( 'Send a test mail', 'reportedip-hive' ) ),
			'performance'    => array( 'diagnose', __( 'Cache and queue tools', 'reportedip-hive' ) ),
			'hardening_mode' => array( 'rules', __( 'Hardening status', 'reportedip-hive' ) ),
		);
		if ( ! isset( $links[ $section ] ) ) {
			return;
		}
		printf(
			'<a class="rip-button rip-button--ghost rip-button--sm" href="%1$s">%2$s</a>',
			esc_url( add_query_arg( 'tab', $links[ $section ][0], $tools_url ) ),
			esc_html( $links[ $section ][1] )
		);
	}

	/**
	 * admin-post handler: save one section through the apply service.
	 *
	 * Keys that are hidden in the current view are dropped, so a form from
	 * the simple view cannot reset expert fields to their empty defaults.
	 * The four preset keys are always accepted.
	 *
	 * @return void
	 */
	public function handle_save() {
		if ( ! ReportedIP_Hive_Option_Routing::current_user_can_manage() ) {
			wp_die( esc_html__( 'Permission denied.', 'reportedip-hive' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::NONCE );
		$post    = wp_unslash( $_POST ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- every value passes the registry sanitizer in Settings_Apply
		$section = isset( $post['rip_section'] ) ? sanitize_key( $post['rip_section'] ) : '';
		if ( ! isset( ReportedIP_Hive_Settings_Registry::sections()[ $section ] ) ) {
			wp_die( esc_html__( 'Unknown section.', 'reportedip-hive' ), '', array( 'response' => 400 ) );
		}
		$values  = self::collect_values( (array) $post, $section );
		$visible = self::visible_keys( $section, self::is_expert() );
		foreach ( array_keys( $values ) as $key ) {
			if ( ! in_array( $key, $visible, true ) && ! in_array( $key, self::PRESET_KEYS, true ) ) {
				unset( $values[ $key ] );
			}
		}
		$result = ReportedIP_Hive_Settings_Apply::apply( $values, 'admin' );
		$errors = array();
		foreach ( $result['results'] as $key => $row ) {
			if ( in_array( $row['status'], array( ReportedIP_Hive_Settings_Apply::STATUS_INVALID, ReportedIP_Hive_Settings_Apply::STATUS_SKIPPED_TIER ), true ) ) {
				$errors[ $key ] = (string) ( $row['message'] ?? __( 'Rejected.', 'reportedip-hive' ) );
			}
		}
		set_transient(
			self::RESULT_TRANSIENT . get_current_user_id(),
			array(
				'section' => $section,
				'applied' => (int) $result['applied'],
				'errors'  => $errors,
			),
			60
		);
		wp_safe_redirect( ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=' . self::PAGE_SLUG ) . '#' . $section );
		exit;
	}

	/**
	 * admin-post handler: flip the expert view for the current user.
	 *
	 * @return void
	 */
	public function handle_expert_toggle() {
		if ( ! ReportedIP_Hive_Option_Routing::current_user_can_manage() ) {
			wp_die( esc_html__( 'Permission denied.', 'reportedip-hive' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION_EXPERT );
		$on = ! empty( $_POST['expert'] );
		update_user_meta( get_current_user_id(), self::META_EXPERT, $on ? 1 : 0 );
		$redirect = wp_get_referer();
		if ( ! $redirect ) {
			$redirect = ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive' );
		}
		wp_safe_redirect( $redirect );
		exit;
	}
}
