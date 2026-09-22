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
	 * URL of the Protection page opened at one section card.
	 *
	 * @param string $section Section id, e.g. `privacy_logs`.
	 * @return string
	 * @since  2.1.62
	 */
	public static function section_url( $section ) {
		return ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=' . self::PAGE_SLUG ) . '#' . sanitize_key( (string) $section );
	}

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
	 * DOM id of the expert-mode explanation the info icon points at.
	 *
	 * @var string
	 * @since 2.1.59
	 */
	const INFO_ID = 'rip-expert-mode-help';

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
	 * Wire hooks.
	 */
	public function __construct() {
		add_action( 'admin_post_' . self::ACTION_SAVE, array( $this, 'handle_save' ) );
		add_action( 'admin_post_' . self::ACTION_EXPERT, array( $this, 'handle_expert_toggle' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
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
	 * Whether one field belongs in the current view.
	 *
	 * Three ways in. The expert view shows everything. `simple` marks a
	 * setting as day-to-day on every site. `simple_form` names the form
	 * plugin whose presence makes a setting day-to-day here: an operator
	 * running Formidable Forms should find the Formidable switch without
	 * learning about expert mode first, and an operator without it should
	 * never see the switch at all.
	 *
	 * A slug rather than a callback, because the registry is compared,
	 * exported and diffed in several places and a closure survives none of
	 * that. `export_schema()` copies named fields only, so the flag stays
	 * local either way.
	 *
	 * @param array<string,mixed> $entry    Registry entry.
	 * @param bool                $expert   Expert view.
	 * @param string[]            $detected Adapter slugs whose form plugin is active.
	 * @return bool
	 * @since  2.1.59
	 */
	public static function is_visible( array $entry, $expert, array $detected ) {
		if ( $expert || ! empty( $entry['simple'] ) ) {
			return true;
		}
		$slug = (string) ( $entry['simple_form'] ?? '' );

		return '' !== $slug && in_array( $slug, $detected, true );
	}

	/**
	 * Adapter slugs whose form plugin is active on this site.
	 *
	 * @return string[]
	 * @since  2.1.59
	 */
	public static function detected_forms() {
		if ( ! class_exists( 'ReportedIP_Hive_Form_Adapters' ) ) {
			return array();
		}
		$adapters = ReportedIP_Hive_Form_Adapters::get_instance();
		$slugs    = array();
		foreach ( array_keys( ReportedIP_Hive_Form_Adapters::ADAPTERS ) as $slug ) {
			if ( $adapters->detected( $slug ) ) {
				$slugs[] = (string) $slug;
			}
		}

		return $slugs;
	}

	/**
	 * Registry keys of one section in registry order, filtered to the
	 * simple set unless the expert view is on.
	 *
	 * @param string        $section  Section id.
	 * @param bool          $expert   Expert view.
	 * @param string[]|null $detected Active form plugins; resolved from the site when null.
	 * @return string[]
	 */
	public static function visible_keys( $section, $expert, $detected = null ) {
		return self::section_keys( $section, $expert, $detected, true );
	}

	/**
	 * Registry keys of one section the simple view does not render.
	 *
	 * Empty in the expert view, where nothing is held back.
	 *
	 * @param string        $section  Section id.
	 * @param bool          $expert   Expert view.
	 * @param string[]|null $detected Active form plugins; resolved from the site when null.
	 * @return string[]
	 * @since  2.1.59
	 */
	public static function expert_only_keys( $section, $expert, $detected = null ) {
		return $expert ? array() : self::section_keys( $section, false, $detected, false );
	}

	/**
	 * Keys of one section on one side of the visibility line.
	 *
	 * @param string        $section  Section id.
	 * @param bool          $expert   Expert view.
	 * @param string[]|null $detected Active form plugins; resolved from the site when null.
	 * @param bool          $visible  Which side to return.
	 * @return string[]
	 * @since  2.1.59
	 */
	private static function section_keys( $section, $expert, $detected, $visible ) {
		$detected = null === $detected ? self::detected_forms() : array_map( 'strval', (array) $detected );
		$keys     = array();
		foreach ( ReportedIP_Hive_Settings_Registry::spec() as $key => $entry ) {
			if ( ( $entry['section'] ?? '' ) !== $section ) {
				continue;
			}
			if ( self::is_visible( $entry, (bool) $expert, $detected ) === (bool) $visible ) {
				$keys[] = $key;
			}
		}

		return $keys;
	}

	/**
	 * Whether a section has no simple key at all.
	 *
	 * @param string        $section  Section id.
	 * @param string[]|null $detected Active form plugins; resolved from the site when null.
	 * @return bool
	 */
	public static function section_is_expert_only( $section, $detected = null ) {
		if ( 'detection' === $section ) {
			return false;
		}
		return array() === self::visible_keys( $section, false, $detected );
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
			$values[ $key ] = array(
				'bool'      => '0',
				'json_list' => array(),
			)[ $entry['kind'] ] ?? '';
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
	 * @param array<string,mixed>  $choices Choice map for `json_list`: value => label, or value => array{label,disabled,fixed}.
	 * @return string
	 */
	public static function field_markup( $key, array $entry, $value, array $status, array $choices = array() ) {
		$gated    = empty( $status['available'] );
		$locked   = $gated && empty( $status['partial'] );
		$id       = self::field_id( $key );
		$label    = (string) ( $entry['label'] ?? $key );
		$desc     = (string) ( $entry['description'] ?? '' );
		$search   = self::search_terms( $key, $entry );
		$disabled = $locked ? ' disabled' : '';
		$classes  = 'rip-protection__field' . ( $locked ? ' rip-protection__field--locked' : '' );
		$kind     = (string) $entry['kind'];

		switch ( $kind ) {
			case 'bool':
				$control = sprintf(
					'<label class="rip-toggle"><input type="checkbox" class="rip-toggle__input" id="%1$s" name="%2$s" value="1"%3$s%4$s /><span class="rip-toggle__slider"></span></label>',
					esc_attr( $id ),
					esc_attr( $key ),
					( ! empty( $value ) || ! empty( $status['forced'] ) ) ? ' checked' : '',
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
				$current = array_map( 'strval', ReportedIP_Hive_Option_Routing::to_array( $value ) );
				$boxes   = '';
				foreach ( $choices as $choice => $choice_def ) {
					$choice_def = is_array( $choice_def ) ? $choice_def : array( 'label' => (string) $choice_def );
					$fixed      = ! empty( $choice_def['fixed'] );
					$boxes     .= sprintf(
						'<label class="rip-checkbox"><input type="checkbox" name="%1$s[]" value="%2$s" %3$s%4$s /> %5$s</label>%6$s',
						esc_attr( $key ),
						esc_attr( (string) $choice ),
						$fixed || in_array( (string) $choice, $current, true ) ? 'checked' : '',
						( $locked || ! empty( $choice_def['disabled'] ) ) ? ' disabled' : '',
						esc_html( (string) ( $choice_def['label'] ?? $choice ) ),
						$fixed ? sprintf( '<input type="hidden" name="%1$s[]" value="%2$s" />', esc_attr( $key ), esc_attr( (string) $choice ) ) : ''
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

		$marker = '';
		$state  = self::tier_marker_state( $entry, $status );
		if ( '' !== $state ) {
			ob_start();
			if ( 'locked' === $state ) {
				ReportedIP_Hive_Admin_Settings::render_tier_marker( $status );
			} else {
				ReportedIP_Hive_Admin_Settings::render_tier_included( $status );
			}
			$marker = (string) ob_get_clean();
		}
		$note = trim( (string) ( $status['note'] ?? '' ) );
		if ( '' !== $note ) {
			$desc = trim( $desc . ' ' . $note );
		}

		return sprintf(
			'<div class="%1$s" data-search="%2$s" data-key="%3$s"><div class="rip-protection__field-head"><label class="rip-label" for="%4$s">%5$s</label>%6$s</div><div class="rip-protection__control">%7$s</div>%8$s</div>',
			esc_attr( $classes ),
			esc_attr( $search ),
			esc_attr( $key ),
			esc_attr( $id ),
			esc_html( $label ),
			$marker,
			$control,
			'' !== $desc ? '<p class="rip-help-text">' . esc_html( $desc ) . '</p>' : ''
		);
	}

	/**
	 * DOM id of one field, and the anchor the expert-mode link jumps to.
	 *
	 * @param string $key Registry key.
	 * @return string
	 * @since  2.1.59
	 */
	public static function field_id( $key ) {
		return 'rip-field-' . str_replace( 'reportedip_hive_', '', (string) $key );
	}

	/**
	 * The lowercase haystack the page search matches against.
	 *
	 * Shared by the rendered field and by the stand-in the simple view draws
	 * for an expert setting, so a search behaves the same in both views.
	 *
	 * @param string              $key   Registry key.
	 * @param array<string,mixed> $entry Registry entry.
	 * @return string
	 * @since  2.1.59
	 */
	public static function search_terms( $key, array $entry ) {
		return strtolower(
			(string) ( $entry['label'] ?? $key ) . ' '
			. (string) ( $entry['description'] ?? '' ) . ' '
			. str_replace( array( 'reportedip_hive_', '_' ), array( '', ' ' ), (string) $key )
		);
	}

	/**
	 * A searchable stand-in for a setting the simple view does not render.
	 *
	 * Deliberately without a control. An expert field drawn into the simple
	 * form and hidden with CSS would travel back with the next save of that
	 * section: {@see collect_values()} fills every missing switch with `0`,
	 * and {@see writable_values()} keeps whatever the view declares visible.
	 * The stored setting would be overwritten with an empty value and nobody
	 * would see it happen. So this entry carries the label, the same search
	 * terms a real field carries and a link into the expert view, and nothing
	 * a browser could ever submit.
	 *
	 * @param string              $key      Registry key.
	 * @param array<string,mixed> $entry    Registry entry.
	 * @param string              $jump_url Link that turns the expert view on and lands on this setting.
	 * @return string
	 * @since  2.1.59
	 */
	public static function hint_markup( $key, array $entry, $jump_url, array $detected = array() ) {
		$missing = self::missing_form_plugin( $entry, $detected );
		$tail    = sprintf(
			'<a class="rip-button rip-button--ghost rip-button--sm" href="%1$s">%2$s</a>',
			esc_url( (string) $jump_url ),
			esc_html__( 'Open in expert mode', 'reportedip-hive' )
		);

		if ( '' !== $missing ) {
			$tail = sprintf(
				'<span class="rip-badge rip-badge--neutral">%s</span>',
				esc_html__( 'Not installed', 'reportedip-hive' )
			);
		}

		return sprintf(
			'<div class="rip-protection__hint rip-hidden" data-search="%1$s" data-key="%2$s"><div class="rip-protection__field-head"><span class="rip-label">%3$s</span></div><p class="rip-help-text">%4$s</p>%5$s</div>',
			esc_attr( self::search_terms( $key, $entry ) ),
			esc_attr( (string) $key ),
			esc_html( (string) ( $entry['label'] ?? $key ) ),
			esc_html( self::hint_reason( $missing ) ),
			$tail
		);
	}

	/**
	 * The form plugin a setting waits for, when that plugin is not here.
	 *
	 * Pure. An empty string means the setting is held back for the ordinary
	 * reason, which is that the simple view stays short.
	 *
	 * @param array<string,mixed> $entry    Registry entry.
	 * @param string[]            $detected Adapter slugs found on this site.
	 * @return string Adapter slug, or an empty string.
	 * @since  2.1.61
	 */
	public static function missing_form_plugin( array $entry, array $detected ) {
		$slug = (string) ( $entry['simple_form'] ?? '' );

		if ( '' === $slug || in_array( $slug, $detected, true ) ) {
			return '';
		}

		return $slug;
	}

	/**
	 * Why a setting is not in the simple view.
	 *
	 * Naming expert mode for a setting that waits for a plugin sends the
	 * operator to a switch that cannot help them: they turn expert mode on,
	 * find the setting, and it still does nothing because the form plugin is
	 * not installed. Say which plugin is missing instead.
	 *
	 * @param string $missing Adapter slug from {@see missing_form_plugin()}.
	 * @return string
	 * @since  2.1.61
	 */
	public static function hint_reason( $missing ) {
		$missing = (string) $missing;

		if ( '' === $missing ) {
			return __( 'This setting lives in expert mode.', 'reportedip-hive' );
		}

		$names = ReportedIP_Hive_Form_Adapters::names();

		return sprintf(
			/* translators: %s: name of a form plugin, for example Contact Form 7. */
			__( '%s is not active on this site. The setting appears here as soon as it is.', 'reportedip-hive' ),
			(string) ( $names[ $missing ] ?? $missing )
		);
	}

	/**
	 * The closing line of a section in the simple view: what the expert view
	 * holds here.
	 *
	 * Names the first few settings and counts the rest, because a section can
	 * hold thirty and a full list would read as a wall rather than as an
	 * offer.
	 *
	 * @param string[] $labels Labels of the settings the simple view holds back.
	 * @return string
	 * @since  2.1.59
	 */
	public static function expert_summary( array $labels ) {
		$labels = array_values( array_filter( array_map( 'strval', $labels ) ) );
		if ( array() === $labels ) {
			return '';
		}
		$shown = array_slice( $labels, 0, 3 );
		$rest  = count( $labels ) - count( $shown );
		if ( $rest > 0 ) {
			return sprintf(
				/* translators: 1: comma-separated setting names, 2: number of further settings */
				_n( 'Expert mode adds %1$s and %2$d more setting here.', 'Expert mode adds %1$s and %2$d more settings here.', $rest, 'reportedip-hive' ),
				implode( ', ', $shown ),
				$rest
			);
		}

		/* translators: %s: comma-separated setting names */
		return sprintf( __( 'Expert mode adds %s here.', 'reportedip-hive' ), implode( ', ', $shown ) );
	}

	/**
	 * Link that turns the expert view on and lands on one anchor.
	 *
	 * @param string $anchor Field id or section id.
	 * @return string
	 * @since  2.1.59
	 */
	private static function expert_jump_url( $anchor ) {
		return wp_nonce_url(
			add_query_arg(
				array(
					'action'     => self::ACTION_EXPERT,
					'expert'     => '1',
					'rip_anchor' => (string) $anchor,
				),
				admin_url( 'admin-post.php' )
			),
			self::ACTION_EXPERT
		);
	}

	/**
	 * Lock status of one field for the current value.
	 *
	 * Three outcomes: available, partial (editable, plan marker shown, the
	 * registry sanitizer refuses a value that crosses the plan line) and
	 * locked (disabled, value dropped on save). A plan gate makes a field
	 * partial only when the registry flags it `partial` and the stored value
	 * is still inside the free range, or when a switch is currently on, so a
	 * feature a plan no longer includes can still be switched off. A `ui_lock`
	 * entry locks the field the same way without gating the sanitizer: the
	 * value is inert while the feature is unavailable, so remote channels
	 * may still write it and fleet hashes stay in sync. Runtime
	 * locks (no crypto, no WooCommerce, the Hide Login constant, wp-admin
	 * forced closed while Hide Login is on) carry a note instead of a plan.
	 *
	 * @param array<string,mixed>          $entry        Registry entry.
	 * @param string                       $key          Registry key.
	 * @param mixed                        $value        Current value.
	 * @param ReportedIP_Hive_Mode_Manager $mode_manager Mode manager.
	 * @return array<string,mixed>
	 */
	public static function field_status( array $entry, $key, $value, $mode_manager ) {
		$feature = (string) ( $entry['tier'] ?? ( $entry['ui_lock'] ?? '' ) );
		$status  = '' === $feature ? array( 'available' => true ) : $mode_manager->feature_status( $feature );
		$runtime = self::runtime_lock( (string) $key, ! empty( $status['available'] ) );
		if ( null !== $runtime ) {
			return $runtime;
		}
		if ( ! empty( $status['available'] ) ) {
			return $status;
		}
		if ( 'bool' === (string) ( $entry['kind'] ?? '' ) && ! empty( $value ) ) {
			$status['partial'] = true;
			return $status;
		}
		if ( ! empty( $entry['partial'] ) && ! empty( $entry['tier_gate'] ) && is_callable( $entry['tier_gate'] ) && ! call_user_func( $entry['tier_gate'], $value ) ) {
			$status['partial'] = true;
		}
		return $status;
	}

	/**
	 * Which plan marker a field carries.
	 *
	 * Every field with a plan entry says which plan it belongs to, in both
	 * directions: `locked` names the plan that is still missing, `included`
	 * names the plan the customer already pays for, so a Business operator
	 * can see what the Business features are instead of a page that looks
	 * the same as the free one. A field without a plan entry, and a field
	 * held back by the server rather than by a plan, carries neither. Neither
	 * does a status without a plan name, because both markers say which plan
	 * the field belongs to and there is nothing to name.
	 *
	 * @param array<string,mixed> $entry  Registry entry.
	 * @param array<string,mixed> $status Status from {@see field_status()}.
	 * @return string `locked`, `included` or an empty string.
	 * @since  2.1.59
	 */
	public static function tier_marker_state( array $entry, array $status ) {
		if ( empty( $entry['tier'] ) && empty( $entry['ui_lock'] ) ) {
			return '';
		}
		if ( empty( $status['min_tier'] ) || 'runtime' === (string) ( $status['reason'] ?? '' ) ) {
			return '';
		}

		return empty( $status['available'] ) ? 'locked' : 'included';
	}

	/**
	 * Locks that do not come from the plan.
	 *
	 * @param string $key     Registry key.
	 * @param bool   $covered Whether the plan covers the field's feature.
	 * @return array<string,mixed>|null Status array, or null when no runtime lock applies.
	 */
	private static function runtime_lock( $key, $covered = true ) {
		$adapter = self::adapter_behind( $key );

		if ( array() !== $adapter ) {
			return self::adapter_lock(
				$covered,
				$adapter['detect'],
				sprintf(
					/* translators: %s: name of a form plugin, for example Gravity Forms. */
					__( '%s is not active on this site.', 'reportedip-hive' ),
					$adapter['name']
				)
			);
		}

		switch ( $key ) {
			case 'reportedip_hive_2fa_enabled_global':
				if ( ! ReportedIP_Hive_Two_Factor_Crypto::is_available() ) {
					return self::runtime_status( __( 'Two-factor authentication needs libsodium or OpenSSL to store secrets encrypted; neither is available on this server.', 'reportedip-hive' ) );
				}
				return null;
			case 'reportedip_hive_monitor_woocommerce':
				if ( ! class_exists( 'WooCommerce' ) ) {
					return self::runtime_status( __( 'WooCommerce is not installed on this site.', 'reportedip-hive' ) );
				}
				return null;
			case 'reportedip_hive_hide_login_enabled':
				if ( defined( 'REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN' ) && REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN ) {
					return self::runtime_status( __( 'The constant REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN is defined as true in wp-config.php; Hide Login stays off until you remove it. This is the recovery path when the slug was lost.', 'reportedip-hive' ) );
				}
				return null;
			case 'reportedip_hive_block_admin_guests':
				if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_enabled', false ) ) {
					$status           = self::runtime_status( __( 'Always on while Hide Login is active; a visible wp-admin would redirect straight to the login URL you just hid.', 'reportedip-hive' ) );
					$status['forced'] = true;
					return $status;
				}
				return null;
		}
		return null;
	}

	/**
	 * The form adapter a registry key switches, if it switches one.
	 *
	 * Read out of the adapter table rather than listed here, so a new form
	 * plugin never arrives with a switch that cannot say why it is locked.
	 *
	 * @param string $key Registry key.
	 * @return array<string, string> Detection class and plugin name, empty when the key is not an adapter switch.
	 * @since  2.1.63
	 */
	private static function adapter_behind( $key ) {
		if ( ! class_exists( 'ReportedIP_Hive_Form_Adapters' ) ) {
			return array();
		}

		$names = ReportedIP_Hive_Form_Adapters::names();

		foreach ( ReportedIP_Hive_Form_Adapters::ADAPTERS as $slug => $adapter ) {
			if ( $adapter['option'] === (string) $key ) {
				return array(
					'detect' => $adapter['detect'],
					'name'   => isset( $names[ $slug ] ) ? $names[ $slug ] : $slug,
				);
			}
		}

		return array();
	}

	/**
	 * Lock a form-adapter switch whose plugin is not installed.
	 *
	 * Only while the plan covers the adapter. Without the plan the plan marker
	 * is the honest answer, and replacing it with a note about a missing plugin
	 * would hide what actually stands between the operator and the switch.
	 *
	 * @param bool   $covered   Whether the plan covers the feature.
	 * @param string $signature Class the target plugin defines.
	 * @param string $note      Reason shown under the field.
	 * @return array<string,mixed>|null
	 */
	private static function adapter_lock( $covered, $signature, $note ) {
		if ( ! $covered || class_exists( $signature ) ) {
			return null;
		}

		return self::runtime_status( $note );
	}

	/**
	 * Status array of a runtime lock.
	 *
	 * @param string $note Reason shown under the field.
	 * @return array<string,mixed>
	 */
	private static function runtime_status( $note ) {
		return array(
			'available' => false,
			'reason'    => 'runtime',
			'note'      => $note,
		);
	}

	/**
	 * The values of one section that the save may write.
	 *
	 * Hidden keys (the expert-only fields of the simple view) and locked keys
	 * are dropped so a posted form cannot reset them to their empty defaults:
	 * a disabled input is not part of the POST and `collect_values()` would
	 * otherwise fill in `0` or an empty string. Forced switches are written as
	 * on. The four preset keys are always accepted.
	 *
	 * @param array<string,mixed>              $values   Collected values.
	 * @param string[]                         $visible  Keys visible in the current view.
	 * @param array<string,array<string,mixed>> $statuses Key => field status.
	 * @return array<string,mixed>
	 */
	public static function writable_values( array $values, array $visible, array $statuses ) {
		$out = array();
		foreach ( $values as $key => $value ) {
			if ( ! in_array( $key, $visible, true ) && ! in_array( $key, self::PRESET_KEYS, true ) ) {
				continue;
			}
			$status = $statuses[ $key ] ?? array( 'available' => true );
			if ( ! empty( $status['forced'] ) ) {
				$out[ $key ] = '1';
				continue;
			}
			if ( empty( $status['available'] ) && empty( $status['partial'] ) ) {
				continue;
			}
			$out[ $key ] = $value;
		}
		return $out;
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
	 * Each entry is `array{label:string,disabled:bool,fixed:bool}`. A fixed
	 * choice is always checked, disabled and carried in the POST by a hidden
	 * input. The SMS method is disabled while the managed relay is not part
	 * of the plan, and the administrator role stays disabled in the adaptive
	 * policies until an administrator has passed one challenge.
	 *
	 * @param array<string,mixed> $entry Registry entry.
	 * @param string              $key   Registry key.
	 * @return array<string,array{label:string,disabled:bool,fixed:bool}>
	 */
	public static function choices_for( array $entry, $key = '' ) {
		$source = (string) ( $entry['choices'] ?? '' );
		$map    = array();
		if ( 'methods' === $source ) {
			$map = array(
				'totp'     => __( 'Authenticator app (TOTP)', 'reportedip-hive' ),
				'email'    => __( 'E-mail code', 'reportedip-hive' ),
				'sms'      => __( 'SMS code', 'reportedip-hive' ),
				'webauthn' => __( 'Security key / passkey', 'reportedip-hive' ),
			);
		} elseif ( 'roles' === $source ) {
			$map = array_map( 'strval', wp_roles()->get_names() );
		} elseif ( 'audit_groups' === $source ) {
			foreach ( ReportedIP_Hive_Audit_Registry::groups() as $slug => $group ) {
				if ( $group['multisite_only'] && ! is_multisite() ) {
					continue;
				}
				$map[ $slug ] = $group['label'];
			}
		}
		$fixed   = array_map( 'strval', (array) ( $entry['choices_fixed'] ?? array() ) );
		$choices = array();
		foreach ( $map as $value => $label ) {
			$choices[ (string) $value ] = array(
				'label'    => (string) $label,
				'disabled' => in_array( (string) $value, $fixed, true ),
				'fixed'    => in_array( (string) $value, $fixed, true ),
			);
		}
		if ( 'methods' === $source && isset( $choices['sms'] ) ) {
			$relay = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'sms_relay_via_api' );
			if ( empty( $relay['available'] ) ) {
				$choices['sms']['disabled'] = true;
				/* translators: %s: plan name */
				$choices['sms']['label'] .= ' ' . sprintf( __( '(%s plan)', 'reportedip-hive' ), ucfirst( (string) ( $relay['min_tier'] ?? 'professional' ) ) );
			}
		}
		if ( 0 === strpos( (string) $key, 'reportedip_hive_2fa_policy_' ) && isset( $choices['administrator'] ) && ! ReportedIP_Hive_Login_Context::admin_latch_open() ) {
			$choices['administrator']['disabled'] = true;
		}
		return $choices;
	}

	/**
	 * Note shown under a checkbox group.
	 *
	 * @param string $key Registry key.
	 * @return string
	 */
	public static function choices_note( $key ) {
		if ( 0 !== strpos( (string) $key, 'reportedip_hive_2fa_policy_' ) ) {
			return '';
		}
		$notes = array();
		if ( ! ReportedIP_Hive_Login_Context::admin_latch_open() ) {
			$notes[] = __( 'Triggers for administrators become available once an administrator has completed one second-factor sign-in on this site.', 'reportedip-hive' );
		}
		if ( 'reportedip_hive_2fa_policy_new_country' === $key && empty( ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'api_reputation_check' )['available'] ) ) {
			$notes[] = __( 'Country data comes from the Community Network. In Local Shield the country trigger never fires.', 'reportedip-hive' );
		}
		return implode( ' ', $notes );
	}

	/**
	 * Short status shown in the card head.
	 *
	 * @param string              $section Section id.
	 * @param array<string,mixed> $current Current values.
	 * @return string
	 */
	public static function section_status( $section, array $current ) {
		return (string) self::section_state( $section, $current )['text'];
	}

	/**
	 * Short status of one section plus the tint it is shown in.
	 *
	 * The tint is decided here rather than read back out of the finished
	 * text. A section that is on is green, a section that is off is red,
	 * and a status that says something else ("Balanced, 10 sensors", the
	 * Hide Login slug, the REST access mode) stays neutral. Guessing the
	 * tint from the text would break on the first translation, and a
	 * status such as "off" inside a longer sentence would be read wrong.
	 *
	 * @param string              $section Section id.
	 * @param array<string,mixed> $current Current values.
	 * @return array{text:string,tone:string} `tone` is `success`, `danger` or `neutral`.
	 * @since  2.1.59
	 */
	public static function section_state( $section, array $current ) {
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
				return self::neutral_state( sprintf( __( '%1$s · %2$d sensors', 'reportedip-hive' ), $preset_labels[ self::current_preset( $current ) ], $sensors ) );
			case 'blocking':
				if ( ! empty( $current['reportedip_hive_report_only_mode'] ) ) {
					return self::neutral_state( __( 'report only', 'reportedip-hive' ) );
				}
				return self::switch_state( ! empty( $current['reportedip_hive_auto_block'] ) );
			case 'waf':
				return self::switch_state( ! empty( $current['reportedip_hive_waf_enabled'] ) );
			case 'hide_login':
				if ( empty( $current['reportedip_hive_hide_login_enabled'] ) ) {
					return self::switch_state( false );
				}
				return self::neutral_state( '/' . (string) ( $current['reportedip_hive_hide_login_slug'] ?? '' ) );
			case 'headers':
				return self::switch_state( ! empty( $current['reportedip_hive_headers_enabled'] ) );
			case 'account_security':
				if ( empty( $current['reportedip_hive_2fa_enabled_global'] ) ) {
					return self::switch_state( false );
				}
				$roles = count( ReportedIP_Hive_Option_Routing::to_array( $current['reportedip_hive_2fa_enforce_roles'] ?? array() ) );
				/* translators: %d: number of roles */
				return self::neutral_state( sprintf( _n( '%d role enforced', '%d roles enforced', $roles, 'reportedip-hive' ), $roles ) );
			case 'privacy_logs':
				/* translators: %d: days */
				return self::neutral_state( sprintf( __( '%d days', 'reportedip-hive' ), (int) ( $current['reportedip_hive_data_retention_days'] ?? 0 ) ) );
			case 'notifications':
				return self::switch_state( ! empty( $current['reportedip_hive_notify_admin'] ) );
			case 'performance':
				$badge = ! empty( $current['reportedip_hive_auto_footer_enabled'] );
				return array(
					'text' => $badge ? __( 'badge on', 'reportedip-hive' ) : __( 'badge off', 'reportedip-hive' ),
					'tone' => $badge ? 'success' : 'danger',
				);
			case 'registration':
				return self::switch_state( 'off' !== (string) ( $current['reportedip_hive_disposable_email_action'] ?? 'off' ) );
			case 'forms':
				return self::switch_state( ! empty( $current['reportedip_hive_form_proof_enabled'] ) );
			case 'lockdown':
				return self::neutral_state( self::enum_label( (string) ( $current['reportedip_hive_rest_access_mode'] ?? 'open' ) ) );
			case 'account_password':
				return self::switch_state( ! empty( $current['reportedip_hive_password_policy_enabled'] ) );
			case 'hardening_mode':
				return self::switch_state( ! empty( $current['reportedip_hive_hardening_realtime_detection'] ) );
			case 'twofa_policies':
				$active = 0;
				foreach ( $current as $key => $value ) {
					if ( 0 === strpos( (string) $key, 'reportedip_hive_2fa_policy_' ) && is_array( $value ) && array() !== $value ) {
						++$active;
					}
				}
				/* translators: %d: number of triggers */
				return self::neutral_state( sprintf( __( '%d triggers', 'reportedip-hive' ), $active ) );
		}
		return self::neutral_state( '' );
	}

	/**
	 * State of a section whose status is a plain on or off.
	 *
	 * @param bool $on Whether the section is switched on.
	 * @return array{text:string,tone:string}
	 * @since  2.1.59
	 */
	private static function switch_state( $on ) {
		return $on
			? array(
				'text' => __( 'on', 'reportedip-hive' ),
				'tone' => 'success',
			)
			: array(
				'text' => __( 'off', 'reportedip-hive' ),
				'tone' => 'danger',
			);
	}

	/**
	 * State of a section whose status says neither on nor off.
	 *
	 * @param string $text Status text.
	 * @return array{text:string,tone:string}
	 * @since  2.1.59
	 */
	private static function neutral_state( $text ) {
		return array(
			'text' => (string) $text,
			'tone' => 'neutral',
		);
	}

	/**
	 * Markup of one section head: title, description, tinted status, chevron.
	 *
	 * The chevron replaces the native `<details>` marker, which the
	 * stylesheet hides, and turns by 180 degrees while the card is open.
	 *
	 * @param array<string,mixed>         $meta  Section meta from the registry.
	 * @param array{text:string,tone:string} $state Section state.
	 * @return string
	 * @since  2.1.59
	 */
	public static function summary_markup( array $meta, array $state ) {
		return sprintf(
			'<summary class="rip-protection__summary"><span class="rip-protection__title">%1$s</span><span class="rip-protection__desc">%2$s</span><span class="rip-badge rip-badge--%3$s rip-protection__status">%4$s</span><svg class="rip-protection__chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><polyline points="6 9 12 15 18 9"/></svg></summary>',
			esc_html( (string) ( $meta['label'] ?? '' ) ),
			esc_html( (string) ( $meta['description'] ?? '' ) ),
			esc_attr( (string) ( $state['tone'] ?? 'neutral' ) ),
			esc_html( (string) ( $state['text'] ?? '' ) )
		);
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
			<span class="rip-expert-toggle__info" tabindex="0" aria-describedby="<?php echo esc_attr( self::INFO_ID ); ?>">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
				<span class="rip-tooltip" id="<?php echo esc_attr( self::INFO_ID ); ?>" role="tooltip"><?php esc_html_e( 'Expert mode shows every setting on the Protection page and lists the Tools page. Simple mode shows the sixteen day-to-day settings; everything else runs on the recommendation. The switch is stored for your user only.', 'reportedip-hive' ); ?></span>
			</span>
			<noscript><button type="submit" class="rip-button rip-button--ghost rip-button--sm"><?php esc_html_e( 'Apply', 'reportedip-hive' ); ?></button></noscript>
		</form>
		<?php
	}

	/**
	 * Render the page.
	 *
	 * @return void
	 */
	public static function render_page() {
		$expert  = self::is_expert();
		$current = ReportedIP_Hive_Settings_Registry::current_values();
		$user_id = get_current_user_id();
		$result  = get_transient( self::RESULT_TRANSIENT . $user_id );
		$result  = is_array( $result ) ? $result : array();
		delete_transient( self::RESULT_TRANSIENT . $user_id );
		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		$spec         = ReportedIP_Hive_Settings_Registry::spec();
		$detected     = self::detected_forms();
		$tools_url    = ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive-tools' );

		ReportedIP_Hive_Admin_Settings::render_page_header(
			__( 'Protection', 'reportedip-hive' ),
			$expert ? __( 'Every setting, grouped by area', 'reportedip-hive' ) : __( 'The settings that matter day to day; everything else runs on the recommendation', 'reportedip-hive' )
		);
		?>
		<div class="rip-content rip-protection">
			<div class="rip-protection__search">
				<input type="search" id="rip-protection-search" class="rip-input" placeholder="<?php esc_attr_e( 'Search settings, e.g. Tor, HSTS, retention', 'reportedip-hive' ); ?>" autocomplete="off" />
				<p class="rip-help-text rip-protection__no-results rip-hidden" id="rip-protection-no-results"><?php esc_html_e( 'No setting matches.', 'reportedip-hive' ); ?></p>
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
				$keys        = self::visible_keys( $section, $expert, $detected );
				$held_back   = self::expert_only_keys( $section, $expert, $detected );
				$expert_only = ! $expert && self::section_is_expert_only( $section, $detected );
				$errors      = ( isset( $result['section'] ) && $result['section'] === $section && ! empty( $result['errors'] ) ) ? $result['errors'] : array();
				$open        = isset( $result['section'] ) && $result['section'] === $section;
				?>
				<details class="rip-card rip-protection__section" id="<?php echo esc_attr( $section ); ?>" <?php echo $open ? 'open' : ''; ?>>
					<?php echo self::summary_markup( $meta, self::section_state( $section, $current ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside ?>
					<div class="rip-card__body">
						<?php if ( $expert_only ) : ?>
							<p class="rip-help-text"><?php esc_html_e( 'Runs on the recommendation. Switch to expert mode to change the details.', 'reportedip-hive' ); ?></p>
						<?php else : ?>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="rip-protection__form">
								<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION_SAVE ); ?>" />
								<input type="hidden" name="rip_section" value="<?php echo esc_attr( $section ); ?>" />
								<?php wp_nonce_field( self::NONCE ); ?>
								<?php if ( 'detection' === $section ) : ?>
									<?php self::render_preset_field( self::current_preset( $current ) ); ?>
								<?php endif; ?>
								<?php foreach ( $keys as $key ) : ?>
									<?php
									$entry      = $spec[ $key ];
									$status     = self::field_status( $entry, $key, $current[ $key ] ?? '', $mode_manager );
									$group_note = 'json_list' === $entry['kind'] ? self::choices_note( $key ) : '';
									if ( '' !== $group_note ) {
										$status['note'] = trim( (string) ( $status['note'] ?? '' ) . ' ' . $group_note );
									}
									echo self::field_markup( $key, $entry, $current[ $key ] ?? '', $status, self::choices_for( $entry, $key ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside
									if ( isset( $errors[ $key ] ) ) {
										echo '<p class="rip-alert rip-alert--error rip-protection__error" data-for="' . esc_attr( $key ) . '">' . esc_html( (string) $errors[ $key ] ) . '</p>';
									}
									?>
								<?php endforeach; ?>
								<div class="rip-card__footer rip-protection__footer">
									<button type="submit" class="rip-button rip-button--primary"><?php esc_html_e( 'Save', 'reportedip-hive' ); ?></button>
									<?php self::render_section_tools_link( $section, $tools_url ); ?>
								</div>
							</form>
						<?php endif; ?>
						<?php self::render_expert_hints( $section, $held_back, $spec ); ?>
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
	private static function render_preset_field( $current ) {
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
	 * The stand-ins and the closing line of a section in the simple view.
	 *
	 * @param string                            $section Section id.
	 * @param string[]                          $keys    Keys the simple view holds back.
	 * @param array<string,array<string,mixed>> $spec    Registry spec.
	 * @return void
	 * @since  2.1.59
	 */
	private static function render_expert_hints( $section, array $keys, array $spec ) {
		if ( array() === $keys ) {
			return;
		}
		$detected = self::detected_forms();
		$labels   = array();
		foreach ( $keys as $key ) {
			$entry = $spec[ $key ];
			if ( '' === self::missing_form_plugin( $entry, $detected ) ) {
				$labels[] = (string) ( $entry['label'] ?? $key );
			}
			echo self::hint_markup( $key, $entry, self::expert_jump_url( self::field_id( $key ) ), $detected ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside
		}
		if ( array() === $labels ) {
			return;
		}
		printf(
			'<p class="rip-help-text rip-protection__more">%1$s <a class="rip-button rip-button--ghost rip-button--sm" href="%2$s">%3$s</a></p>',
			esc_html( self::expert_summary( $labels ) ),
			esc_url( self::expert_jump_url( $section ) ),
			esc_html__( 'Show these', 'reportedip-hive' )
		);
	}

	/**
	 * Link from a section card to the matching tools tab.
	 *
	 * @param string $section   Section id.
	 * @param string $tools_url Tools page URL.
	 * @return void
	 */
	private static function render_section_tools_link( $section, $tools_url ) {
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
	 * See {@see writable_values()} for which posted keys are written.
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
		$values       = self::collect_values( (array) $post, $section );
		$visible      = self::visible_keys( $section, self::is_expert() );
		$spec         = ReportedIP_Hive_Settings_Registry::spec();
		$current      = ReportedIP_Hive_Settings_Registry::current_values();
		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		$statuses     = array();
		foreach ( array_keys( $values ) as $key ) {
			if ( isset( $spec[ $key ] ) ) {
				$statuses[ $key ] = self::field_status( $spec[ $key ], $key, $current[ $key ] ?? '', $mode_manager );
			}
		}
		$values = self::writable_values( $values, $visible, $statuses );
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
	 * Reached from the header toggle as a POST, and from the stand-ins of the
	 * simple view as a nonce-signed GET. A `rip_anchor` sends the browser to
	 * the setting that was searched for instead of back to the referer.
	 *
	 * @return void
	 */
	public function handle_expert_toggle() {
		if ( ! ReportedIP_Hive_Option_Routing::current_user_can_manage() ) {
			wp_die( esc_html__( 'Permission denied.', 'reportedip-hive' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION_EXPERT );
		$on = ! empty( $_REQUEST['expert'] );
		update_user_meta( get_current_user_id(), self::META_EXPERT, $on ? 1 : 0 );
		$anchor = isset( $_REQUEST['rip_anchor'] ) ? sanitize_key( wp_unslash( $_REQUEST['rip_anchor'] ) ) : '';
		if ( '' !== $anchor ) {
			wp_safe_redirect( ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=' . self::PAGE_SLUG ) . '#' . $anchor );
			exit;
		}
		$redirect = wp_get_referer();
		if ( ! $redirect ) {
			$redirect = ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive' );
		}
		wp_safe_redirect( $redirect );
		exit;
	}
}
