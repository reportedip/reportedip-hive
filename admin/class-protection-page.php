<?php
/**
 * Protection page: five tabs over the registry sections, one form per tab.
 *
 * Every key is rendered in every view: the day-to-day keys as rows, the
 * rest behind "Show technical details", which expert mode opens by
 * default. Saving posts one tab to admin-post.php and writes through
 * `ReportedIP_Hive_Settings_Apply`, the same path MainWP, the cloud
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
	 * URL of the Protection page opened at one section, on the tab that holds it.
	 *
	 * @param string $section Section id, e.g. `privacy_logs`.
	 * @return string
	 * @since  2.1.62
	 */
	public static function section_url( $section ) {
		$section = sanitize_key( (string) $section );
		$url     = ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=' . self::PAGE_SLUG );
		$tab     = self::tab_of( $section );
		return ( '' !== $tab ? add_query_arg( self::TAB_PARAM, $tab, $url ) : $url ) . '#' . $section;
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
	 * admin-post action of the "Check protection" button.
	 *
	 * @var string
	 * @since 2.1.69
	 */
	const ACTION_CHECK = 'reportedip_hive_protection_check';

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
	 * Fields that only matter while another switch is on: key => switch.
	 *
	 * The row stays in the form (its value still round-trips), the script
	 * only hides it while the switch is off and shows it the moment the
	 * switch is flipped, so the operator who never touches Hide Login never
	 * sees a slug field.
	 *
	 * @var array<string,string>
	 * @since 2.1.69
	 */
	const DEPENDS = array(
		'reportedip_hive_hide_login_slug' => 'reportedip_hive_hide_login_enabled',
	);

	/**
	 * Query parameter that names the open tab.
	 *
	 * @var string
	 * @since 2.1.69
	 */
	const TAB_PARAM = 'tab';

	/**
	 * The five tabs of the page, in display order.
	 *
	 * A tab is a group of registry sections and nothing more. The sections
	 * keep their ids, their order inside a tab is the registry order, and
	 * nothing outside this class ever needs to know which tab holds which
	 * section: every link into the page still points at a section id.
	 *
	 * The sections of {@see ReportedIP_Hive_Catalog::sections()} (the ones
	 * the add-on fills completely) sit on the tab the catalog names, so the
	 * Advanced tab shows their catalog rows without the add-on and the real
	 * fields with it. A registry section no tab names (one an add-on adds
	 * through `reportedip_hive_settings_sections`) lands on the Advanced
	 * tab. A tab without sections is left out.
	 *
	 * @return array<string, array{label:string,icon:string,sections:string[],advice:string}>
	 * @since  2.1.69
	 */
	public static function tabs() {
		$tabs = array(
			'basics'     => array(
				'label'    => __( 'Core protection', 'reportedip-hive' ),
				'icon'     => 'shield',
				'sections' => array( 'detection', 'blocking', 'hide_login', 'account_security', 'account_password' ),
				'advice'   => __( 'Recommended: keep the defaults on. Change a threshold only when a sign-in or a block does not behave as expected.', 'reportedip-hive' ),
			),
			'forms'      => array(
				'label'    => __( 'Forms', 'reportedip-hive' ),
				'icon'     => 'file',
				'sections' => array( 'forms', 'registration' ),
				'advice'   => __( 'Recommended: keep the defaults on. Changes are only needed when a form does not work as expected.', 'reportedip-hive' ),
			),
			'firewall'   => array(
				'label'    => __( 'Firewall & Bots', 'reportedip-hive' ),
				'icon'     => 'users',
				'sections' => array( 'waf', 'lockdown', 'headers' ),
				'advice'   => __( 'Recommended: keep the firewall on. Add an exception on the Tools page before switching a rule off.', 'reportedip-hive' ),
			),
			'advanced'   => array(
				'label'    => __( 'Advanced', 'reportedip-hive' ),
				'icon'     => 'settings',
				'sections' => array(),
				'advice'   => __( 'These settings only matter during a coordinated attack or for a second factor asked again. The recommendation covers both.', 'reportedip-hive' ),
			),
			'operations' => array(
				'label'    => __( 'Operations', 'reportedip-hive' ),
				'icon'     => 'activity',
				'sections' => array( 'privacy_logs', 'notifications', 'performance' ),
				'advice'   => __( 'Logs, mails and the footprint per request. None of it decides what is blocked.', 'reportedip-hive' ),
			),
		);

		foreach ( ReportedIP_Hive_Catalog::sections() as $section => $meta ) {
			if ( isset( $tabs[ $meta['tab'] ] ) ) {
				$tabs[ $meta['tab'] ]['sections'][] = (string) $section;
			}
		}
		$claimed = array_merge( ...array_column( $tabs, 'sections' ) );
		foreach ( array_keys( ReportedIP_Hive_Settings_Registry::sections() ) as $section ) {
			if ( ! in_array( $section, $claimed, true ) ) {
				$tabs['advanced']['sections'][] = $section;
			}
		}

		/**
		 * The tabs of the Protection page, slug => label, icon, sections and
		 * advice. A result that is not an array is ignored.
		 *
		 * @param array<string, array{label:string,icon:string,sections:string[],advice:string}> $tabs Tabs in display order.
		 * @since 3.0.0
		 */
		$filtered = apply_filters( 'reportedip_hive_protection_tabs', $tabs );
		$tabs     = is_array( $filtered ) ? $filtered : $tabs;

		return array_filter(
			$tabs,
			static function ( $tab ) {
				return array() !== $tab['sections'];
			}
		);
	}

	/**
	 * Slug of the tab that holds one section.
	 *
	 * @param string $section Section id.
	 * @return string Tab slug, or an empty string for an unknown section.
	 * @since  2.1.69
	 */
	public static function tab_of( $section ) {
		foreach ( self::tabs() as $slug => $tab ) {
			if ( in_array( (string) $section, $tab['sections'], true ) ) {
				return (string) $slug;
			}
		}
		return '';
	}

	/**
	 * Inline SVG of a tab icon.
	 *
	 * @param string $icon Icon key from {@see tabs()}.
	 * @return string Escaped markup, empty for an unknown key.
	 * @since  2.1.69
	 */
	public static function tab_icon( $icon ) {
		$open  = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">';
		$paths = array(
			'shield'   => '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
			'file'     => '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="16" y2="17"/>',
			'users'    => '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
			'settings' => '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
			'activity' => '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
		);
		if ( ! isset( $paths[ (string) $icon ] ) ) {
			return '';
		}
		return $open . $paths[ (string) $icon ] . '</svg>';
	}

	/**
	 * Wire hooks.
	 */
	public function __construct() {
		add_action( 'admin_post_' . self::ACTION_SAVE, array( $this, 'handle_save' ) );
		add_action( 'admin_post_' . self::ACTION_EXPERT, array( $this, 'handle_expert_toggle' ) );
		add_action( 'admin_post_' . self::ACTION_CHECK, array( $this, 'handle_check' ) );
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
	 * Whether one field is a main row of its section. Three ways in. The
	 * expert flag makes everything a main row (used to list every key of a
	 * section). `simple` marks a setting as day-to-day on every site.
	 * `simple_form` names the form plugin whose presence makes a setting
	 * day-to-day here: an operator running Formidable Forms should find the
	 * Formidable switch at the top of the section, and an operator without
	 * it finds it in the technical details with a note.
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
		foreach ( array_keys( ReportedIP_Hive_Form_Adapters::adapters() ) as $slug ) {
			if ( $adapters->detected( $slug ) ) {
				$slugs[] = (string) $slug;
			}
		}

		return $slugs;
	}

	/**
	 * Registry keys of one section in registry order: every key when
	 * `$expert` is true, otherwise the main rows only.
	 *
	 * @param string        $section  Section id.
	 * @param bool          $expert   Expert view.
	 * @param string[]|null $detected Active form plugins; resolved from the site when null.
	 * @return string[]
	 */
	public static function visible_keys( $section, $expert, $detected = null ) {
		$detected = null === $detected ? self::detected_forms() : array_map( 'strval', (array) $detected );
		$keys     = array();
		foreach ( ReportedIP_Hive_Settings_Registry::spec() as $key => $entry ) {
			if ( ( $entry['section'] ?? '' ) === $section && self::is_visible( $entry, (bool) $expert, $detected ) ) {
				$keys[] = $key;
			}
		}
		return $keys;
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
		$kind     = (string) $entry['kind'];
		$row      = in_array( $kind, array( 'bool', 'int', 'enum' ), true );
		$plan_row = 'bool' === $kind && $locked && ! empty( $status['plan_url'] ) && ! empty( $status['plan_label'] );
		$control  = '';
		$classes  = 'rip-protection__field' . ( $row ? ' rip-protection__field--row' : '' ) . ( $locked ? ' rip-protection__field--locked' : '' );

		if ( $plan_row ) {
			$control = self::plan_row_markup( (string) $status['plan_label'], (string) $status['plan_url'] );
			$kind    = 'plan';
		}

		switch ( $kind ) {
			case 'plan':
				break;
			case 'bool':
				$on      = ! empty( $value ) || ! empty( $status['forced'] );
				$control = sprintf(
					'<label class="rip-toggle"><input type="checkbox" class="rip-toggle__input" id="%1$s" name="%2$s" value="1"%3$s%4$s /><span class="rip-toggle__slider"></span></label><span class="rip-protection__state" data-on="%5$s" data-off="%6$s" aria-hidden="true">%7$s</span>',
					esc_attr( $id ),
					esc_attr( $key ),
					$on ? ' checked' : '',
					$disabled,
					esc_attr__( 'Active', 'reportedip-hive' ),
					esc_attr__( 'Off', 'reportedip-hive' ),
					$on ? esc_html__( 'Active', 'reportedip-hive' ) : esc_html__( 'Off', 'reportedip-hive' )
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
					$checked    = $fixed || in_array( (string) $choice, $current, true );
					$closed     = $fixed || ( ! $checked && ! empty( $choice_def['disabled'] ) );
					$boxes     .= sprintf(
						'<label class="rip-checkbox"><input type="checkbox" name="%1$s[]" value="%2$s" %3$s%4$s /> %5$s</label>%6$s',
						esc_attr( $key ),
						esc_attr( (string) $choice ),
						$checked ? 'checked' : '',
						( $locked || $closed ) ? ' disabled' : '',
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
		if ( ! $plan_row ) {
			ob_start();
			/**
			 * Print a marker next to the label of one Protection-page field,
			 * for a reason the free plugin does not know (the add-on names
			 * the plan a field belongs to).
			 *
			 * @param array<string,mixed> $status Status from `field_status()`.
			 * @param string              $key    Option key.
			 * @param array<string,mixed> $entry  Spec entry.
			 * @since 3.0.0
			 */
			do_action( 'reportedip_hive_protection_field_marker', $status, (string) $key, $entry );
			$marker = (string) ob_get_clean();
		}
		$note = trim( (string) ( $status['note'] ?? '' ) );
		if ( '' !== $note ) {
			$desc = trim( $desc . ' ' . $note );
		}

		$depends = isset( self::DEPENDS[ $key ] ) ? ' data-depends="' . esc_attr( self::DEPENDS[ $key ] ) . '"' : '';

		return sprintf(
			'<div class="%1$s" data-search="%2$s" data-key="%3$s"%9$s><div class="rip-protection__field-head"><label class="rip-label" for="%4$s">%5$s</label>%6$s</div><div class="rip-protection__control">%7$s</div>%8$s</div>',
			esc_attr( $classes ),
			esc_attr( $search ),
			esc_attr( $key ),
			esc_attr( $id ),
			esc_html( $label ),
			$marker,
			$control,
			'' !== $desc ? '<p class="rip-help-text">' . esc_html( $desc ) . '</p>' : '',
			$depends
		);
	}

	/**
	 * A catalog row: a feature of the add-on, shown in the section it
	 * belongs to, with its plan, its description and a link to the product
	 * page. No input, nothing to switch.
	 *
	 * @param string              $feature Catalog key.
	 * @param array<string,mixed> $row     Catalog row.
	 * @return string
	 * @since  3.0.0
	 */
	public static function catalog_row_markup( $feature, array $row ) {
		$label = (string) $row['label'];
		$info  = ReportedIP_Hive_Mode_Manager::get_instance()->get_tier_info( (string) $row['tier'] );
		/* translators: %s: plan name, for example Professional */
		$desc = (string) $row['description'] . ' ' . sprintf( __( 'Available in the ReportedIP Hive Pro add-on (%s plan).', 'reportedip-hive' ), (string) $info['label'] );
		if ( ! empty( $row['community_only'] ) ) {
			$desc .= ' ' . __( 'Needs the Community Network.', 'reportedip-hive' );
		}
		$badge = sprintf( '<span class="rip-tier-badge rip-tier-badge--sm %1$s">%2$s</span>', esc_attr( (string) $info['badge_class'] ), esc_html( (string) $info['short_label'] ) );

		return sprintf(
			'<div class="rip-protection__field rip-protection__field--row rip-protection__field--catalog" data-search="%1$s" data-feature="%2$s"><div class="rip-protection__field-head"><span class="rip-label">%3$s</span></div><div class="rip-protection__control"><span class="rip-protection__plan">%4$s<a class="rip-button rip-button--secondary rip-button--sm" href="%5$s" target="_blank" rel="noopener">%6$s</a></span></div><p class="rip-help-text">%7$s</p></div>',
			esc_attr( strtolower( $label . ' ' . $desc ) ),
			esc_attr( (string) $feature ),
			esc_html( $label ),
			$badge,
			esc_url( (string) $row['docs_url'] ),
			esc_html__( 'Learn more', 'reportedip-hive' ),
			esc_html( $desc )
		);
	}

	/**
	 * The catalog rows of one section, without the ones an add-on hides
	 * because it renders the real fields.
	 *
	 * @param string $section Section id.
	 * @return array<string, array<string, mixed>> Catalog key => row.
	 * @since  3.0.0
	 */
	public static function catalog_rows( $section ) {
		$rows = array();
		foreach ( ReportedIP_Hive_Catalog::by_section()[ (string) $section ] ?? array() as $feature => $row ) {
			/**
			 * Hide one catalog row, for instance because the add-on renders
			 * the real fields of the feature.
			 *
			 * @param bool   $hidden  Default false.
			 * @param string $feature Catalog key.
			 * @since 3.0.0
			 */
			if ( apply_filters( 'reportedip_hive_catalog_row_hidden', false, (string) $feature ) ) {
				continue;
			}
			$rows[ (string) $feature ] = $row;
		}
		return $rows;
	}

	/**
	 * What a plan-locked switch shows in place of its toggle.
	 *
	 * @param string $plan_label Name of the plan the feature needs.
	 * @param string $href       Pricing link.
	 * @return string
	 * @since  2.1.69
	 */
	public static function plan_row_markup( $plan_label, $href ) {
		return sprintf(
			'<span class="rip-protection__plan"><span class="rip-badge rip-badge--warning">%1$s</span><a class="rip-button rip-button--secondary rip-button--sm" href="%2$s" target="_blank" rel="noopener">%3$s</a></span>',
			/* translators: %s: plan name, for example Professional */
			esc_html( sprintf( __( '%s feature', 'reportedip-hive' ), (string) $plan_label ) ),
			esc_url( (string) $href ),
			esc_html__( 'Learn more', 'reportedip-hive' )
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
	 * Shared by every rendered field, so a search behaves the same in every tab.
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
	 * Lock status of one field for the current value.
	 *
	 * Three outcomes: available, partial (editable, the value is checked on
	 * save) and locked (disabled, value dropped on save). The free plugin
	 * only knows runtime locks (no crypto, no WooCommerce, the Hide Login
	 * constant, wp-admin forced closed while Hide Login is on, a form plugin
	 * that is not active); they carry a note. Every other reason comes from
	 * `reportedip_hive_protection_field_status`, which sees the runtime
	 * status and may replace it. A status with `plan_label` and `plan_url`
	 * turns a locked switch into a plan row.
	 *
	 * @param array<string,mixed>          $entry        Registry entry.
	 * @param string                       $key          Registry key.
	 * @param mixed                        $value        Current value.
	 * @param ReportedIP_Hive_Mode_Manager $mode_manager Mode manager.
	 * @return array<string,mixed>
	 */
	public static function field_status( array $entry, $key, $value, $mode_manager ) {
		$runtime = self::runtime_lock( (string) $key );
		$status  = null !== $runtime ? $runtime : array( 'available' => true );

		/**
		 * Lock or annotate one Protection-page field for a reason the free
		 * plugin does not know. Keys the page reads: `available`, `partial`
		 * (editable while locked), `forced` (a switch written as on),
		 * `reason`, `note` (appended to the description), `plan_label` and
		 * `plan_url` (a locked switch becomes a plan row). A result that is
		 * not an array keeps the status.
		 *
		 * @param array<string,mixed>          $status       Runtime lock, or `available` true.
		 * @param string                       $key          Option key.
		 * @param array<string,mixed>          $entry        Spec entry.
		 * @param mixed                        $value        Stored value.
		 * @param ReportedIP_Hive_Mode_Manager $mode_manager Mode manager.
		 * @since 3.0.0
		 */
		$filtered = apply_filters( 'reportedip_hive_protection_field_status', $status, (string) $key, $entry, $value, $mode_manager );
		return is_array( $filtered ) ? $filtered : $status;
	}

	/**
	 * Locks that do not come from the plan.
	 *
	 * @param string $key Registry key.
	 * @return array<string,mixed>|null Status array, or null when no runtime lock applies.
	 */
	private static function runtime_lock( $key ) {
		$adapter = self::adapter_behind( $key );

		if ( array() !== $adapter ) {
			return self::adapter_lock(
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

		foreach ( ReportedIP_Hive_Form_Adapters::adapters() as $slug => $adapter ) {
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
	 * The add-on replaces this status with its plan lock when the plan does
	 * not cover the adapter, see `reportedip_hive_protection_field_status`.
	 *
	 * @param string $signature Class the target plugin defines.
	 * @param string $note      Reason shown under the field.
	 * @return array<string,mixed>|null
	 */
	private static function adapter_lock( $signature, $note ) {
		if ( class_exists( $signature ) ) {
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
	 * Keys outside the given list and locked keys
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
	 * The recommendation for the keys of one tab.
	 *
	 * Pure. Keys the recommendation does not name are absent, so a reset
	 * leaves them where they are.
	 *
	 * @param string $tab  Tab slug.
	 * @param string $tier Tier slug.
	 * @param string $mode `community` or `local`.
	 * @return array<string,mixed>
	 * @since  2.1.69
	 */
	public static function reset_values( $tab, $tier, $mode ) {
		$keys = array();
		foreach ( self::tabs()[ $tab ]['sections'] ?? array() as $section ) {
			$keys = array_merge( $keys, self::visible_keys( $section, true, array() ) );
		}
		return array_intersect_key( ReportedIP_Hive_Defaults::recommended( (string) $tier, (string) $mode ), array_flip( $keys ) );
	}

	/**
	 * Lock status of every registry key for the current values.
	 *
	 * @param array<string,mixed>          $current      Current values.
	 * @param ReportedIP_Hive_Mode_Manager $mode_manager Mode manager.
	 * @return array<string,array<string,mixed>>
	 * @since  2.1.69
	 */
	public static function field_statuses( array $current, $mode_manager ) {
		$statuses = array();
		foreach ( ReportedIP_Hive_Settings_Registry::spec() as $key => $entry ) {
			$statuses[ $key ] = self::field_status( $entry, $key, $current[ $key ] ?? '', $mode_manager );
		}
		return $statuses;
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
			'digest'      => __( 'Daily summary', 'reportedip-hive' ),
			'instant'     => __( 'Single mail per event', 'reportedip-hive' ),
		);
		return $labels[ $value ] ?? $value;
	}

	/**
	 * Choice map for a `json_list` key.
	 *
	 * Each entry is `array{label:string,disabled:bool,fixed:bool}`. A fixed
	 * choice is always checked, disabled and carried in the POST by a hidden
	 * input. The method list comes from the 2FA method registry; a method
	 * whose `choice_lock` names a plan is disabled and marked with it. A
	 * registry entry with `choice_locks` (callable returning the values that
	 * cannot be selected right now) disables those values. A disabled choice that is
	 * stored renders checked and enabled, so it can be removed (a feature
	 * the plan no longer includes can still be switched off); it only
	 * cannot be selected anew, see field_markup().
	 *
	 * @param array<string,mixed> $entry Registry entry.
	 * @param string              $key   Registry key.
	 * @return array<string,array{label:string,disabled:bool,fixed:bool}>
	 */
	public static function choices_for( array $entry, $key = '' ) {
		$source  = (string) ( $entry['choices'] ?? '' );
		$map     = ReportedIP_Hive_Settings_Registry::choice_values( $source );
		$fixed   = array_map( 'strval', (array) ( $entry['choices_fixed'] ?? array() ) );
		$choices = array();
		foreach ( $map as $value => $label ) {
			$choices[ (string) $value ] = array(
				'label'    => (string) $label,
				'disabled' => in_array( (string) $value, $fixed, true ),
				'fixed'    => in_array( (string) $value, $fixed, true ),
			);
		}
		if ( 'methods' === $source ) {
			foreach ( ReportedIP_Hive_Two_Factor::methods() as $slug => $definition ) {
				if ( ! isset( $choices[ $slug ], $definition['choice_lock'] ) || ! is_callable( $definition['choice_lock'] ) ) {
					continue;
				}
				$plan = (string) call_user_func( $definition['choice_lock'] );
				if ( '' !== $plan ) {
					$choices[ $slug ]['disabled'] = true;
					/* translators: %s: plan name */
					$choices[ $slug ]['label'] .= ' ' . sprintf( __( '(%s plan)', 'reportedip-hive' ), $plan );
				}
			}
		}
		if ( isset( $entry['choice_locks'] ) && is_callable( $entry['choice_locks'] ) ) {
			foreach ( (array) call_user_func( $entry['choice_locks'], (string) $key ) as $value ) {
				if ( isset( $choices[ (string) $value ] ) ) {
					$choices[ (string) $value ]['disabled'] = true;
				}
			}
		}
		return $choices;
	}

	/**
	 * Note shown under a checkbox group, from the registry entry's
	 * `choices_note` (callable receiving the key, returning the note or '').
	 *
	 * @param string              $key   Registry key.
	 * @param array<string,mixed> $entry Registry entry; read from the registry when empty.
	 * @return string
	 */
	public static function choices_note( $key, array $entry = array() ) {
		if ( array() === $entry ) {
			$entry = ReportedIP_Hive_Settings_Registry::spec()[ (string) $key ] ?? array();
		}
		if ( ! isset( $entry['choices_note'] ) || ! is_callable( $entry['choices_note'] ) ) {
			return '';
		}
		return (string) call_user_func( $entry['choices_note'], (string) $key );
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
		}

		/**
		 * Short status of a section the free plugin does not describe, as
		 * `array{text:string,tone:string}` with `tone` `success`, `danger`
		 * or `neutral`.
		 *
		 * @param array{text:string,tone:string} $state   Default: empty and neutral.
		 * @param string                         $section Section id.
		 * @param array<string,mixed>            $current Current values.
		 * @since 3.0.0
		 */
		$state = (array) apply_filters( 'reportedip_hive_section_state', self::neutral_state( '' ), (string) $section, $current );
		$tone  = (string) ( $state['tone'] ?? 'neutral' );
		return array(
			'text' => (string) ( $state['text'] ?? '' ),
			'tone' => in_array( $tone, array( 'success', 'danger', 'neutral' ), true ) ? $tone : 'neutral',
		);
	}

	/**
	 * Whether every key of a section sits behind the plan.
	 *
	 * A plan lock (`reason` `tier`) and a mode lock (`reason` `mode`, the
	 * feature needs the Community Network) both count. A `partial` status
	 * does not open the section: a switch that is still on after a
	 * downgrade may be switched off, but the feature behind it is not in
	 * the plan, and the tab pill must not call it active. A runtime lock or
	 * a single open key leaves the section open.
	 *
	 * @param string                            $section  Section id.
	 * @param array<string,array<string,mixed>> $statuses Key => status from {@see field_status()}.
	 * @return bool
	 * @since  2.1.69
	 */
	public static function section_locked( $section, array $statuses ) {
		$keys = self::visible_keys( $section, true, array() );
		if ( array() === $keys ) {
			return false;
		}
		foreach ( $keys as $key ) {
			$status = $statuses[ $key ] ?? array( 'available' => true );
			if ( ! empty( $status['available'] ) || ! in_array( (string) ( $status['reason'] ?? '' ), array( 'tier', 'mode' ), true ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Short state of one tab, aggregated from its section states.
	 *
	 * Counting sections rather than switches keeps the pill and the
	 * dashboard area rows on the same verdict, and keeps a switch whose
	 * "on" means less protection (report-only, minimal logging) from being
	 * read as protection. A locked section is left out and remembered; a
	 * neutral section is left out. `plan` names the plan a fully locked tab
	 * waits for, so the renderer can label it without this method needing
	 * the mode manager.
	 *
	 * @param string                            $tab      Tab slug.
	 * @param array<string,mixed>               $current  Current values.
	 * @param array<string,array<string,mixed>> $statuses Key => status from {@see field_status()}.
	 * @return array{text:string,tone:string,plan:string}
	 * @since  2.1.69
	 */
	public static function tab_state( $tab, array $current, array $statuses ) {
		$sections = self::tabs()[ $tab ]['sections'] ?? array();
		$counted  = 0;
		$on       = 0;
		$plan     = '';
		foreach ( $sections as $section ) {
			if ( self::section_locked( $section, $statuses ) ) {
				$first = $statuses[ self::visible_keys( $section, true, array() )[0] ];
				if ( '' === $plan && 'tier' === (string) ( $first['reason'] ?? '' ) ) {
					$plan = (string) ( $first['min_tier'] ?? '' );
				}
				continue;
			}
			$tone = self::section_state( $section, $current )['tone'];
			if ( 'neutral' === $tone ) {
				continue;
			}
			++$counted;
			if ( 'success' === $tone ) {
				++$on;
			}
		}
		if ( 0 === $counted ) {
			return array(
				'text' => '',
				'tone' => 'neutral',
				'plan' => $plan,
			);
		}
		if ( $on === $counted ) {
			return array(
				'text' => __( 'Active', 'reportedip-hive' ),
				'tone' => 'success',
				'plan' => '',
			);
		}
		if ( 0 === $on ) {
			return array(
				'text' => __( 'Off', 'reportedip-hive' ),
				'tone' => 'danger',
				'plan' => '',
			);
		}
		return array(
			/* translators: 1: sections switched on, 2: sections counted */
			'text' => sprintf( __( '%1$d of %2$d active', 'reportedip-hive' ), $on, $counted ),
			'tone' => 'neutral',
			'plan' => '',
		);
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
				<span class="rip-tooltip" id="<?php echo esc_attr( self::INFO_ID ); ?>" role="tooltip"><?php esc_html_e( 'Expert mode opens the technical details of every area by default and lists the Tools page. Simple mode keeps them folded; what sits in them runs on the recommendation. The switch is stored for your user only.', 'reportedip-hive' ); ?></span>
			</span>
			<noscript><button type="submit" class="rip-button rip-button--ghost rip-button--sm"><?php esc_html_e( 'Apply', 'reportedip-hive' ); ?></button></noscript>
		</form>
		<?php
	}

	/**
	 * One section inside a tab panel: head, main rows, technical details.
	 *
	 * Every key of the section is rendered, the day-to-day keys as rows
	 * and the rest inside a `<details>` that starts open in expert mode.
	 * The registry description of the section is written for the expert
	 * and only shown there; the simple view keeps the head to the label
	 * and the status.
	 * A closed details block still posts its fields, so nothing here can
	 * come back empty on the next save; a locked field is still dropped by
	 * {@see writable_values()}.
	 *
	 * @param string                            $section  Section id.
	 * @param array<string,mixed>               $current  Current values.
	 * @param array<string,array<string,mixed>> $statuses Key => status from {@see field_statuses()}.
	 * @param bool                              $expert   Whether the details start open.
	 * @param string[]                          $detected Adapter slugs whose form plugin is active.
	 * @param array<string,string>              $errors   Key => message from the last save.
	 * @param array<string,array<string,mixed>> $choices  Key => choice map for `json_list` keys; resolved through {@see choices_for()} when absent.
	 * @return string
	 * @since  2.1.69
	 */
	public static function section_markup( $section, array $current, array $statuses, $expert, array $detected, array $errors, array $choices = array() ) {
		$meta  = ReportedIP_Hive_Settings_Registry::sections()[ $section ] ?? ( ReportedIP_Hive_Catalog::sections()[ $section ] ?? array() );
		$spec  = ReportedIP_Hive_Settings_Registry::spec();
		$state = self::section_state( $section, $current );
		$main  = self::visible_keys( $section, false, $detected );
		$rest  = array_values( array_diff( self::visible_keys( $section, true, $detected ), $main ) );

		$rows = static function ( array $keys ) use ( $spec, $current, $statuses, $errors, $detected, $choices ) {
			$out = '';
			foreach ( $keys as $key ) {
				$entry  = $spec[ $key ];
				$status = $statuses[ $key ] ?? array( 'available' => true );
				$note   = 'json_list' === $entry['kind'] ? self::choices_note( $key, $entry ) : '';
				$missed = self::missing_form_plugin( $entry, $detected );
				if ( '' !== $missed && empty( $status['note'] ) ) {
					$note = trim( $note . ' ' . self::hint_reason( $missed ) );
				}
				if ( '' !== $note ) {
					$status['note'] = trim( (string) ( $status['note'] ?? '' ) . ' ' . $note );
				}
				$map  = isset( $choices[ $key ] ) ? $choices[ $key ] : ( 'json_list' === $entry['kind'] ? self::choices_for( $entry, $key ) : array() );
				$out .= self::field_markup( $key, $entry, $current[ $key ] ?? '', $status, $map );
				if ( isset( $errors[ $key ] ) ) {
					$out .= '<p class="rip-alert rip-alert--error rip-protection__error" data-for="' . esc_attr( $key ) . '">' . esc_html( (string) $errors[ $key ] ) . '</p>';
				}
			}
			return $out;
		};

		$html = sprintf(
			'<div class="rip-protection__section" id="%1$s"><div class="rip-protection__section-head"><span class="rip-protection__title">%2$s</span>%3$s%4$s</div>',
			esc_attr( $section ),
			esc_html( (string) ( $meta['label'] ?? $section ) ),
			$expert ? '<span class="rip-protection__desc">' . esc_html( (string) ( $meta['description'] ?? '' ) ) . '</span>' : '',
			'' === $state['text'] ? '' : '<span class="rip-badge rip-badge--' . esc_attr( $state['tone'] ) . ' rip-protection__status">' . esc_html( $state['text'] ) . '</span>'
		);
		if ( 'detection' === $section ) {
			ob_start();
			self::render_preset_field( self::current_preset( $current ) );
			$html .= (string) ob_get_clean();
		}
		$html .= $rows( $main );
		if ( array() !== $rest ) {
			$html .= sprintf(
				'<details class="rip-protection__details"%1$s><summary><svg class="rip-protection__chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><polyline points="6 9 12 15 18 9"/></svg>%2$s</summary>%3$s</details>',
				$expert ? ' open' : '',
				esc_html__( 'Show technical details', 'reportedip-hive' ),
				$rows( $rest )
			);
		}
		foreach ( self::catalog_rows( $section ) as $feature => $row ) {
			$html .= self::catalog_row_markup( $feature, $row );
		}
		return $html . '</div>';
	}

	/**
	 * Whether a tab holds at least one registry key, so its form has
	 * something to save or reset. A tab of catalog rows alone has not.
	 *
	 * @param string $tab Tab slug.
	 * @return bool
	 * @since  3.0.0
	 */
	public static function tab_has_fields( $tab ) {
		foreach ( self::tabs()[ $tab ]['sections'] ?? array() as $section ) {
			if ( array() !== self::visible_keys( $section, true, array() ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Slug of the tab the request asks for.
	 *
	 * @param string $requested Value of the `tab` parameter.
	 * @return string A known slug; the first tab when the parameter is missing or unknown.
	 * @since  2.1.69
	 */
	public static function active_tab( $requested ) {
		$tabs = self::tabs();
		$slug = sanitize_key( (string) $requested );
		return isset( $tabs[ $slug ] ) ? $slug : (string) array_key_first( $tabs );
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
		$statuses     = self::field_statuses( $current, $mode_manager );
		$detected     = self::detected_forms();
		$requested    = isset( $_GET[ self::TAB_PARAM ] ) && is_string( $_GET[ self::TAB_PARAM ] ) ? wp_unslash( $_GET[ self::TAB_PARAM ] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- read-only tab choice, whitelisted in active_tab()
		$active       = self::active_tab( $requested );
		$page_url     = ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=' . self::PAGE_SLUG );
		$errors       = ! empty( $result['errors'] ) && is_array( $result['errors'] ) ? $result['errors'] : array();

		ReportedIP_Hive_Admin_Settings::render_page_header(
			__( 'Protection', 'reportedip-hive' ),
			__( 'Every setting, grouped by area; the technical details fold away', 'reportedip-hive' )
		);
		?>
		<div class="rip-content rip-protection">
			<?php self::render_page_banner( $active ); ?>
			<div class="rip-protection__search">
				<input type="search" id="rip-protection-search" class="rip-input" placeholder="<?php esc_attr_e( 'Search settings, e.g. Tor, HSTS, retention', 'reportedip-hive' ); ?>" autocomplete="off" />
				<p class="rip-help-text rip-protection__no-results rip-hidden" id="rip-protection-no-results"><?php esc_html_e( 'No setting matches.', 'reportedip-hive' ); ?></p>
			</div>
			<?php if ( isset( $result['check'] ) && is_array( $result['check'] ) ) : ?>
				<?php $attention = (int) ( $result['check']['attention'] ?? 0 ); ?>
				<div class="rip-alert <?php echo 0 === $attention ? 'rip-alert--success' : 'rip-alert--warning'; ?>">
					<?php
					/* translators: 1: issues that need attention, 2: advisory hints */
					echo esc_html( sprintf( __( 'Check done: %1$d issues need attention, %2$d hints are open.', 'reportedip-hive' ), $attention, (int) ( $result['check']['advisory'] ?? 0 ) ) );
					printf(
						' <a href="%1$s">%2$s</a>',
						esc_url( ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive' ) . '#rip-next-steps' ),
						esc_html__( 'See the next steps on the dashboard.', 'reportedip-hive' )
					);
					?>
				</div>
			<?php endif; ?>
			<?php if ( isset( $result['applied'] ) ) : ?>
				<div class="rip-alert <?php echo array() === $errors ? 'rip-alert--success' : 'rip-alert--warning'; ?>">
					<?php
					if ( array() !== $errors ) {
						/* translators: %d: number of rejected settings */
						echo esc_html( sprintf( _n( '%d field was not saved, see the marked field.', '%d fields were not saved, see the marked fields.', count( $errors ), 'reportedip-hive' ), count( $errors ) ) );
					} elseif ( ! empty( $result['reset'] ) ) {
						/* translators: %d: number of changed settings */
						echo esc_html( sprintf( _n( '%d setting set back to the recommendation.', '%d settings set back to the recommendation.', (int) $result['applied'], 'reportedip-hive' ), (int) $result['applied'] ) );
					} else {
						/* translators: %d: number of changed settings */
						echo esc_html( sprintf( _n( '%d setting saved.', '%d settings saved.', (int) $result['applied'], 'reportedip-hive' ), (int) $result['applied'] ) );
					}
					?>
				</div>
			<?php endif; ?>
			<nav class="rip-nav-tabs rip-protection__tabs" aria-label="<?php esc_attr_e( 'Protection areas', 'reportedip-hive' ); ?>">
				<?php foreach ( self::tabs() as $slug => $tab ) : ?>
					<?php $state = self::tab_state( $slug, $current, $statuses ); ?>
					<?php
					$pill = $state['text'];
					if ( '' === $pill && '' !== $state['plan'] ) {
						$pill = (string) $mode_manager->get_tier_info( $state['plan'] )['label'];
					}
					?>
					<a href="<?php echo esc_url( add_query_arg( self::TAB_PARAM, $slug, $page_url ) ); ?>" class="rip-nav-tabs__tab<?php echo $slug === $active ? ' rip-nav-tabs__tab--active' : ''; ?>" data-tab="<?php echo esc_attr( $slug ); ?>">
						<?php echo self::tab_icon( $tab['icon'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static inline SVG ?>
						<span><?php echo esc_html( $tab['label'] ); ?></span>
						<?php if ( '' !== $pill ) : ?>
							<span class="rip-badge rip-badge--<?php echo esc_attr( $state['tone'] ); ?>"><?php echo esc_html( $pill ); ?></span>
						<?php endif; ?>
					</a>
				<?php endforeach; ?>
			</nav>
			<?php foreach ( self::tabs() as $slug => $tab ) : ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="rip-card rip-protection__panel<?php echo $slug === $active ? '' : ' rip-hidden'; ?>" data-tab="<?php echo esc_attr( $slug ); ?>">
					<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION_SAVE ); ?>" />
					<input type="hidden" name="rip_tab" value="<?php echo esc_attr( $slug ); ?>" />
					<?php wp_nonce_field( self::NONCE ); ?>
					<div class="rip-card__body">
						<div class="rip-alert rip-alert--info"><?php echo esc_html( $tab['advice'] ); ?></div>
						<?php foreach ( $tab['sections'] as $section ) : ?>
							<?php echo self::section_markup( $section, $current, $statuses, $expert, $detected, $errors ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside ?>
						<?php endforeach; ?>
						<?php if ( self::tab_has_fields( $slug ) ) : ?>
						<div class="rip-card__footer rip-protection__footer">
							<button type="submit" name="rip_reset" value="1" class="rip-button rip-button--ghost rip-protection__reset" data-confirm="<?php esc_attr_e( 'Set every setting of this tab back to the recommendation for your plan?', 'reportedip-hive' ); ?>"><?php esc_html_e( 'Restore defaults', 'reportedip-hive' ); ?></button>
							<button type="submit" class="rip-button rip-button--primary"><?php esc_html_e( 'Save changes', 'reportedip-hive' ); ?></button>
						</div>
						<?php endif; ?>
					</div>
				</form>
			<?php endforeach; ?>
		</div>
		<?php
		ReportedIP_Hive_Admin_Settings::render_page_footer();
	}

	/**
	 * The status banner above the tabs, shared with the dashboard, and the
	 * "Check protection" button next to it.
	 *
	 * The button runs the readiness check again, past its cache, and the
	 * page reports the count; the dashboard holds the list. Only shown once
	 * the quickstart is done, because the banner is empty before that.
	 *
	 * @param string $tab Active tab, so the check lands back on it.
	 * @return void
	 * @since  2.1.69
	 */
	private static function render_page_banner( $tab ) {
		if ( ! class_exists( 'ReportedIP_Hive_Dashboard_Next_Steps' ) || ! ReportedIP_Hive_Mode_Manager::get_instance()->is_wizard_completed() ) {
			return;
		}
		?>
		<div class="rip-protection__banner">
			<?php ReportedIP_Hive_Dashboard_Next_Steps::render_banner( ReportedIP_Hive_API::get_instance() ); ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="rip-protection__check">
				<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION_CHECK ); ?>" />
				<input type="hidden" name="rip_tab" value="<?php echo esc_attr( $tab ); ?>" />
				<?php wp_nonce_field( self::ACTION_CHECK ); ?>
				<button type="submit" class="rip-button rip-button--secondary rip-button--sm"><?php esc_html_e( 'Check protection', 'reportedip-hive' ); ?></button>
				<p class="rip-help-text"><?php esc_html_e( 'Runs the setup check again and reports what still needs attention.', 'reportedip-hive' ); ?></p>
			</form>
		</div>
		<?php
	}

	/**
	 * admin-post handler: run the readiness check past its cache and
	 * report the counts on the page.
	 *
	 * @return void
	 * @since  2.1.69
	 */
	public function handle_check() {
		if ( ! ReportedIP_Hive_Option_Routing::current_user_can_manage() ) {
			wp_die( esc_html__( 'Permission denied.', 'reportedip-hive' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION_CHECK );
		$issues    = ReportedIP_Hive_Readiness::open_issues( true );
		$attention = ReportedIP_Hive_Readiness::attention_count( $issues );
		set_transient(
			self::RESULT_TRANSIENT . get_current_user_id(),
			array(
				'check' => array(
					'attention' => $attention,
					'advisory'  => count( $issues ) - $attention,
				),
			),
			60
		);
		$tab = isset( $_POST['rip_tab'] ) ? self::active_tab( sanitize_key( wp_unslash( $_POST['rip_tab'] ) ) ) : '';
		wp_safe_redirect( add_query_arg( self::TAB_PARAM, $tab, ReportedIP_Hive_Admin_Settings::back_url( 'admin.php?page=' . self::PAGE_SLUG ) ) );
		exit;
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
	 * admin-post handler: save or reset one tab through the apply service.
	 *
	 * See {@see writable_values()} for which posted keys are written and
	 * {@see reset_values()} for what a reset writes. A preset that still
	 * matches the stored values is dropped from the POST, so a number typed
	 * into the blocking rows of the same form is not overwritten by the
	 * preset's copy of it.
	 *
	 * @return void
	 */
	public function handle_save() {
		if ( ! ReportedIP_Hive_Option_Routing::current_user_can_manage() ) {
			wp_die( esc_html__( 'Permission denied.', 'reportedip-hive' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::NONCE );
		$post = wp_unslash( $_POST ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- every value passes the registry sanitizer in Settings_Apply
		$tab  = isset( $post['rip_tab'] ) ? sanitize_key( $post['rip_tab'] ) : '';
		$tabs = self::tabs();
		if ( ! isset( $tabs[ $tab ] ) ) {
			wp_die( esc_html__( 'Unknown tab.', 'reportedip-hive' ), '', array( 'response' => 400 ) );
		}
		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		$current      = ReportedIP_Hive_Settings_Registry::current_values();
		$statuses     = self::field_statuses( $current, $mode_manager );
		$reset        = ! empty( $post['rip_reset'] );
		$values       = array();

		if ( $reset ) {
			$tier   = (string) ( $mode_manager->get_tier_info()['key'] ?? 'free' );
			$values = self::reset_values( $tab, $tier, (string) $mode_manager->get_mode() );
			$values = self::writable_values( $values, array_keys( $values ), $statuses );
		} else {
			if ( isset( $post[ self::PRESET_FIELD ] ) && (string) $post[ self::PRESET_FIELD ] === self::current_preset( $current ) ) {
				unset( $post[ self::PRESET_FIELD ] );
			}
			foreach ( $tabs[ $tab ]['sections'] as $section ) {
				$all     = self::visible_keys( $section, true, array() );
				$values += self::writable_values( self::collect_values( (array) $post, $section ), $all, $statuses );
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
				'applied' => (int) $result['applied'],
				'errors'  => $errors,
				'reset'   => $reset,
			),
			60
		);
		$url = add_query_arg( self::TAB_PARAM, $tab, ReportedIP_Hive_Admin_Settings::back_url( 'admin.php?page=' . self::PAGE_SLUG ) );
		if ( array() !== $errors ) {
			$spec = ReportedIP_Hive_Settings_Registry::spec();
			$url .= '#' . (string) ( $spec[ array_key_first( $errors ) ]['section'] ?? $tab );
		}
		wp_safe_redirect( $url );
		exit;
	}

	/**
	 * admin-post handler: flip the expert view for the current user.
	 *
	 * Reached from the header toggle as a POST.
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
		$redirect = wp_get_referer();
		if ( ! $redirect ) {
			$redirect = ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive' );
		}
		wp_safe_redirect( $redirect );
		exit;
	}
}
