<?php
/**
 * Shared filter bar for the list tables on the Activity page.
 *
 * The bar is its own GET form above the table, so the active filters live
 * in the URL: pagination, column sorting and a bulk action keep them, and a
 * filtered view can be bookmarked. The table's own POST form only carries
 * the bulk action.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.57
 *
 * @phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only filter state echoed back into a GET form.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Opens and closes the filter form; the table renders its fields in between.
 *
 * @since 2.1.57
 */
class ReportedIP_Hive_Filter_Bar {

	/**
	 * Open the form and carry the page location plus the current sort order.
	 *
	 * @param array<string,string> $location Hidden fields that identify the tab, e.g. page/tab/sub.
	 * @return void
	 * @since  2.1.57
	 */
	public static function open( array $location ) {
		foreach ( array( 'orderby', 'order' ) as $sort_key ) {
			if ( ! empty( $_GET[ $sort_key ] ) ) {
				$location[ $sort_key ] = sanitize_text_field( wp_unslash( $_GET[ $sort_key ] ) );
			}
		}
		echo '<form method="get" class="rip-filter-bar" role="search">';
		foreach ( $location as $name => $value ) {
			printf( '<input type="hidden" name="%s" value="%s" />', esc_attr( $name ), esc_attr( $value ) );
		}
	}

	/**
	 * Render one labelled control.
	 *
	 * @param string $id      Control id, also the label target.
	 * @param string $label   Visible label.
	 * @param string $control Escaped control markup.
	 * @param bool   $grow    Whether the field takes the remaining width.
	 * @return void
	 * @since  2.1.57
	 */
	public static function field( $id, $label, $control, $grow = false ) {
		printf(
			'<div class="rip-filter-bar__field%s"><label class="rip-filter-bar__label" for="%s">%s</label>%s</div>',
			$grow ? ' rip-filter-bar__field--grow' : '',
			esc_attr( $id ),
			esc_html( $label ),
			$control // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Control markup is escaped by the caller.
		);
	}

	/**
	 * Render the apply button, a reset link while a filter is active, and close the form.
	 *
	 * @param string[] $filter_keys Request keys the bar controls.
	 * @return void
	 * @since  2.1.57
	 */
	public static function close( array $filter_keys ) {
		$active = 0;
		foreach ( $filter_keys as $key ) {
			if ( ! empty( $_GET[ $key ] ) ) {
				++$active;
			}
		}
		echo '<div class="rip-filter-bar__actions">';
		if ( $active > 0 ) {
			printf(
				'<a class="rip-button rip-button--ghost" href="%s">%s</a>',
				esc_url( remove_query_arg( array_merge( $filter_keys, array( 'paged', 'filter_action' ) ) ) ),
				esc_html(
					sprintf(
					/* translators: %d: number of active filters */
						_n( 'Reset %d filter', 'Reset %d filters', $active, 'reportedip-hive' ),
						$active
					)
				)
			);
		}
		printf(
			'<button type="submit" name="filter_action" value="1" class="rip-button rip-button--primary">%s</button>',
			esc_html__( 'Apply filters', 'reportedip-hive' )
		);
		echo '</div></form>';
	}
}
