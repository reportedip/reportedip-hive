<?php
/**
 * Canonical admin-notice renderer shared by every Hive backend banner.
 *
 * Collapses the two historical notice styles (design-system `rip-alert` and
 * raw WordPress `.notice`) into one BEM-classed primitive. The matching
 * stylesheet {@see assets/css/admin-notices.css} is self-contained and is
 * enqueued on every admin page so notices render identically regardless of
 * which screen `admin_notices` fires on — including pages where the heavy
 * design-system stylesheet is not loaded.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.0.1
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Static notice renderer plus the global stylesheet/script enqueue.
 *
 * @since 2.0.1
 */
final class ReportedIP_Hive_Admin_Notice {

	/**
	 * Wire the global asset enqueue. Idempotent.
	 *
	 * @return void
	 * @since  2.0.1
	 */
	public static function register_hooks() {
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'enqueue_assets' ), 100 );
	}

	/**
	 * Enqueue the self-contained notice stylesheet plus the dismiss handler on
	 * every admin page (single-site and network admin). No screen gate: notices
	 * can surface anywhere `admin_notices` fires.
	 *
	 * @return void
	 * @since  2.0.1
	 */
	public static function enqueue_assets() {
		wp_enqueue_style(
			'rip-admin-notices',
			REPORTEDIP_HIVE_PLUGIN_URL . 'assets/css/admin-notices.css',
			array(),
			REPORTEDIP_HIVE_VERSION
		);

		wp_enqueue_script(
			'rip-admin-notices',
			REPORTEDIP_HIVE_PLUGIN_URL . 'assets/js/admin-notices.js',
			array( 'jquery' ),
			REPORTEDIP_HIVE_VERSION,
			true
		);

		wp_localize_script(
			'rip-admin-notices',
			'reportedip_hive_notices',
			array(
				'ajax_url' => admin_url( 'admin-ajax.php' ),
				'nonce'    => wp_create_nonce( 'reportedip_hive_nonce' ),
			)
		);
	}

	/**
	 * Echo a notice from a normalised argument bag.
	 *
	 * @param array $args {
	 *     Notice definition. All keys optional.
	 *
	 *     @type string     $variant           One of info|warning|error|success. Default 'info'.
	 *     @type string     $title             Heading text (plain, escaped with esc_html).
	 *     @type string     $body              Body HTML (run through wp_kses_post).
	 *     @type string[]   $list_items        Bullet rows (each through wp_kses_post).
	 *     @type array[]    $checklist         Rows of { label:string, done:bool }.
	 *     @type array|null $primary_action    { label, url, target?, rel?, variant? }.
	 *     @type array[]    $secondary_actions Each { type:'link'|'form'|'button', label, ... }.
	 *     @type array|null $muted_link        { label, url }.
	 *     @type bool       $dismissible       Adds the WordPress `is-dismissible` X.
	 *     @type string     $data_notice_id    Enables the persistent AJAX dismiss path.
	 *     @type string     $extra_classes     Extra container classes (selector/test hooks).
	 * }
	 * @return void
	 * @since  2.0.1
	 */
	public static function render( array $args ) {
		$defaults = array(
			'variant'           => 'info',
			'title'             => '',
			'body'              => '',
			'list_items'        => array(),
			'checklist'         => array(),
			'primary_action'    => null,
			'secondary_actions' => array(),
			'muted_link'        => null,
			'dismissible'       => false,
			'data_notice_id'    => '',
			'extra_classes'     => '',
		);
		$args     = wp_parse_args( $args, $defaults );

		$variant = in_array( $args['variant'], array( 'info', 'warning', 'error', 'success' ), true )
			? $args['variant']
			: 'info';

		$classes = array( 'notice', 'rip-notice', 'rip-notice--' . $variant );
		if ( ! empty( $args['dismissible'] ) ) {
			$classes[] = 'is-dismissible';
		}
		$notice_id = (string) $args['data_notice_id'];
		if ( '' !== $notice_id ) {
			$classes[] = 'reportedip-dismissible';
		}
		if ( '' !== (string) $args['extra_classes'] ) {
			$classes[] = (string) $args['extra_classes'];
		}

		$has_actions = is_array( $args['primary_action'] )
			|| ! empty( $args['secondary_actions'] )
			|| is_array( $args['muted_link'] );
		?>
		<div class="<?php echo esc_attr( implode( ' ', $classes ) ); ?>"
			<?php if ( '' !== $notice_id ) : ?>
				data-notice-id="<?php echo esc_attr( $notice_id ); ?>"
			<?php endif; ?>
		>
			<?php if ( '' !== (string) $args['title'] ) : ?>
				<p class="rip-notice__title"><?php echo esc_html( $args['title'] ); ?></p>
			<?php endif; ?>

			<?php if ( '' !== (string) $args['body'] ) : ?>
				<div class="rip-notice__body"><?php echo wp_kses_post( $args['body'] ); ?></div>
			<?php endif; ?>

			<?php if ( ! empty( $args['list_items'] ) ) : ?>
				<ul class="rip-notice__list">
					<?php foreach ( $args['list_items'] as $item ) : ?>
						<li><?php echo wp_kses_post( $item ); ?></li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>

			<?php if ( ! empty( $args['checklist'] ) ) : ?>
				<ul class="rip-notice__checklist">
					<?php foreach ( $args['checklist'] as $item ) : ?>
						<li class="rip-notice__checklist-item rip-notice__checklist-item--<?php echo esc_attr( ! empty( $item['done'] ) ? 'done' : 'open' ); ?>">
							<span class="rip-notice__checklist-marker" aria-hidden="true"></span>
							<span class="rip-notice__checklist-label"><?php echo esc_html( isset( $item['label'] ) ? (string) $item['label'] : '' ); ?></span>
						</li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>

			<?php if ( $has_actions ) : ?>
				<div class="rip-notice__actions">
					<?php
					if ( is_array( $args['primary_action'] ) ) {
						self::render_link_action( $args['primary_action'], 'primary' );
					}
					foreach ( (array) $args['secondary_actions'] as $action ) {
						self::render_secondary_action( $action );
					}
					if ( is_array( $args['muted_link'] ) ) {
						self::render_muted_link( $args['muted_link'] );
					}
					?>
				</div>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Return a notice as a string (buffered {@see self::render()}).
	 *
	 * @param array $args See {@see self::render()}.
	 * @return string Fully escaped notice markup.
	 * @since  2.0.1
	 */
	public static function get( array $args ) {
		ob_start();
		self::render( $args );
		return (string) ob_get_clean();
	}

	/**
	 * Echo an anchor styled as a notice button.
	 *
	 * @param array  $action          { label, url, target?, rel?, variant? }.
	 * @param string $default_variant Fallback button variant.
	 * @return void
	 * @since  2.0.1
	 */
	private static function render_link_action( array $action, $default_variant ) {
		$variant = isset( $action['variant'] ) ? (string) $action['variant'] : $default_variant;
		$target  = isset( $action['target'] ) ? (string) $action['target'] : '';
		$rel     = isset( $action['rel'] ) ? (string) $action['rel'] : '';
		?>
		<a class="rip-notice__btn rip-notice__btn--<?php echo esc_attr( $variant ); ?>"
			href="<?php echo esc_url( isset( $action['url'] ) ? (string) $action['url'] : '' ); ?>"
			<?php if ( '' !== $target ) : ?>
				target="<?php echo esc_attr( $target ); ?>"
			<?php endif; ?>
			<?php if ( '' !== $rel ) : ?>
				rel="<?php echo esc_attr( $rel ); ?>"
			<?php endif; ?>
		>
			<?php echo esc_html( isset( $action['label'] ) ? (string) $action['label'] : '' ); ?>
		</a>
		<?php
	}

	/**
	 * Echo one secondary action (ghost link, POST form, or JS-bound button).
	 *
	 * @param array $action Action definition; `type` selects the shape.
	 * @return void
	 * @since  2.0.1
	 */
	private static function render_secondary_action( array $action ) {
		$type = isset( $action['type'] ) ? (string) $action['type'] : 'link';

		if ( 'form' === $type ) {
			$variant = isset( $action['variant'] ) ? (string) $action['variant'] : 'ghost';
			?>
			<form class="rip-notice__form" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="<?php echo esc_attr( isset( $action['form_action'] ) ? (string) $action['form_action'] : '' ); ?>" />
				<?php wp_nonce_field( isset( $action['nonce'] ) ? (string) $action['nonce'] : '' ); ?>
				<button type="submit" class="rip-notice__btn rip-notice__btn--<?php echo esc_attr( $variant ); ?>">
					<?php echo esc_html( isset( $action['label'] ) ? (string) $action['label'] : '' ); ?>
				</button>
			</form>
			<?php
			return;
		}

		if ( 'button' === $type ) {
			$variant = isset( $action['variant'] ) ? (string) $action['variant'] : 'secondary';
			$id      = isset( $action['id'] ) ? (string) $action['id'] : '';
			?>
			<button type="button" class="rip-notice__btn rip-notice__btn--<?php echo esc_attr( $variant ); ?>"
				<?php if ( '' !== $id ) : ?>
					id="<?php echo esc_attr( $id ); ?>"
				<?php endif; ?>
			>
				<?php echo esc_html( isset( $action['label'] ) ? (string) $action['label'] : '' ); ?>
			</button>
			<?php
			return;
		}

		self::render_link_action( $action, 'ghost' );
	}

	/**
	 * Echo a de-emphasised text link (e.g. "Don't show this again").
	 *
	 * @param array $link { label, url }.
	 * @return void
	 * @since  2.0.1
	 */
	private static function render_muted_link( array $link ) {
		?>
		<a class="rip-notice__link-muted" href="<?php echo esc_url( isset( $link['url'] ) ? (string) $link['url'] : '' ); ?>">
			<?php echo esc_html( isset( $link['label'] ) ? (string) $link['label'] : '' ); ?>
		</a>
		<?php
	}
}
