<?php
/**
 * Audit connector for pages and posts.
 *
 * Records the transitions a support case turns on: an entry was published,
 * taken offline, trashed, restored, deleted for good, or its URL slug was
 * changed. Everyday edits are not rows, and neither are autosaves,
 * revisions, auto-drafts or the internal post types the block editor and
 * the Customizer write on their own.
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
 * Content lifecycle capture.
 *
 * @since 2.1.62
 */
class ReportedIP_Hive_Audit_Connector_Content extends ReportedIP_Hive_Audit_Connector {

	/**
	 * Post types that never produce a row.
	 *
	 * @var string[]
	 */
	public const IGNORED_TYPES = array(
		'revision',
		'nav_menu_item',
		'attachment',
		'customize_changeset',
		'custom_css',
		'oembed_cache',
		'user_request',
		'wp_template',
		'wp_template_part',
		'wp_global_styles',
		'wp_navigation',
		'wp_font_family',
		'wp_font_face',
	);

	/**
	 * Hooks of this connector.
	 *
	 * @return array<string, array{0:string, 1:int, 2:int}>
	 * @since  2.1.62
	 */
	protected function hooks() {
		return array(
			'transition_post_status' => array( 'on_transition', 10, 3 ),
			'trashed_post'           => array( 'on_trashed', 10, 1 ),
			'untrashed_post'         => array( 'on_untrashed', 10, 1 ),
			'deleted_post'           => array( 'on_deleted', 10, 2 ),
			'post_updated'           => array( 'on_updated', 10, 3 ),
		);
	}

	/**
	 * Map a status transition to an audit action, or null for noise.
	 *
	 * Pure: the trash pair is handled by `trashed_post`/`untrashed_post`, a
	 * fresh entry starts as `new` or `auto-draft`, and only the visible side
	 * of a change matters (publish to draft is unpublished, draft to pending
	 * is nothing).
	 *
	 * @param string $old_status Previous status.
	 * @param string $new_status New status.
	 * @param string $post_type  Post type.
	 * @return string|null `published`, `unpublished` or null.
	 * @since  2.1.62
	 */
	public static function classify( $old_status, $new_status, $post_type ) {
		if ( in_array( (string) $post_type, self::IGNORED_TYPES, true ) ) {
			return null;
		}
		if ( $old_status === $new_status || in_array( 'trash', array( $old_status, $new_status ), true ) ) {
			return null;
		}
		$was_live = in_array( $old_status, array( 'publish', 'private', 'future' ), true );
		$is_live  = in_array( $new_status, array( 'publish', 'private', 'future' ), true );
		if ( ! $was_live && $is_live ) {
			return 'published';
		}
		if ( $was_live && ! $is_live ) {
			return 'unpublished';
		}
		return null;
	}

	/**
	 * Status transition.
	 *
	 * @param string  $new_status New status.
	 * @param string  $old_status Old status.
	 * @param WP_Post $post       Post.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_transition( $new_status, $old_status, $post ) {
		if ( ! $post instanceof WP_Post || ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) ) {
			return;
		}
		$action = self::classify( (string) $old_status, (string) $new_status, (string) $post->post_type );
		if ( null === $action || self::seen( 'content:' . $post->ID . ':' . $action ) ) {
			return;
		}
		$this->log(
			'content',
			$action,
			array(
				'post_type'  => (string) $post->post_type,
				'old_status' => (string) $old_status,
				'new_status' => (string) $new_status,
			),
			self::object_for( $post )
		);
	}

	/**
	 * Entry moved to the trash.
	 *
	 * @param int $post_id Post id.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_trashed( $post_id ) {
		$this->log_simple( 'trashed', $post_id );
	}

	/**
	 * Entry restored from the trash.
	 *
	 * @param int $post_id Post id.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_untrashed( $post_id ) {
		$this->log_simple( 'untrashed', $post_id );
	}

	/**
	 * Entry deleted for good. The post object is passed because the row is
	 * already gone when the hook fires.
	 *
	 * @param int          $post_id Post id.
	 * @param WP_Post|null $post    Deleted post (WP 5.5+).
	 * @return void
	 * @since  2.1.62
	 */
	public function on_deleted( $post_id, $post = null ) {
		if ( ! $post instanceof WP_Post || in_array( (string) $post->post_type, self::IGNORED_TYPES, true ) ) {
			return;
		}
		if ( 'auto-draft' === $post->post_status || self::seen( 'content:' . $post->ID . ':deleted' ) ) {
			return;
		}
		$this->log(
			'content',
			'deleted',
			array(
				'post_type' => (string) $post->post_type,
				'status'    => (string) $post->post_status,
			),
			self::object_for( $post )
		);
	}

	/**
	 * Slug change on save.
	 *
	 * @param int     $post_id Post id.
	 * @param WP_Post $after   Post after the update.
	 * @param WP_Post $before  Post before the update.
	 * @return void
	 * @since  2.1.62
	 */
	public function on_updated( $post_id, $after, $before ) {
		if ( ! $after instanceof WP_Post || ! $before instanceof WP_Post ) {
			return;
		}
		if ( in_array( (string) $after->post_type, self::IGNORED_TYPES, true ) ) {
			return;
		}
		if ( 'auto-draft' === $before->post_status || '' === (string) $before->post_name ) {
			return;
		}
		if ( 'trash' === $before->post_status || 'trash' === $after->post_status ) {
			return;
		}
		if ( (string) $before->post_name === (string) $after->post_name ) {
			return;
		}
		if ( self::seen( 'content:' . $post_id . ':slug:' . $after->post_name ) ) {
			return;
		}
		$this->log(
			'content',
			'slug_changed',
			array(
				'post_type' => (string) $after->post_type,
				'old_slug'  => (string) $before->post_name,
				'new_slug'  => (string) $after->post_name,
			),
			self::object_for( $after )
		);
	}

	/**
	 * Trash and untrash share one shape.
	 *
	 * @param string $action  Audit action.
	 * @param int    $post_id Post id.
	 * @return void
	 * @since  2.1.62
	 */
	private function log_simple( $action, $post_id ) {
		$post = get_post( (int) $post_id );
		if ( ! $post instanceof WP_Post || in_array( (string) $post->post_type, self::IGNORED_TYPES, true ) ) {
			return;
		}
		if ( in_array( (string) get_post_meta( $post->ID, '_wp_trash_meta_status', true ), array( 'auto-draft', 'new' ), true ) ) {
			return;
		}
		if ( self::seen( 'content:' . $post->ID . ':' . $action ) ) {
			return;
		}
		$this->log( 'content', $action, array( 'post_type' => (string) $post->post_type ), self::object_for( $post ) );
	}

	/**
	 * Object descriptor of a post.
	 *
	 * @param WP_Post $post Post.
	 * @return array{type:string, id:int, label:string}
	 * @since  2.1.62
	 */
	private static function object_for( $post ) {
		$title = trim( (string) $post->post_title );
		return array(
			'type'  => 'post',
			'id'    => (int) $post->ID,
			/* translators: %d: entry id */
			'label' => '' !== $title ? $title : sprintf( __( 'Entry #%d', 'reportedip-hive' ), (int) $post->ID ),
		);
	}
}
