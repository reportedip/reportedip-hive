<?php
/**
 * Build one form per supported form plugin, plus the page that renders it.
 *
 * The adapter spec needs a Contact Form 7, a Formidable, an Elementor, an
 * Ultimate Member and a Gravity Forms form that exist on every machine the
 * suite runs on, so it creates them here rather than relying on whatever the
 * stack happens to hold.
 * Idempotent: a second run finds what the first one made and changes nothing.
 * A plugin that is not installed is skipped and reports an id of zero, which
 * is how the spec knows to skip its cases.
 *
 * Executed inside the WordPress container through `wp eval-file`, the same way
 * the WebAuthn and reset-flow fixtures are.
 *
 * Echoes one line of `key=value` pairs the spec reads back.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\E2E
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @since      2.1.58
 */

/**
 * Create or update a page holding one shortcode.
 *
 * @param string $slug    Page slug.
 * @param string $title   Page title.
 * @param string $content Page content.
 * @return int Page id.
 */
function rip_e2e_page( $slug, $title, $content ) {
	$existing = get_posts(
		array(
			'name'        => $slug,
			'post_type'   => 'page',
			'post_status' => 'any',
			'numberposts' => 1,
		)
	);

	if ( $existing ) {
		wp_update_post(
			array(
				'ID'           => $existing[0]->ID,
				'post_content' => $content,
			)
		);

		return (int) $existing[0]->ID;
	}

	return (int) wp_insert_post(
		array(
			'post_title'   => $title,
			'post_name'    => $slug,
			'post_type'    => 'page',
			'post_status'  => 'publish',
			'post_content' => $content,
		)
	);
}

$rip_cf7 = 0;

if ( class_exists( 'WPCF7_ContactForm' ) ) {
	$rip_found = get_posts(
		array(
			'name'        => 'rip-e2e-cf7',
			'post_type'   => 'wpcf7_contact_form',
			'post_status' => 'any',
			'numberposts' => 1,
		)
	);

	if ( $rip_found ) {
		$rip_cf7 = (int) $rip_found[0]->ID;
	} else {
		$rip_form = WPCF7_ContactForm::get_template( array( 'title' => 'RIP E2E CF7' ) );
		$rip_form->set_properties(
			array(
				'form' => "[text* your-name]\n[email* your-email]\n[textarea your-message]\n[submit \"Send\"]",
				'mail' => array(
					'subject'            => 'RIP E2E CF7',
					'sender'             => 'wordpress@localhost',
					'recipient'          => 'e2e@example.com',
					'body'               => "[your-name]\n[your-email]\n[your-message]",
					'additional_headers' => '',
					'attachments'        => '',
					'use_html'           => 0,
					'exclude_blank'      => 0,
				),
			)
		);
		$rip_cf7 = (int) $rip_form->save();
		wp_update_post(
			array(
				'ID'        => $rip_cf7,
				'post_name' => 'rip-e2e-cf7',
			)
		);
	}

	rip_e2e_page( 'rip-e2e-cf7-page', 'RIP E2E CF7 Page', '[contact-form-7 id="' . $rip_cf7 . '"]' );
}

$rip_frm  = 0;
$rip_name = 0;
$rip_text = 0;

if ( class_exists( 'FrmForm' ) ) {
	global $wpdb;

	if ( ! $wpdb->get_var( "SHOW TABLES LIKE '{$wpdb->prefix}frm_forms'" ) && class_exists( 'FrmMigrate' ) ) {
		$rip_migrate = new FrmMigrate();
		$rip_migrate->upgrade();
	}

	$rip_frm = (int) FrmForm::get_id_by_key( 'ripe2efrm' );

	if ( ! $rip_frm ) {
		$rip_frm = (int) FrmForm::create(
			array(
				'form_key'    => 'ripe2efrm',
				'name'        => 'RIP E2E Formidable',
				'description' => '',
				'status'      => 'published',
				'options'     => array(
					'submit_value' => 'Send',
					'ajax_load'    => 0,
				),
			)
		);
		FrmField::create(
			array(
				'form_id'     => $rip_frm,
				'field_key'   => 'ripe2efrmname',
				'type'        => 'text',
				'name'        => 'Name',
				'required'    => 1,
				'field_order' => 1,
			)
		);
		FrmField::create(
			array(
				'form_id'     => $rip_frm,
				'field_key'   => 'ripe2efrmmsg',
				'type'        => 'textarea',
				'name'        => 'Message',
				'required'    => 0,
				'field_order' => 2,
			)
		);
	}

	$rip_name = (int) FrmField::get_id_by_key( 'ripe2efrmname' );
	$rip_text = (int) FrmField::get_id_by_key( 'ripe2efrmmsg' );

	rip_e2e_page( 'rip-e2e-frm-page', 'RIP E2E Formidable Page', '[formidable id="' . $rip_frm . '"]' );
}

$rip_elementor = 0;

if ( class_exists( '\ElementorPro\Plugin' ) ) {
	$rip_elementor = rip_e2e_page( 'rip-e2e-elementor-page', 'RIP E2E Elementor Page', '' );
	$rip_data      = array(
		array(
			'id'       => 'ripsec01',
			'elType'   => 'section',
			'settings' => new stdClass(),
			'elements' => array(
				array(
					'id'       => 'ripcol01',
					'elType'   => 'column',
					'settings' => array( '_column_size' => 100 ),
					'elements' => array(
						array(
							'id'         => 'ripfrm01',
							'elType'     => 'widget',
							'widgetType' => 'form',
							'settings'   => array(
								'form_name'      => 'RIP E2E Elementor',
								'form_fields'    => array(
									array(
										'custom_id'   => 'name',
										'field_type'  => 'text',
										'field_label' => 'Name',
										'required'    => 'true',
										'_id'         => 'ripf1',
									),
									array(
										'custom_id'   => 'message',
										'field_type'  => 'textarea',
										'field_label' => 'Message',
										'_id'         => 'ripf2',
									),
								),
								'submit_actions' => array( 'email' ),
								'email_to'       => 'e2e@example.com',
							),
							'elements'   => array(),
						),
					),
				),
			),
		),
	);

	update_post_meta( $rip_elementor, '_elementor_edit_mode', 'builder' );
	update_post_meta( $rip_elementor, '_elementor_template_type', 'wp-page' );
	update_post_meta( $rip_elementor, '_elementor_version', defined( 'ELEMENTOR_VERSION' ) ? ELEMENTOR_VERSION : '3.34.0' );
	update_post_meta( $rip_elementor, '_elementor_data', wp_slash( (string) wp_json_encode( $rip_data ) ) );
	delete_post_meta( $rip_elementor, '_elementor_element_cache' );
}

$rip_um_register = 0;
$rip_um_login    = 0;

if ( function_exists( 'UM' ) ) {
	if ( ! get_option( 'um_is_installed' ) ) {
		wp_set_current_user( 1 );
		UM()->setup()->run_setup();
	}

	$rip_um_register = (int) UM()->query()->find_post_id( 'um_form', '_um_core', 'register' );
	$rip_um_login    = (int) UM()->query()->find_post_id( 'um_form', '_um_core', 'login' );

	rip_e2e_page( 'rip-e2e-um-register', 'RIP E2E Ultimate Member register', '[ultimatemember form_id="' . $rip_um_register . '"]' );
	rip_e2e_page( 'rip-e2e-um-login', 'RIP E2E Ultimate Member login', '[ultimatemember form_id="' . $rip_um_login . '"]' );
	rip_e2e_page( 'rip-e2e-um-password', 'RIP E2E Ultimate Member password', '[ultimatemember_password]' );
}

$rip_gravity = 0;

if ( class_exists( 'GFAPI' ) ) {
	foreach ( GFAPI::get_forms( true, false ) as $rip_form ) {
		if ( 'RIP E2E Gravity' === rgar( $rip_form, 'title' ) ) {
			$rip_gravity = (int) $rip_form['id'];
		}
	}

	if ( ! $rip_gravity ) {
		$rip_created = GFAPI::add_form(
			array(
				'title'          => 'RIP E2E Gravity',
				'enableHoneypot' => false,
				'is_active'      => '1',
				'button'         => array(
					'type' => 'text',
					'text' => 'Send',
				),
				'fields'         => array(
					array(
						'id'         => 1,
						'type'       => 'text',
						'label'      => 'Name',
						'isRequired' => true,
					),
					array(
						'id'    => 2,
						'type'  => 'textarea',
						'label' => 'Message',
					),
				),
			)
		);
		$rip_gravity = is_wp_error( $rip_created ) ? 0 : (int) $rip_created;
	}

	rip_e2e_page( 'rip-e2e-gravity-page', 'RIP E2E Gravity Page', '[gravityform id="' . $rip_gravity . '" ajax="true" title="false" description="false"]' );
	rip_e2e_page( 'rip-e2e-gravity-ajax-page', 'RIP E2E Gravity AJAX Page', '[gravityform id="' . $rip_gravity . '" title="false" description="false"]' );

	/*
	 * A second Gravity Forms form with a page break, so the multi-step path
	 * can be driven: Name on page one, Message on page two, submitted over
	 * AJAX. The plugin only judges the last page, this proves it lets a real
	 * multi-step submission through and refuses a bot on the final step.
	 */
	$rip_gravity_multi = 0;
	foreach ( GFAPI::get_forms( true, false ) as $rip_form ) {
		if ( 'RIP E2E Gravity Multi' === rgar( $rip_form, 'title' ) ) {
			$rip_gravity_multi = (int) $rip_form['id'];
		}
	}

	if ( ! $rip_gravity_multi ) {
		$rip_multi = GFAPI::add_form(
			array(
				'title'          => 'RIP E2E Gravity Multi',
				'enableHoneypot' => false,
				'is_active'      => '1',
				'pagination'     => array(
					'type'  => 'percentage',
					'pages' => array( 'Schritt 1', 'Schritt 2' ),
				),
				'button'         => array(
					'type' => 'text',
					'text' => 'Send',
				),
				'fields'         => array(
					array(
						'id'         => 1,
						'type'       => 'text',
						'label'      => 'Name',
						'isRequired' => true,
						'pageNumber' => 1,
					),
					array(
						'id'         => 2,
						'type'       => 'page',
						'label'      => 'Seitenumbruch',
						'nextButton' => array(
							'type' => 'text',
							'text' => 'Weiter',
						),
					),
					array(
						'id'         => 3,
						'type'       => 'textarea',
						'label'      => 'Message',
						'pageNumber' => 2,
					),
				),
			)
		);
		$rip_gravity_multi = is_wp_error( $rip_multi ) ? 0 : (int) $rip_multi;
	}

	rip_e2e_page( 'rip-e2e-gravity-multi-page', 'RIP E2E Gravity Multi Page', '[gravityform id="' . $rip_gravity_multi . '" ajax="true" title="false" description="false"]' );
}

echo 'cf7=' . (int) $rip_cf7
	. ' frm=' . (int) $rip_frm
	. ' frm_name=' . (int) $rip_name
	. ' frm_text=' . (int) $rip_text
	. ' elementor=' . (int) $rip_elementor
	. ' um_register=' . (int) $rip_um_register
	. ' um_login=' . (int) $rip_um_login
	. ' gravity=' . (int) $rip_gravity
	. ' gravity_multi=' . ( isset( $rip_gravity_multi ) ? (int) $rip_gravity_multi : 0 );
