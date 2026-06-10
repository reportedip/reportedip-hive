<?php
/**
 * Blocked-page template — rendered when the request is rejected.
 *
 * Standalone HTML response (the front-end theme and the design-system
 * stylesheet are not loaded on a short-circuited request), so the styling is
 * inlined but uses the ReportedIP design-system palette with sharp-edged
 * containers. A correlatable reference code (see ReportedIP_Hive_Block_Ref) is
 * shown to the visitor and emitted as the `X-RIP-Ref` header so a wrongly
 * blocked user can quote one short string the admin can match without exposing
 * any personal data.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$reportedip_hive_block_context = isset( $reportedip_hive_block_context ) && is_string( $reportedip_hive_block_context ) && '' !== $reportedip_hive_block_context
	? $reportedip_hive_block_context
	: 'ip_block';

$reportedip_hive_block_strings = 'hide_login' === $reportedip_hive_block_context
	? array(
		'doc_title' => __( 'Page not available', 'reportedip-hive' ),
		'title'     => __( 'Page not available', 'reportedip-hive' ),
		'message'   => __( 'This endpoint has been disabled by the site administrator.', 'reportedip-hive' ),
		'reason'    => __( 'Login endpoint protected', 'reportedip-hive' ),
	)
	: array(
		'doc_title' => __( 'Access Denied - IP Blocked', 'reportedip-hive' ),
		'title'     => __( 'Access Denied', 'reportedip-hive' ),
		'message'   => __( 'Your IP address has been temporarily blocked due to suspicious activity detected on this website.', 'reportedip-hive' ),
		'reason'    => __( 'Security policy violation', 'reportedip-hive' ),
	);

$reportedip_hive_ref = ReportedIP_Hive::block_ref_code( $reportedip_hive_block_context );
if ( ! headers_sent() ) {
	header( 'X-RIP-Ref: ' . $reportedip_hive_ref );
}

$reportedip_hive_contact_url = get_option( 'reportedip_hive_blocked_page_contact_url', '' );
?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title><?php echo esc_html( $reportedip_hive_block_strings['doc_title'] ); ?></title>
	<style>
		:root {
			--rip-primary: #4F46E5;
			--rip-primary-dark: #3730A3;
			--rip-danger: #EF4444;
			--rip-gray-50: #F9FAFB;
			--rip-gray-200: #E5E7EB;
			--rip-gray-500: #6B7280;
			--rip-gray-700: #374151;
			--rip-gray-900: #111827;
		}
		* { box-sizing: border-box; }
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
			background: var(--rip-gray-50);
			color: var(--rip-gray-700);
			margin: 0;
			padding: 24px;
			min-height: 100vh;
			display: flex;
			align-items: center;
			justify-content: center;
		}
		.rip-blocked {
			background: #fff;
			border: 1px solid var(--rip-gray-200);
			box-shadow: 0 10px 30px rgba(17, 24, 39, 0.08);
			padding: 40px;
			max-width: 480px;
			width: 100%;
			text-align: center;
		}
		.rip-blocked__icon {
			width: 56px;
			height: 56px;
			margin: 0 auto 20px;
			color: var(--rip-danger);
		}
		.rip-blocked__icon svg { width: 100%; height: 100%; display: block; }
		.rip-blocked__title {
			color: var(--rip-gray-900);
			font-size: 26px;
			font-weight: 600;
			margin: 0 0 12px;
		}
		.rip-blocked__message {
			color: var(--rip-gray-500);
			font-size: 15px;
			line-height: 1.6;
			margin: 0 0 28px;
		}
		.rip-blocked__details {
			background: var(--rip-gray-50);
			border: 1px solid var(--rip-gray-200);
			padding: 18px 20px;
			margin: 0 0 28px;
			text-align: left;
		}
		.rip-blocked__details h2 {
			color: var(--rip-gray-900);
			margin: 0 0 12px;
			font-size: 14px;
			text-transform: uppercase;
			letter-spacing: 0.04em;
		}
		.rip-blocked__details p {
			color: var(--rip-gray-500);
			margin: 6px 0;
			font-size: 14px;
		}
		.rip-blocked__details strong { color: var(--rip-gray-700); }
		.rip-blocked__ref {
			font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
			color: var(--rip-gray-900);
		}
		.rip-blocked__actions {
			display: flex;
			gap: 12px;
			justify-content: center;
			flex-wrap: wrap;
		}
		.rip-button {
			display: inline-block;
			padding: 11px 22px;
			border: 1px solid transparent;
			font-size: 14px;
			font-weight: 500;
			text-decoration: none;
			cursor: pointer;
		}
		.rip-button--primary { background: var(--rip-primary); color: #fff; }
		.rip-button--primary:hover { background: var(--rip-primary-dark); }
		.rip-button--secondary { background: #fff; color: var(--rip-gray-700); border-color: var(--rip-gray-200); }
		.rip-button--secondary:hover { background: var(--rip-gray-50); }
		.rip-blocked__footer {
			margin: 28px 0 0;
			font-size: 12px;
			color: var(--rip-gray-500);
		}
		@media (max-width: 600px) {
			.rip-blocked { padding: 28px 20px; }
			.rip-blocked__title { font-size: 22px; }
			.rip-blocked__actions { flex-direction: column; }
		}
	</style>
</head>
<body>
	<div class="rip-blocked">
		<div class="rip-blocked__icon" aria-hidden="true">
			<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg">
				<path d="M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z"/>
				<line x1="9" y1="9" x2="15" y2="15"/>
				<line x1="15" y1="9" x2="9" y2="15"/>
			</svg>
		</div>

		<h1 class="rip-blocked__title"><?php echo esc_html( $reportedip_hive_block_strings['title'] ); ?></h1>

		<p class="rip-blocked__message">
			<?php echo esc_html( $reportedip_hive_block_strings['message'] ); ?>
		</p>

		<div class="rip-blocked__details">
			<h2><?php esc_html_e( 'Block information', 'reportedip-hive' ); ?></h2>
			<p><strong><?php esc_html_e( 'Your IP:', 'reportedip-hive' ); ?></strong> <?php echo esc_html( ReportedIP_Hive::get_client_ip() ); ?></p>
			<p><strong><?php esc_html_e( 'Time:', 'reportedip-hive' ); ?></strong> <?php echo esc_html( gmdate( 'Y-m-d H:i:s T' ) ); ?></p>
			<p><strong><?php esc_html_e( 'Reason:', 'reportedip-hive' ); ?></strong> <?php echo esc_html( $reportedip_hive_block_strings['reason'] ); ?></p>
			<p><strong><?php esc_html_e( 'Reference:', 'reportedip-hive' ); ?></strong> <span class="rip-blocked__ref"><?php echo esc_html( $reportedip_hive_ref ); ?></span></p>
		</div>

		<div class="rip-blocked__actions">
			<?php if ( ! empty( $reportedip_hive_contact_url ) ) : ?>
			<a href="<?php echo esc_url( $reportedip_hive_contact_url ); ?>" class="rip-button rip-button--primary">
				<?php esc_html_e( 'Contact administrator', 'reportedip-hive' ); ?>
			</a>
			<?php endif; ?>
			<a href="javascript:history.back()" class="rip-button rip-button--secondary">
				<?php esc_html_e( 'Go back', 'reportedip-hive' ); ?>
			</a>
		</div>

		<p class="rip-blocked__footer">
			<?php esc_html_e( 'If you believe this is an error, please contact the site administrator and quote the reference above.', 'reportedip-hive' ); ?>
		</p>
	</div>
</body>
</html>
