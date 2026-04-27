<?php
/**
 * Blocked-page template — rendered when the request is rejected.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$reportedip_hive_block_context = isset( $reportedip_hive_block_context ) && is_string( $reportedip_hive_block_context )
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
?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title><?php echo esc_html( $reportedip_hive_block_strings['doc_title'] ); ?></title>
	<style>
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
			background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
			margin: 0;
			padding: 0;
			min-height: 100vh;
			display: flex;
			align-items: center;
			justify-content: center;
		}
		
		.blocked-container {
			background: white;
			border-radius: 10px;
			box-shadow: 0 20px 40px rgba(0,0,0,0.1);
			padding: 40px;
			max-width: 500px;
			text-align: center;
			margin: 20px;
		}
		
		.blocked-icon {
			font-size: 64px;
			color: #e74c3c;
			margin-bottom: 20px;
		}
		
		.blocked-title {
			color: #2c3e50;
			font-size: 28px;
			font-weight: 600;
			margin-bottom: 15px;
		}
		
		.blocked-message {
			color: #7f8c8d;
			font-size: 16px;
			line-height: 1.6;
			margin-bottom: 30px;
		}
		
		.blocked-details {
			background: #f8f9fa;
			border-radius: 5px;
			padding: 20px;
			margin-bottom: 30px;
			text-align: left;
		}
		
		.blocked-details h4 {
			color: #2c3e50;
			margin-top: 0;
			margin-bottom: 15px;
			font-size: 16px;
		}
		
		.blocked-details p {
			color: #7f8c8d;
			margin: 5px 0;
			font-size: 14px;
		}
		
		.blocked-actions {
			display: flex;
			gap: 15px;
			justify-content: center;
			flex-wrap: wrap;
		}
		
		.btn {
			padding: 12px 24px;
			border: none;
			border-radius: 5px;
			font-size: 14px;
			font-weight: 500;
			text-decoration: none;
			cursor: pointer;
			transition: all 0.3s ease;
		}
		
		.btn-primary {
			background: #3498db;
			color: white;
		}
		
		.btn-primary:hover {
			background: #2980b9;
			transform: translateY(-2px);
		}
		
		.btn-secondary {
			background: #95a5a6;
			color: white;
		}
		
		.btn-secondary:hover {
			background: #7f8c8d;
			transform: translateY(-2px);
		}
		
		.footer-text {
			margin-top: 30px;
			font-size: 12px;
			color: #bdc3c7;
		}
		
		@media (max-width: 600px) {
			.blocked-container {
				padding: 30px 20px;
				margin: 10px;
			}
			
			.blocked-title {
				font-size: 24px;
			}
			
			.blocked-actions {
				flex-direction: column;
			}
		}
	</style>
</head>
<body>
	<div class="blocked-container">
		<div class="blocked-icon">🚫</div>
		
		<h1 class="blocked-title"><?php echo esc_html( $reportedip_hive_block_strings['title'] ); ?></h1>

		<p class="blocked-message">
			<?php echo esc_html( $reportedip_hive_block_strings['message'] ); ?>
		</p>

		<div class="blocked-details">
			<h4><?php esc_html_e( 'Block Information:', 'reportedip-hive' ); ?></h4>
			<p><strong><?php esc_html_e( 'Your IP:', 'reportedip-hive' ); ?></strong> <?php echo esc_html( ReportedIP_Hive::get_client_ip() ); ?></p>
			<p><strong><?php esc_html_e( 'Time:', 'reportedip-hive' ); ?></strong> <?php echo esc_html( gmdate( 'Y-m-d H:i:s T' ) ); ?></p>
			<p><strong><?php esc_html_e( 'Reason:', 'reportedip-hive' ); ?></strong> <?php echo esc_html( $reportedip_hive_block_strings['reason'] ); ?></p>
		</div>

		<div class="blocked-actions">
			<?php
			$contact_url = get_option( 'reportedip_hive_blocked_page_contact_url', '' );
			if ( ! empty( $contact_url ) ) :
				?>
			<a href="<?php echo esc_url( $contact_url ); ?>" class="btn btn-primary">
				Contact Administrator
			</a>
			<?php else : ?>
			<p>If you believe this is an error, please contact the site administrator.</p>
			<?php endif; ?>
			<a href="javascript:history.back()" class="btn btn-secondary">
				Go Back
			</a>
		</div>
		
		<p class="footer-text">
			This security measure is powered by ReportedIP Hive.<br>
			If you believe this is an error, please contact the site administrator.
		</p>
	</div>
</body>
</html>
