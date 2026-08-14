<?php
/**
 * Unified email template for ReportedIP Hive.
 *
 * Variables expected (all populated by the Mailer):
 *
 * @var array $context {
 *     @type string $site_name        Site name (already decoded).
 *     @type string $site_url         Site home URL.
 *     @type string $greeting         Optional greeting line (e.g. "Hello Patrick,"), already escaped.
 *     @type string $intro_html       Intro paragraph, already escaped.
 *     @type string $main_block_html  Main content block, raw HTML (caller-controlled).
 *     @type array  $cta              Optional ['label' => string, 'url' => string].
 *     @type array  $security_notice  Optional ['ip' => string, 'timestamp' => string].
 *     @type string $disclaimer       Optional final-line disclaimer, already escaped.
 * }
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template-scoped locals, not globals; the file is included from ReportedIP_Hive_Mailer with $context already in scope.
$site_name       = isset( $context['site_name'] ) ? (string) $context['site_name'] : '';
$site_url        = isset( $context['site_url'] ) ? (string) $context['site_url'] : '';
$greeting        = isset( $context['greeting'] ) ? (string) $context['greeting'] : '';
$intro_html      = isset( $context['intro_html'] ) ? (string) $context['intro_html'] : '';
$main_block_html = isset( $context['main_block_html'] ) ? (string) $context['main_block_html'] : '';
$cta             = isset( $context['cta'] ) && is_array( $context['cta'] ) ? $context['cta'] : array();
$security_notice = isset( $context['security_notice'] ) && is_array( $context['security_notice'] ) ? $context['security_notice'] : array();
$disclaimer      = isset( $context['disclaimer'] ) ? (string) $context['disclaimer'] : '';
// phpcs:enable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
?>
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#F9FAFB;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#F9FAFB;padding:32px 16px;">
<tr><td align="center">
<table role="presentation" width="480" cellpadding="0" cellspacing="0" bgcolor="#ffffff" style="background:#ffffff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,0.1);overflow:hidden;max-width:480px;">
	<!-- Header -->
	<?php
	/*
	 * Header background: bgcolor attribute + background-color are the only reliable
	 * carriers. GMX Webmail and Outlook for Android strip `linear-gradient()`, which
	 * used to leave white text on a white cell (invisible title, and SpamAssassin
	 * HTML_FONT_LOW_CONTRAST). The gradient stays as a progressive enhancement.
	 * Inline SVG is not rendered by GMX/Outlook either, so the header is text-only.
	 */
	?>
	<tr><td bgcolor="#4F46E5" style="background-color:#4F46E5;background-image:linear-gradient(135deg,#4F46E5,#7C3AED);padding:24px 32px;text-align:center;">
		<span style="color:#ffffff;font-size:18px;font-weight:600;"><?php echo esc_html( $site_name ); ?></span>
	</td></tr>
	<!-- Body -->
	<tr><td style="padding:32px;">
		<?php if ( '' !== $greeting ) : ?>
		<p style="margin:0 0 8px;font-size:16px;font-weight:600;color:#111827;">
			<?php echo esc_html( $greeting ); ?>
		</p>
		<?php endif; ?>

		<?php if ( '' !== $intro_html ) : ?>
		<p style="margin:0 0 24px;font-size:14px;color:#6B7280;line-height:1.6;">
			<?php echo wp_kses_post( $intro_html ); ?>
		</p>
		<?php endif; ?>

		<?php if ( '' !== $main_block_html ) : ?>
			<?php echo wp_kses_post( $main_block_html ); ?>
		<?php endif; ?>

		<?php if ( ! empty( $cta['label'] ) && ! empty( $cta['url'] ) ) : ?>
			<?php /* Table + bgcolor, so the button keeps its indigo fill in Outlook/GMX; a white label on a stripped background would be unreadable. */ ?>
		<table role="presentation" cellpadding="0" cellspacing="0" style="margin:24px auto;"><tr>
			<td bgcolor="#4F46E5" style="background-color:#4F46E5;border-radius:6px;">
				<a href="<?php echo esc_url( $cta['url'] ); ?>" style="display:inline-block;padding:12px 28px;color:#ffffff;text-decoration:none;font-size:14px;font-weight:600;">
					<?php echo esc_html( $cta['label'] ); ?>
				</a>
			</td>
		</tr></table>
		<?php endif; ?>

		<?php if ( ! empty( $security_notice ) ) : ?>
		<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#FEF3C7;border-radius:8px;margin:0 0 24px;">
		<tr><td style="padding:16px;">
			<p style="margin:0 0 4px;font-size:13px;font-weight:600;color:#92400E;">
				<?php esc_html_e( 'Security notice', 'reportedip-hive' ); ?>
			</p>
			<p style="margin:0;font-size:12px;color:#92400E;line-height:1.5;">
				<?php
				printf(
					/* translators: 1: IP address, 2: timestamp */
					esc_html__( 'Recorded for your security: IP %1$s at %2$s. If this wasn\'t you, please update your password and review your recent sessions.', 'reportedip-hive' ),
					'<strong>' . esc_html( (string) ( $security_notice['ip'] ?? '' ) ) . '</strong>',
					esc_html( (string) ( $security_notice['timestamp'] ?? '' ) )
				);
				?>
			</p>
		</td></tr>
		</table>
		<?php endif; ?>

		<?php if ( '' !== $disclaimer ) : ?>
		<p style="margin:0;font-size:12px;color:#9CA3AF;line-height:1.5;">
			<?php echo esc_html( $disclaimer ); ?>
		</p>
		<?php endif; ?>
	</td></tr>
	<!-- Footer -->
	<tr><td style="padding:16px 32px;background:#F9FAFB;border-top:1px solid #E5E7EB;text-align:center;">
		<p style="margin:0 0 6px;font-size:11px;color:#6B7280;">
			<?php
			printf(
				/* translators: %s: site link */
				esc_html__( 'Protected by ReportedIP Hive on %s', 'reportedip-hive' ),
				'<a href="' . esc_url( $site_url ) . '" style="color:#4F46E5;text-decoration:none;">' . esc_html( $site_name ) . '</a>'
			);
			?>
		</p>
		<p style="margin:0;font-size:11px;color:#6B7280;">
			<?php
			printf(
				/* translators: 1: opening link tag, 2: closing link tag */
				esc_html__( 'This message is protected by %1$sReportedIP%2$s — Open Threat Intelligence for a Safer Internet.', 'reportedip-hive' ),
				'<a href="https://reportedip.com/" style="color:#4F46E5;text-decoration:none;" target="_blank" rel="noopener">',
				'</a>'
			);
			?>
		</p>
	</td></tr>
</table>
</td></tr>
</table>
</body>
</html>
