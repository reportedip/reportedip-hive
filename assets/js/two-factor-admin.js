/**
 * ReportedIP Hive — Two-Factor Admin Script.
 *
 * jQuery-based (consistent with existing admin.js).
 * Handles TOTP setup, recovery codes, and trusted device management.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     1.3.0
 */

( function ( $ ) {
	'use strict';

	var config = window.reportedip2faAdmin || {};

	/**
	 * HTML-escape a value for safe interpolation into innerHTML/.html() strings.
	 */
	function escapeHtml( value ) {
		if ( value === null || value === undefined ) {
			return '';
		}
		return String( value )
			.replace( /&/g, '&amp;' )
			.replace( /</g, '&lt;' )
			.replace( />/g, '&gt;' )
			.replace( /"/g, '&quot;' )
			.replace( /'/g, '&#39;' );
	}

	$( document ).ready( function () {
		initSetupButtons();
		initDisableButton();
		initRecoveryRegenerate();
		initDeviceRevocation();
	} );

	var NOTICE_AUTODISMISS_MS = 6000;

	/**
	 * Display a non-blocking error notice on the profile page.
	 *
	 * Equivalent in spirit to ReportedIPAdmin.showNotification, but admin.js is
	 * not enqueued on profile.php / user-edit.php — so we render a small
	 * WordPress-style notice ourselves. Announces via wp.a11y.speak when available.
	 *
	 * @param {string} message Plain-text message.
	 */
	function notifyError( message ) {
		var safe = String( message || '' );
		if ( window.wp && window.wp.a11y && typeof window.wp.a11y.speak === 'function' ) {
			window.wp.a11y.speak( safe, 'assertive' );
		}
		var $notice = $( '<div class="notice notice-error is-dismissible"><p></p></div>' );
		$notice.find( 'p' ).text( safe );
		var $target = $( '.wrap > h1, .wrap > h2' ).first();
		if ( $target.length ) {
			$target.after( $notice );
		} else {
			$( '.wrap' ).first().prepend( $notice );
		}
		setTimeout( function () {
			$notice.fadeOut( 300, function () {
				$( this ).remove();
			} );
		}, NOTICE_AUTODISMISS_MS );
	}

	/**
	 * Build HTML grid for recovery codes.
	 *
	 * @param {Array} codes Recovery code strings.
	 * @return {string} HTML for the code grid.
	 */
	function buildRecoveryCodesHtml( codes ) {
		var html = '';
		for ( var i = 0; i < codes.length; i++ ) {
			html += '<div class="rip-2fa-recovery-codes__code">' + escapeHtml( codes[ i ] ) + '</div>';
		}
		return html;
	}

	/**
	 * Setup buttons (TOTP and Email).
	 */
	function initSetupButtons() {
		$( '#rip-2fa-setup-totp' ).on( 'click', function () {
			startTotpSetup();
		} );

		$( '#rip-2fa-setup-email' ).on( 'click', function () {
			startEmailSetup();
		} );
	}

	/**
	 * TOTP setup flow.
	 */
	function startTotpSetup() {
		var $container = $( '#rip-2fa-setup-flow' );
		var $buttons = $( '#rip-2fa-setup-container' );

		$buttons.hide();
		$container.show().html( '<p>' + config.strings.scanQrCode + '</p><div class="rip-2fa-setup__qr"><div id="rip-2fa-qr-target"></div><p class="description">' + config.strings.enterCode + '</p></div><p style="text-align:center; color: #6B7280;">…</p>' );

		$.post( config.ajaxUrl, {
			action: 'reportedip_hive_2fa_setup_totp',
			nonce: config.nonce,
			user_id: config.userId,
		}, function ( response ) {
			if ( ! response.success ) {
				$container.html( '<div class="notice notice-error"><p>' + escapeHtml( response.data ? response.data.message : ( config.strings.error || 'Error' ) ) + '</p></div>' );
				$buttons.show();
				return;
			}

			var uri = response.data.uri;
			var secret = response.data.secret;

			// Build QR + verification form
			var html = '<div class="rip-2fa-setup__qr">';
			html += '<div id="rip-2fa-qr-canvas"></div>';
			html += '<p class="rip-2fa-setup__secret" title="Manual key">' + escapeHtml( secret ) + '</p>';
			html += '</div>';
			html += '<div style="text-align: center; margin-top: 16px;">';
			html += '<p>' + config.strings.enterCode + '</p>';
			html += '<input type="text" id="rip-2fa-confirm-code" class="rip-2fa-challenge__input" style="max-width: 200px; margin: 8px auto;" maxlength="6" inputmode="numeric" pattern="[0-9]{6}" placeholder="000000" />';
			html += '<br><button type="button" class="button button-primary" id="rip-2fa-confirm-btn" style="margin-top: 8px;">' + ( config.strings.confirm || 'Confirm' ) + '</button>';
			html += '<button type="button" class="button" id="rip-2fa-cancel-btn" style="margin-top: 8px; margin-left: 8px;">' + ( config.strings.cancel || 'Cancel' ) + '</button>';
			html += '</div>';

			$container.html( html );

			// Generate QR code using bundled library
			if ( typeof qrcode !== 'undefined' ) {
				var qr = qrcode( 0, 'M' );
				qr.addData( uri );
				qr.make();
				$( '#rip-2fa-qr-canvas' ).html( qr.createSvgTag( 5, 0 ) );
			} else if ( typeof QRCode !== 'undefined' ) {
				new QRCode( document.getElementById( 'rip-2fa-qr-canvas' ), {
					text: uri,
					width: 200,
					height: 200,
				} );
			} else {
				$( '#rip-2fa-qr-canvas' ).html( '<p style="color: #EF4444;">' + ( config.strings.qrLibMissing || 'QR code library not loaded.' ) + '</p>' );
			}

			// Confirm button handler
			$( '#rip-2fa-confirm-btn' ).on( 'click', function () {
				var code = $( '#rip-2fa-confirm-code' ).val().trim();
				if ( code.length !== 6 ) {
					return;
				}

				var $btn = $( this );
				$btn.prop( 'disabled', true ).text( '…' );

				$.post( config.ajaxUrl, {
					action: 'reportedip_hive_2fa_confirm_totp',
					nonce: config.nonce,
					user_id: config.userId,
					code: code,
				}, function ( confirmResponse ) {
					if ( confirmResponse.success ) {
						showSetupComplete( confirmResponse.data.recovery_codes );
					} else {
						$btn.prop( 'disabled', false ).text( config.strings.confirm || 'Confirm' );
						$( '#rip-2fa-confirm-code' ).val( '' ).focus();
						notifyError( confirmResponse.data ? confirmResponse.data.message : ( config.strings.error || 'Error' ) );
					}
				} );
			} );

			// Cancel button
			$( '#rip-2fa-cancel-btn' ).on( 'click', function () {
				$container.hide().empty();
				$buttons.show();
			} );

			// Auto-submit on 6 digits
			$( '#rip-2fa-confirm-code' ).on( 'input', function () {
				this.value = this.value.replace( /[^0-9]/g, '' );
				if ( this.value.length === 6 ) {
					$( '#rip-2fa-confirm-btn' ).trigger( 'click' );
				}
			} );
		} );
	}

	/**
	 * Email 2FA setup — two-step verification (send → verify).
	 */
	function startEmailSetup() {
		if ( ! confirm( config.strings.confirmEmailSetup || 'Enable email-based 2FA? We will send a test code to your registered email address.' ) ) {
			return;
		}

		var $container = $( '#rip-2fa-setup-flow' );
		$container.html(
			'<p>' + ( config.strings.emailSetupIntro || 'We will send you a code. Check your inbox…' ) + '</p>' +
			'<div class="rip-2fa-code-confirm" style="margin-top:12px;">' +
				'<input type="text" id="rip-2fa-email-verify-input" class="regular-text" inputmode="numeric" pattern="[0-9]*" maxlength="6" autocomplete="one-time-code" placeholder="000000">' +
				'<button type="button" class="button button-primary" id="rip-2fa-email-verify-btn">' + ( config.strings.confirm || 'Confirm' ) + '</button>' +
			'</div>' +
			'<p class="description" id="rip-2fa-email-verify-msg" role="status"></p>'
		).show();

		$.post( config.ajaxUrl, {
			action: 'reportedip_hive_2fa_setup_email',
			nonce: config.nonce,
			user_id: config.userId,
			step: 'send',
		}, function ( response ) {
			var $msg = $( '#rip-2fa-email-verify-msg' );
			if ( response.success ) {
				$msg.text( response.data.message || 'Code sent.' );
			} else {
				$msg.text( response.data ? response.data.message : 'Sending failed.' );
			}
		} );

		$( document ).off( 'click.rip2faEmail' ).on( 'click.rip2faEmail', '#rip-2fa-email-verify-btn', function () {
			var code = ( $( '#rip-2fa-email-verify-input' ).val() || '' ).replace( /\D/g, '' );
			if ( 6 !== code.length ) { return; }

			$.post( config.ajaxUrl, {
				action: 'reportedip_hive_2fa_setup_email',
				nonce: config.nonce,
				user_id: config.userId,
				step: 'verify',
				code: code,
			}, function ( response ) {
				if ( response.success ) {
					$.post( config.ajaxUrl, {
						action: 'reportedip_hive_2fa_regenerate_recovery',
						nonce: config.nonce,
						user_id: config.userId,
					}, function ( rec ) {
						if ( rec.success ) {
							showSetupComplete( rec.data.codes );
						} else {
							$( '#rip-2fa-email-verify-msg' ).text( rec.data ? rec.data.message : 'Recovery codes failed.' );
						}
					} );
				} else {
					$( '#rip-2fa-email-verify-msg' ).text( response.data ? response.data.message : 'Invalid code.' );
				}
			} );
		} );
	}

	/**
	 * Show setup completion with recovery codes.
	 *
	 * @param {Array} codes Recovery codes.
	 */
	function showSetupComplete( codes ) {
		var $container = $( '#rip-2fa-setup-flow' );

		var html = '<div class="notice notice-success"><p><strong>' + config.strings.setupComplete + '</strong></p></div>';
		html += '<div style="margin-top: 16px;">';
		html += '<p><strong>' + config.strings.saveRecoveryCodes + '</strong></p>';
		html += '<div class="rip-2fa-recovery-codes">';
		html += buildRecoveryCodesHtml( codes );
		html += '</div>';
		html += '<div class="rip-2fa-recovery-codes__actions">';
		html += '<button type="button" class="button" id="rip-2fa-copy-codes">' + escapeHtml( config.strings.copy || 'Copy' ) + '</button>';
		html += '<button type="button" class="button" id="rip-2fa-download-codes">' + escapeHtml( config.strings.download || 'Download' ) + '</button>';
		html += '</div>';
		html += '<p class="description" style="margin-top: 8px; color: #EF4444;">' + escapeHtml( config.strings.recoveryShownOnce || 'These codes are shown only once!' ) + '</p>';
		html += '</div>';

		$container.html( html );

		// Copy to clipboard
		$( '#rip-2fa-copy-codes' ).on( 'click', function () {
			var text = codes.join( '\n' );
			if ( navigator.clipboard ) {
				navigator.clipboard.writeText( text ).then( function () {
					$( '#rip-2fa-copy-codes' ).text( config.strings.copied );
				} );
			}
		} );

		// Download as text file
		$( '#rip-2fa-download-codes' ).on( 'click', function () {
			var text = 'ReportedIP Hive - Recovery Codes\n';
			text += '====================================\n\n';
			for ( var j = 0; j < codes.length; j++ ) {
				text += codes[ j ] + '\n';
			}
			text += '\n' + ( config.strings.recoveryOneUse || 'Each code can be used only once.' ) + '\n';

			var blob = new Blob( [ text ], { type: 'text/plain' } );
			var url = URL.createObjectURL( blob );
			var a = document.createElement( 'a' );
			a.href = url;
			a.download = 'reportedip-recovery-codes.txt';
			a.click();
			URL.revokeObjectURL( url );
		} );
	}

	/**
	 * Disable 2FA button.
	 */
	function initDisableButton() {
		$( '#rip-2fa-disable' ).on( 'click', function () {
			if ( ! confirm( config.strings.confirmDisable ) ) {
				return;
			}

			$.post( config.ajaxUrl, {
				action: 'reportedip_hive_2fa_disable',
				nonce: config.nonce,
				user_id: config.userId,
			}, function ( response ) {
				if ( response.success ) {
					location.reload();
				} else {
					notifyError( response.data ? response.data.message : ( config.strings.error || 'Error' ) );
				}
			} );
		} );
	}

	/**
	 * Regenerate recovery codes.
	 */
	function initRecoveryRegenerate() {
		$( '#rip-2fa-regenerate-recovery' ).on( 'click', function () {
			if ( ! confirm( config.strings.confirmRegenerate ) ) {
				return;
			}

			$.post( config.ajaxUrl, {
				action: 'reportedip_hive_2fa_regenerate_recovery',
				nonce: config.nonce,
				user_id: config.userId,
			}, function ( response ) {
				if ( response.success ) {
					var $display = $( '#rip-2fa-recovery-display' );
					var codes = response.data.codes;

					var html = '<div class="rip-2fa-recovery-codes" style="margin-top: 12px;">';
					html += buildRecoveryCodesHtml( codes );
					html += '</div>';
					html += '<p class="description" style="color: #EF4444;">Diese Codes werden nur einmal angezeigt!</p>';

					$display.html( html ).show();
				} else {
					notifyError( response.data ? response.data.message : ( config.strings.error || 'Error' ) );
				}
			} );
		} );
	}

	/**
	 * Device revocation handlers.
	 */
	function initDeviceRevocation() {
		// Single device revoke
		$( '.rip-2fa-revoke-device' ).on( 'click', function () {
			var $btn = $( this );
			var deviceId = $btn.data( 'device-id' );

			$.post( config.ajaxUrl, {
				action: 'reportedip_hive_2fa_revoke_device',
				nonce: config.nonce,
				user_id: config.userId,
				device_id: deviceId,
			}, function ( response ) {
				if ( response.success ) {
					$btn.closest( '.rip-2fa-device-list__item' ).fadeOut( 300, function () {
						$( this ).remove();
					} );
				}
			} );
		} );

		// Revoke all
		$( '#rip-2fa-revoke-all' ).on( 'click', function () {
			if ( ! confirm( config.strings.confirmRevokeAll ) ) {
				return;
			}

			$.post( config.ajaxUrl, {
				action: 'reportedip_hive_2fa_revoke_all_devices',
				nonce: config.nonce,
				user_id: config.userId,
			}, function ( response ) {
				if ( response.success ) {
					$( '.rip-2fa-device-list' ).fadeOut( 300 );
					$( '#rip-2fa-revoke-all' ).hide();
				}
			} );
		} );
	}

} )( jQuery );
