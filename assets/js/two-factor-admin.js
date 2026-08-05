/**
 * ReportedIP Hive — Two-Factor Admin Script.
 *
 * Drives the sign-in method rows on the profile page: inline setup flows
 * (TOTP, email, SMS), default-method selection, single-method removal,
 * recovery codes and trusted device management. All flow markup and
 * user-facing descriptions are server-rendered; this script only toggles
 * the markup and runs the AJAX steps.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     1.3.0
 */

( function ( $ ) {
	'use strict';

	var config = window.reportedip2faAdmin || {};
	var NOTICE_AUTODISMISS_MS = 6000;

	/**
	 * HTML-escape a value for safe interpolation into innerHTML/.html() strings.
	 *
	 * @param {*} value Raw value.
	 * @return {string} Escaped string.
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

	/**
	 * Read a localized string with a fallback.
	 *
	 * @param {string} key      String key in config.strings.
	 * @param {string} fallback Fallback text.
	 * @return {string} Localized string.
	 */
	function str( key, fallback ) {
		return ( config.strings && config.strings[ key ] ) || fallback;
	}

	$( document ).ready( function () {
		initMethodRows();
		initDisableButton();
		initRecoveryRegenerate();
		initDeviceRevocation();
	} );

	/**
	 * Display a non-blocking error notice on the profile page.
	 *
	 * admin.js is not enqueued on profile.php / user-edit.php, so a small
	 * WordPress-style notice is rendered here. Announces via wp.a11y.speak.
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
	 * Extract the message from a wp_send_json_* response.
	 *
	 * @param {Object} response AJAX response.
	 * @return {string} Message text.
	 */
	function responseMessage( response ) {
		return ( response && response.data && response.data.message ) || str( 'error', 'Error' );
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
	 * Bind copy/download handlers for a rendered recovery-code block.
	 *
	 * @param {jQuery} $scope Container holding the action buttons.
	 * @param {Array}  codes  Recovery code strings.
	 */
	function bindRecoveryActions( $scope, codes ) {
		$scope.find( '[data-recovery-copy]' ).on( 'click', function () {
			var $btn = $( this );
			if ( navigator.clipboard ) {
				navigator.clipboard.writeText( codes.join( '\n' ) ).then( function () {
					$btn.text( str( 'copied', 'Copied!' ) );
				} );
			}
		} );

		$scope.find( '[data-recovery-download]' ).on( 'click', function () {
			var text = 'ReportedIP Hive - Recovery Codes\n';
			text += '====================================\n\n';
			for ( var j = 0; j < codes.length; j++ ) {
				text += codes[ j ] + '\n';
			}
			text += '\n' + str( 'recoveryOneUse', 'Each code can be used only once.' ) + '\n';

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
	 * Render recovery codes with copy/download actions into a container.
	 *
	 * @param {Array}  codes   Recovery code strings.
	 * @param {jQuery} $target Container to render into.
	 * @param {Object} opts    heading: success notice + save prompt,
	 *                         done: reload button for the one-time reveal.
	 */
	function showRecoveryCodes( codes, $target, opts ) {
		opts = opts || {};
		var html = '';
		if ( opts.heading ) {
			html += '<div class="notice notice-success"><p><strong>' + escapeHtml( str( 'setupComplete', '2FA has been set up successfully!' ) ) + '</strong></p></div>';
			html += '<p><strong>' + escapeHtml( str( 'saveRecoveryCodes', 'Save these recovery codes in a secure place:' ) ) + '</strong></p>';
		}
		html += '<div class="rip-2fa-recovery-codes">' + buildRecoveryCodesHtml( codes ) + '</div>';
		html += '<div class="rip-2fa-recovery-codes__actions">';
		html += '<button type="button" class="rip-button rip-button--secondary rip-button--sm" data-recovery-copy>' + escapeHtml( str( 'copy', 'Copy' ) ) + '</button>';
		html += '<button type="button" class="rip-button rip-button--secondary rip-button--sm" data-recovery-download>' + escapeHtml( str( 'download', 'Download' ) ) + '</button>';
		if ( opts.done ) {
			html += '<button type="button" class="rip-button rip-button--primary rip-button--sm" data-recovery-done>' + escapeHtml( str( 'codesSaved', 'I have saved my codes' ) ) + '</button>';
		}
		html += '</div>';
		html += '<p class="description rip-2fa-recovery-codes__warning">' + escapeHtml( str( 'recoveryShownOnce', 'These codes are shown only once!' ) ) + '</p>';

		$target.html( html ).prop( 'hidden', false ).show();
		bindRecoveryActions( $target, codes );
		$target.find( '[data-recovery-done]' ).on( 'click', function () {
			location.reload();
		} );
		if ( $target.get( 0 ) && $target.get( 0 ).scrollIntoView ) {
			$target.get( 0 ).scrollIntoView( { behavior: 'smooth', block: 'nearest' } );
		}
	}

	/**
	 * Finish a successful setup: show recovery codes when the server
	 * generated a fresh set, otherwise reload to re-render the row state.
	 *
	 * @param {Object} data AJAX success payload.
	 */
	function finishSetup( data ) {
		var codes = data && data.recovery_codes;
		if ( codes && codes.length ) {
			$( '.rip-2fa-method__flow' ).prop( 'hidden', true );
			showRecoveryCodes( codes, $( '#rip-2fa-method-recovery' ), { heading: true, done: true } );
			return;
		}
		location.reload();
	}

	/**
	 * Close every open method flow and clear its status line.
	 */
	function closeAllFlows() {
		$( '.rip-2fa-method__flow' ).each( function () {
			var $flow = $( this );
			$flow.prop( 'hidden', true );
			$flow.find( '[data-status]' ).text( '' );
			$flow.find( '[data-code]' ).val( '' );
		} );
	}

	/**
	 * Open the flow container of one method row.
	 *
	 * @param {jQuery} $row Method row.
	 * @return {jQuery} The flow container.
	 */
	function openFlow( $row ) {
		closeAllFlows();
		var $flow = $row.find( '.rip-2fa-method__flow' );
		$flow.prop( 'hidden', false );
		return $flow;
	}

	/**
	 * Set the status line of a flow.
	 *
	 * @param {jQuery} $flow   Flow container.
	 * @param {string} message Status text.
	 */
	function flowStatus( $flow, message ) {
		$flow.find( '[data-status]' ).text( String( message || '' ) );
	}

	/**
	 * Count the currently active methods from the rendered rows.
	 *
	 * @return {number} Active method count.
	 */
	function activeMethodCount() {
		return $( '.rip-2fa-method[data-active="1"]' ).length;
	}

	/**
	 * Wire the method rows: setup, make-default, remove and flow controls.
	 */
	function initMethodRows() {
		var $list = $( '.rip-2fa-methods' );
		if ( ! $list.length ) {
			return;
		}

		$list.on( 'click', '[data-action="setup"]', function () {
			var $row = $( this ).closest( '.rip-2fa-method' );
			var slug = $row.data( 'method' );
			var replace = '1' === String( $( this ).data( 'replace' ) || '' );

			if ( 'totp' === slug ) {
				if ( replace && ! window.confirm( str( 'confirmReplaceTotp', 'Set up the authenticator app again?' ) ) ) {
					return;
				}
				startTotpFlow( $row, replace );
			} else if ( 'email' === slug ) {
				startEmailFlow( $row );
			} else if ( 'sms' === slug ) {
				startSmsFlow( $row );
			}
		} );

		$list.on( 'click', '[data-action="make-default"]', function () {
			var $row = $( this ).closest( '.rip-2fa-method' );
			$.post( config.ajaxUrl, {
				action: 'reportedip_hive_2fa_set_primary_method',
				nonce: config.nonce,
				user_id: config.userId,
				method: $row.data( 'method' ),
			}, function ( response ) {
				if ( response.success ) {
					location.reload();
				} else {
					notifyError( responseMessage( response ) );
				}
			} );
		} );

		$list.on( 'click', '[data-action="remove"]', function () {
			var $row = $( this ).closest( '.rip-2fa-method' );
			var question = 1 >= activeMethodCount()
				? str( 'confirmRemoveLast', 'This is your last active method. Removing it turns off two-factor authentication completely. Continue?' )
				: str( 'confirmRemoveMethod', 'Remove this sign-in method?' );
			if ( ! window.confirm( question ) ) {
				return;
			}

			$.post( config.ajaxUrl, {
				action: 'reportedip_hive_2fa_disable_method',
				nonce: config.nonce,
				user_id: config.userId,
				method: $row.data( 'method' ),
			}, function ( response ) {
				if ( response.success ) {
					location.reload();
				} else {
					notifyError( responseMessage( response ) );
				}
			} );
		} );

		$list.on( 'click', '[data-step="cancel"]', function () {
			closeAllFlows();
		} );

		$list.on( 'input', '[data-code]', function () {
			this.value = this.value.replace( /[^0-9]/g, '' );
			if ( 6 === this.value.length ) {
				$( this ).closest( '.rip-2fa-method__flow' ).find( '[data-step="confirm"]' ).first().trigger( 'click' );
			}
		} );

		$list.on( 'keydown', '[data-code], [data-phone]', function ( event ) {
			if ( 'Enter' === event.key ) {
				event.preventDefault();
				var $flow = $( this ).closest( '.rip-2fa-method__flow' );
				var $send = $flow.find( '[data-step="send-sms"]:visible' );
				if ( $send.length && $( this ).is( '[data-phone]' ) ) {
					$send.trigger( 'click' );
				} else {
					$flow.find( '[data-step="confirm"]' ).first().trigger( 'click' );
				}
			}
		} );
	}

	/**
	 * TOTP flow: fetch secret, render QR, verify the first code.
	 *
	 * @param {jQuery}  $row    Method row.
	 * @param {boolean} replace Replace an existing confirmed secret.
	 */
	function startTotpFlow( $row, replace ) {
		var $flow = openFlow( $row );
		flowStatus( $flow, str( 'working', 'Please wait' ) );

		$.post( config.ajaxUrl, {
			action: 'reportedip_hive_2fa_setup_totp',
			nonce: config.nonce,
			user_id: config.userId,
			replace: replace ? 1 : 0,
		}, function ( response ) {
			if ( ! response.success ) {
				flowStatus( $flow, responseMessage( response ) );
				return;
			}
			flowStatus( $flow, '' );

			var uri = response.data.uri;
			var $qr = $flow.find( '[data-qr]' ).empty();
			$flow.find( '[data-secret]' ).text( response.data.secret );

			if ( 'undefined' !== typeof qrcode ) {
				var qr = qrcode( 0, 'M' );
				qr.addData( uri );
				qr.make();
				$qr.html( qr.createSvgTag( 5, 0 ) );
			} else if ( 'undefined' !== typeof QRCode ) {
				new QRCode( $qr.get( 0 ), { text: uri, width: 200, height: 200 } );
			} else {
				$qr.text( str( 'qrLibMissing', 'QR code library not loaded.' ) );
			}

			$flow.find( '[data-code]' ).trigger( 'focus' );
			bindConfirm( $flow, function ( code, done ) {
				$.post( config.ajaxUrl, {
					action: 'reportedip_hive_2fa_confirm_totp',
					nonce: config.nonce,
					user_id: config.userId,
					code: code,
				}, function ( confirmResponse ) {
					if ( confirmResponse.success ) {
						finishSetup( confirmResponse.data );
					} else {
						done( responseMessage( confirmResponse ) );
					}
				} );
			} );
		} );
	}

	/**
	 * Email flow: dispatch a code on explicit request, then verify it.
	 *
	 * @param {jQuery} $row Method row.
	 */
	function startEmailFlow( $row ) {
		var $flow = openFlow( $row );
		$flow.find( '[data-email-step="send"]' ).prop( 'hidden', false );
		$flow.find( '[data-email-step="code"]' ).prop( 'hidden', true );

		$flow.off( 'click.ripEmailSend' ).on( 'click.ripEmailSend', '[data-step="send-email"]', function () {
			flowStatus( $flow, str( 'working', 'Please wait' ) );
			$.post( config.ajaxUrl, {
				action: 'reportedip_hive_2fa_setup_email',
				nonce: config.nonce,
				user_id: config.userId,
				step: 'send',
			}, function ( response ) {
				if ( ! response.success ) {
					flowStatus( $flow, responseMessage( response ) );
					return;
				}
				flowStatus( $flow, '' );
				$flow.find( '[data-email-step="send"]' ).prop( 'hidden', true );
				$flow.find( '[data-email-step="code"]' ).prop( 'hidden', false );
				$flow.find( '[data-email-sent-note]' ).text(
					responseMessage( response ) + ( response.data.masked ? ' (' + response.data.masked + ')' : '' )
				);
				$flow.find( '[data-code]' ).trigger( 'focus' );
			} );
		} );

		bindConfirm( $flow, function ( code, done ) {
			$.post( config.ajaxUrl, {
				action: 'reportedip_hive_2fa_setup_email',
				nonce: config.nonce,
				user_id: config.userId,
				step: 'verify',
				code: code,
			}, function ( response ) {
				if ( response.success ) {
					finishSetup( response.data );
				} else {
					done( responseMessage( response ) );
				}
			} );
		} );
	}

	/**
	 * SMS flow: register number with consent, then verify the code.
	 *
	 * @param {jQuery} $row Method row.
	 */
	function startSmsFlow( $row ) {
		var $flow = openFlow( $row );
		$flow.find( '[data-sms-step="phone"]' ).prop( 'hidden', false );
		$flow.find( '[data-sms-step="code"]' ).prop( 'hidden', true );
		$flow.find( '[data-phone]' ).trigger( 'focus' );

		$flow.off( 'click.ripSmsSend' ).on( 'click.ripSmsSend', '[data-step="send-sms"]', function () {
			var phone = String( $flow.find( '[data-phone]' ).val() || '' ).trim();
			if ( '' === phone || '+' !== phone.charAt( 0 ) ) {
				flowStatus( $flow, str( 'phoneRequired', 'Please enter your mobile number in international format.' ) );
				return;
			}
			if ( ! $flow.find( '[data-consent]' ).is( ':checked' ) ) {
				flowStatus( $flow, str( 'consentRequired', 'Please confirm the processing of your phone number first.' ) );
				return;
			}

			flowStatus( $flow, str( 'working', 'Please wait' ) );
			$.post( config.ajaxUrl, {
				action: 'reportedip_hive_2fa_setup_sms',
				nonce: config.nonce,
				user_id: config.userId,
				step: 'register',
				phone: phone,
				consent: 1,
			}, function ( response ) {
				if ( ! response.success ) {
					flowStatus( $flow, responseMessage( response ) );
					return;
				}
				flowStatus( $flow, '' );
				$flow.find( '[data-sms-step="phone"]' ).prop( 'hidden', true );
				$flow.find( '[data-sms-step="code"]' ).prop( 'hidden', false );
				$flow.find( '[data-sms-sent-note]' ).text(
					responseMessage( response ) + ' (' + ( response.data.masked || '' ) + ')'
				);
				$flow.find( '[data-code]' ).trigger( 'focus' );
			} );
		} );

		bindConfirm( $flow, function ( code, done ) {
			$.post( config.ajaxUrl, {
				action: 'reportedip_hive_2fa_setup_sms',
				nonce: config.nonce,
				user_id: config.userId,
				step: 'verify',
				code: code,
			}, function ( response ) {
				if ( response.success ) {
					finishSetup( response.data );
				} else {
					done( responseMessage( response ) );
				}
			} );
		} );
	}

	/**
	 * Bind the confirm button of a flow to a verify callback.
	 *
	 * @param {jQuery}   $flow  Flow container.
	 * @param {Function} verify Callback receiving (code, done). done(message)
	 *                          re-enables the button and shows the message.
	 */
	function bindConfirm( $flow, verify ) {
		$flow.off( 'click.ripConfirm' ).on( 'click.ripConfirm', '[data-step="confirm"]', function () {
			var $btn = $( this );
			var $input = $flow.find( '[data-code]' ).filter( ':visible' ).first();
			if ( ! $input.length ) {
				$input = $flow.find( '[data-code]' ).first();
			}
			var code = String( $input.val() || '' ).replace( /\D/g, '' );
			if ( 6 !== code.length ) {
				return;
			}

			$btn.prop( 'disabled', true );
			verify( code, function ( message ) {
				$btn.prop( 'disabled', false );
				$input.val( '' ).trigger( 'focus' );
				flowStatus( $flow, message );
			} );
		} );
	}

	/**
	 * Disable 2FA button.
	 */
	function initDisableButton() {
		$( '#rip-2fa-disable' ).on( 'click', function () {
			if ( ! window.confirm( str( 'confirmDisable', 'Turn off two-factor authentication completely?' ) ) ) {
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
					notifyError( responseMessage( response ) );
				}
			} );
		} );
	}

	/**
	 * Regenerate recovery codes.
	 */
	function initRecoveryRegenerate() {
		$( '#rip-2fa-regenerate-recovery' ).on( 'click', function () {
			if ( ! window.confirm( str( 'confirmRegenerate', 'Existing recovery codes will stop working. Continue?' ) ) ) {
				return;
			}

			$.post( config.ajaxUrl, {
				action: 'reportedip_hive_2fa_regenerate_recovery',
				nonce: config.nonce,
				user_id: config.userId,
			}, function ( response ) {
				if ( ! response.success ) {
					notifyError( responseMessage( response ) );
					return;
				}
				showRecoveryCodes( response.data.codes, $( '#rip-2fa-recovery-display' ) );
			} );
		} );
	}

	/**
	 * Device revocation handlers (delegated so re-rendered lists keep working).
	 */
	function initDeviceRevocation() {
		$( document ).on( 'click', '.rip-2fa-revoke-device', function () {
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
				} else {
					notifyError( responseMessage( response ) );
				}
			} );
		} );

		$( '#rip-2fa-revoke-all' ).on( 'click', function () {
			if ( ! window.confirm( str( 'confirmRevokeAll', 'Revoke all trusted devices?' ) ) ) {
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
				} else {
					notifyError( responseMessage( response ) );
				}
			} );
		} );
	}

} )( jQuery );
