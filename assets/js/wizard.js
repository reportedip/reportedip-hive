/**
 * ReportedIP Hive — Setup Wizard JavaScript.
 *
 * Cross-step persistence via sessionStorage. All settings are saved
 * centrally when the final-submit fires from Step 6 (#rip-save-config),
 * which calls the ajax_complete_wizard endpoint.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     1.1.0
 */

(function ($) {
	'use strict';

	var STORAGE_KEY = 'reportedipWizardState';

	// Defaults are sourced from PHP via wp_localize_script (single source of
	// truth: ReportedIP_Hive_Defaults::wizard()). The hardcoded fallback
	// shim only fires if the script is loaded without the localized payload —
	// e.g. when a third-party loader bypasses our enqueue helper.
	var LOCALIZED = (typeof window.reportedipWizard === 'object' && window.reportedipWizard) || {};
	var DEFAULTS = $.extend(
		{
			grace_days: 7,
			max_skips: 3,
			retention_days: 30,
			anonymize_days: 7,
			mode: 'local',
			protection_level: 'medium',
			auto_footer_align: 'center'
		},
		LOCALIZED.defaults || {}
	);

	var ReportedIPWizard = {

		init: function () {
			// Wizard JS is enqueued only on the wizard page by convention; this
			// body-class guard protects against third-party loaders pulling it
			// into unrelated admin pages.
			if (!document.body || !document.body.classList.contains('rip-wizard-page')) {
				return;
			}
			this.bindEvents();
			this.initModeSelection();
			this.initStep3();
			this.initStep4();
			this.initStep6();
			this.initStep8();
			this.restoreFromSession();
		},

		bindEvents: function () {
			// Step 2: mode selection
			$(document).on('click', '.rip-mode-card', this.handleModeCardClick.bind(this));
			$(document).on('click', '#rip-continue-mode', this.handleContinueMode.bind(this));

			// Step 2: API key
			$(document).on('click', '#rip-validate-key', this.handleValidateApiKey.bind(this));
			$(document).on('keypress', '#rip-api-key', this.handleApiKeyEnter.bind(this));

			// Step 3: monitoring toggles → warning banner
			$(document).on('change', '#rip-monitor-logins, #rip-monitor-comments, #rip-monitor-xmlrpc', this.updateMonitoringWarning.bind(this));

			// Step 3 → 4: cache values to sessionStorage
			$(document).on('click', '#rip-step3-next', this.persistStep3.bind(this));

			// Step 4: 2FA method-card multi-select
			$(document).on('click', '.rip-method-card', this.handleMethodCardClick.bind(this));
			$(document).on('change', '#rip-2fa-enabled', this.update2faEnabledState.bind(this));

			// Step 4 → 5: cache values to sessionStorage
			$(document).on('click', '#rip-step4-next', this.persistStep4.bind(this));

			// Step 5 → 6: cache privacy values before the Hide-Login step renders
			$(document).on('click', '#rip-step5-next', this.persistStep5.bind(this));

			// Step 6: live slug validation + toggle-driven enable state
			$(document).on('input', '#rip-hide-login-slug', this.debounceValidateSlug.bind(this));
			$(document).on('change', '#rip-hide-login-enabled', this.toggleHideLoginFields.bind(this));

			// Step 6: final submit
			$(document).on('click', '#rip-save-config', this.handleSaveConfig.bind(this));

			// Skip wizard
			$(document).on('click', '#rip-skip-wizard', this.handleSkipWizard.bind(this));
		},

		// ========================================================================
		// Step 2: Mode + API-Key
		// ========================================================================

		initModeSelection: function () {
			var $selectedCard = $('.rip-mode-card--selected');
			if ($selectedCard.length) {
				this.updateContinueButton(true);
				this.toggleApiKeyCard($selectedCard.data('mode'));
			}
		},

		handleModeCardClick: function (e) {
			var $card = $(e.currentTarget);
			var mode = $card.data('mode');

			$('.rip-mode-card').removeClass('rip-mode-card--selected');
			$card.addClass('rip-mode-card--selected');

			$('#rip-selected-mode').val(mode);
			this.toggleApiKeyCard(mode);
			this.updateContinueButton(true);
		},

		toggleApiKeyCard: function (mode) {
			$('#rip-api-key-card').toggleClass('rip-is-hidden', mode !== 'community');
		},

		updateContinueButton: function (enabled) {
			$('#rip-continue-mode').prop('disabled', !enabled);
		},

		handleContinueMode: function (e) {
			e.preventDefault();
			var mode = $('#rip-selected-mode').val();
			var $button = $(e.currentTarget);

			if (!mode) { return; }

			// Im Community-Modus: API-Key vor Weiter speichern (ohne Validation-Zwang)
			if (mode === 'community') {
				var apiKey = ($('#rip-api-key').val() || '').trim();
				if (apiKey) {
					this.setSession({ apiKey: apiKey });
				}
			}

			$button.prop('disabled', true);
			var originalText = $button.html();
			$button.html('<span class="rip-spinner"></span> ' + (reportedipWizard.strings.saving || 'Saving…'));

			$.ajax({
				url: reportedipWizard.ajaxUrl,
				type: 'POST',
				data: {
					action: 'reportedip_wizard_save_mode',
					nonce: reportedipWizard.nonce,
					mode: mode
				},
				success: function (response) {
					if (response.success && response.data.redirect_url) {
						// Mode in sessionStorage cachen für Final-Submit
						ReportedIPWizard.setSession({ mode: mode });
						window.location.href = response.data.redirect_url;
					} else {
						$button.html(originalText).prop('disabled', false);
						alert((response.data && response.data.message) || response.data || (reportedipWizard.strings.errorGeneric || 'Error'));
					}
				},
				error: function () {
					$button.html(originalText).prop('disabled', false);
					alert(reportedipWizard.strings.errorRetry || 'Error. Please try again.');
				}
			});
		},

		handleApiKeyEnter: function (e) {
			if (e.which === 13) {
				e.preventDefault();
				$('#rip-validate-key').click();
			}
		},

		handleValidateApiKey: function (e) {
			e.preventDefault();
			var $button = $(e.currentTarget);
			var $input = $('#rip-api-key');
			var $status = $('#rip-api-key-status');
			var $apiInfo = $('#rip-api-info');
			var apiKey = $input.val().trim();

			if (!apiKey) {
				$status.html('<span class="rip-input-status--error">' + (reportedipWizard.strings.missingKey || 'Please enter an API key.') + '</span>');
				$input.addClass('rip-input--invalid').removeClass('rip-input--valid');
				return;
			}

			var originalText = $button.text();
			$button.prop('disabled', true).html('<span class="rip-spinner"></span>');
			$status.html('<span class="rip-input-status--loading">' + (reportedipWizard.strings.validating || 'Checking…') + '</span>');
			$input.removeClass('rip-input--valid rip-input--invalid');

			$.ajax({
				url: reportedipWizard.ajaxUrl,
				type: 'POST',
				data: {
					action: 'reportedip_wizard_validate_api_key',
					nonce: reportedipWizard.nonce,
					api_key: apiKey
				},
				success: function (response) {
					$button.prop('disabled', false).text(originalText);

					if (response.success && response.data.valid) {
						$input.addClass('rip-input--valid').removeClass('rip-input--invalid');
						$status.html('<span class="rip-input-status--success"><svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg> ' + (reportedipWizard.strings.valid || 'API key is valid!') + '</span>');

						$('#rip-key-name').text(response.data.key_name || '-');
						$('#rip-user-role').text(ReportedIPWizard.formatRole(response.data.user_role));
						$('#rip-daily-limit').text(ReportedIPWizard.formatNumber(response.data.daily_limit));
						$('#rip-remaining-calls').text(ReportedIPWizard.formatNumber(response.data.remaining_calls));
						$apiInfo.removeClass('rip-is-hidden');

						ReportedIPWizard.setSession({ apiKey: apiKey });
					} else {
						$input.addClass('rip-input--invalid').removeClass('rip-input--valid');
						var message = (response.data && response.data.message) ? response.data.message : (reportedipWizard.strings.invalid || 'Invalid API key.');
						$status.html('<span class="rip-input-status--error"><svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg> ' + message + '</span>');
						$apiInfo.addClass('rip-is-hidden');
					}
				},
				error: function () {
					$button.prop('disabled', false).text(originalText);
					$input.addClass('rip-input--invalid').removeClass('rip-input--valid');
					$status.html('<span class="rip-input-status--error">' + (reportedipWizard.strings.error || 'Validation failed.') + '</span>');
					$apiInfo.hide();
				}
			});
		},

		// ========================================================================
		// Step 3: Protection
		// ========================================================================

		initStep3: function () {
			this.updateMonitoringWarning();
		},

		updateMonitoringWarning: function () {
			var anyActive = $('#rip-monitor-logins').is(':checked')
				|| $('#rip-monitor-comments').is(':checked')
				|| $('#rip-monitor-xmlrpc').is(':checked');
			$('#rip-monitoring-warning').toggleClass('is-visible', !anyActive);
		},

		persistStep3: function () {
			this.setSession({
				protection_level: $('input[name="protection_level"]:checked').val() || 'medium',
				monitor_failed_logins: $('#rip-monitor-logins').is(':checked') ? 1 : 0,
				monitor_comments: $('#rip-monitor-comments').is(':checked') ? 1 : 0,
				monitor_xmlrpc: $('#rip-monitor-xmlrpc').is(':checked') ? 1 : 0,
				monitor_app_passwords: $('#rip-monitor-app-passwords').is(':checked') ? 1 : 0,
				monitor_rest_api: $('#rip-monitor-rest-api').is(':checked') ? 1 : 0,
				block_user_enumeration: $('#rip-block-user-enumeration').is(':checked') ? 1 : 0,
				monitor_404_scans: $('#rip-monitor-404-scans').is(':checked') ? 1 : 0,
				monitor_geo_anomaly: $('#rip-monitor-geo-anomaly').is(':checked') ? 1 : 0,
				auto_block: $('#rip-auto-block').is(':checked') ? 1 : 0,
				block_escalation_enabled: $('#rip-block-escalation').is(':checked') ? 1 : 0,
				report_only_mode: $('#rip-report-only').is(':checked') ? 1 : 0
			});
		},

		// ========================================================================
		// Step 4: 2FA
		// ========================================================================

		initStep4: function () {
			this.update2faEnabledState();
			this.update2faMethodsHidden();
		},

		handleMethodCardClick: function (e) {
			var $card = $(e.currentTarget);
			if ($card.hasClass('rip-method-card--disabled')) { return; }
			$card.toggleClass('rip-method-card--selected');
			this.update2faMethodsHidden();
		},

		update2faMethodsHidden: function () {
			var $cards = $('.rip-method-card--selected');
			var methods = [];
			$cards.each(function () {
				methods.push($(this).data('method'));
			});
			$('#rip-2fa-methods-input').val(methods.join(','));
		},

		update2faEnabledState: function () {
			var enabled = $('#rip-2fa-enabled').is(':checked');
			$('#rip-2fa-methods-card, #rip-2fa-roles-card').toggleClass('rip-config-card--disabled', !enabled);
		},

		persistStep4: function (e) {
			var twofaEnabled = $('#rip-2fa-enabled').is(':checked');
			var methods = $('#rip-2fa-methods-input').val() || '';

			if (twofaEnabled && methods.split(',').filter(function (m) { return m.length; }).length === 0) {
				if (e) { e.preventDefault(); }
				alert(reportedipWizard.strings.no2faMethod || 'Please choose at least one method.');
				return false;
			}

			var roles = [];
			$('input[name="2fa_enforce_role[]"]:checked').each(function () {
				roles.push($(this).val());
			});

			if (twofaEnabled && roles.length === 0) {
				if (e) { e.preventDefault(); }
				alert(reportedipWizard.strings.no2faRole || 'Please pick at least one role to enforce 2FA for.');
				$('input[name="2fa_enforce_role[]"][value="administrator"]').prop('checked', true).trigger('change');
				return false;
			}

			this.setSession({
				'2fa_enabled_global': twofaEnabled ? 1 : 0,
				'2fa_methods': methods,
				'2fa_enforce_role': roles,
				'2fa_enforce_grace_days': parseInt($('#rip-2fa-grace-days').val(), 10) || DEFAULTS.grace_days,
				'2fa_max_skips': parseInt($('#rip-2fa-max-skips').val(), 10) || DEFAULTS.max_skips,
				'2fa_trusted_devices': $('#rip-2fa-trusted-devices').is(':checked') ? 1 : 0,
				'2fa_frontend_onboarding': $('#rip-2fa-frontend-onboarding').is(':checked') ? 1 : 0,
				'2fa_notify_new_device': $('#rip-2fa-notify-new-device').is(':checked') ? 1 : 0,
				'2fa_xmlrpc_app_password_only': $('#rip-2fa-xmlrpc-app-password-only').is(':checked') ? 1 : 0
			});
		},

		// ========================================================================
		// Step 5: Privacy → Step 6: Hide Login
		// ========================================================================

		persistStep5: function () {
			this.setSession({
				minimal_logging: $('#rip-minimal-logging').is(':checked') ? 1 : 0,
				data_retention_days: $('#rip-data-retention').val() || DEFAULTS.retention_days,
				auto_anonymize_days: $('#rip-auto-anonymize').val() || DEFAULTS.anonymize_days,
				log_user_agents: $('#rip-log-user-agents').is(':checked') ? 1 : 0,
				log_referer_domains: $('#rip-log-referer').is(':checked') ? 1 : 0,
				notify_admin: $('#rip-notify-admin').is(':checked') ? 1 : 0,
				delete_data_on_uninstall: $('#rip-delete-on-uninstall').is(':checked') ? 1 : 0
			});
		},

		// ========================================================================
		// Step 6: Hide Login (slug validation + final submit)
		// ========================================================================

		initStep6: function () {
			if (!$('#rip-hide-login-enabled').length) { return; }
			this.toggleHideLoginFields();
		},

		// ========================================================================
		// Step 8: Setup-complete celebration trigger
		// ========================================================================

		initStep8: function () {
			var $complete = $('.rip-wizard__complete');
			if (!$complete.length) { return; }
			// Defer to next paint so CSS animations start cleanly on load.
			window.requestAnimationFrame(function () {
				$complete.addClass('rip-wizard__complete--play');
			});
		},

		toggleHideLoginFields: function () {
			var enabled = $('#rip-hide-login-enabled').is(':checked');
			$('#rip-hide-login-fields').toggleClass('rip-is-disabled', !enabled);
			if (!enabled) {
				$('#rip-hide-login-validation').text('').css('color', '');
			}
		},

		debounceValidateSlug: function () {
			var self = this;
			if (this._slugTimer) { clearTimeout(this._slugTimer); }
			this._slugTimer = setTimeout(function () { self.validateSlug(); }, 350);
		},

		validateSlug: function () {
			var $slug = $('#rip-hide-login-slug');
			var $msg  = $('#rip-hide-login-validation');
			var slug  = ($slug.val() || '').toLowerCase().trim();
			if (!slug) {
				$msg.text('').css('color', '');
				return;
			}
			$msg.text(reportedipWizard.strings.validating || 'Checking…').css('color', '');

			$.ajax({
				url: reportedipWizard.ajaxUrl,
				type: 'POST',
				data: {
					action: 'reportedip_wizard_validate_login_slug',
					nonce: reportedipWizard.nonce,
					slug: slug
				},
				success: function (response) {
					if (response.success && response.data && response.data.full_url) {
						$msg.text('✓ ' + response.data.full_url).css('color', 'var(--rip-success)');
					} else {
						$msg.text((response.data && response.data.message) || (reportedipWizard.strings.errorGeneric || 'Error')).css('color', 'var(--rip-danger)');
					}
				},
				error: function () {
					$msg.text(reportedipWizard.strings.errorRetry || 'Error.').css('color', 'var(--rip-danger)');
				}
			});
		},

		handleSaveConfig: function (e) {
			e.preventDefault();
			var $button = $(e.currentTarget);

			var step6 = {
				hide_login_enabled: $('#rip-hide-login-enabled').is(':checked') ? 1 : 0,
				hide_login_slug: ($('#rip-hide-login-slug').val() || '').toLowerCase().trim(),
				hide_login_response_mode: $('input[name="hide_login_response_mode"]:checked').val() || 'block_page'
			};

			var session = this.getSession();
			var payload = $.extend({}, session, step6, {
				action: 'reportedip_wizard_complete',
				nonce: reportedipWizard.nonce
			});

			// Defaults für den Fall dass Nutzer Steps übersprungen hat
			if (!payload.mode) { payload.mode = DEFAULTS.mode; }
			if (!payload.protection_level) { payload.protection_level = DEFAULTS.protection_level; }

			var originalText = $button.html();
			$button.prop('disabled', true);
			$button.html('<span class="rip-spinner"></span> ' + (reportedipWizard.strings.completing || 'Wird gespeichert…'));

			$.ajax({
				url: reportedipWizard.ajaxUrl,
				type: 'POST',
				data: payload,
				// traditional: false (default) — sendet Arrays mit "[]"-Suffix (key[]=v1&key[]=v2),
				// das PHP $_POST korrekt zu einem Array zusammenführt.
				success: function (response) {
					if (response.success && response.data.redirect_url) {
						$button.html('<svg viewBox="0 0 20 20" fill="currentColor" width="20" height="20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg> ' + (reportedipWizard.strings.saved || 'Gespeichert!'));

						// Session aufräumen
						ReportedIPWizard.clearSession();

						setTimeout(function () {
							$button.html(reportedipWizard.strings.redirecting || 'Redirecting…');
							window.location.href = response.data.redirect_url;
						}, 500);
					} else {
						$button.html(originalText).prop('disabled', false);
						alert(response.data || (reportedipWizard.strings.errorGeneric || 'Error'));
					}
				},
				error: function () {
					$button.html(originalText).prop('disabled', false);
					alert(reportedipWizard.strings.errorRetry || 'Error. Please try again.');
				}
			});
		},

		// ========================================================================
		// Skip
		// ========================================================================

		handleSkipWizard: function (e) {
			e.preventDefault();

			if (!confirm(reportedipWizard.strings.confirmSkip || 'Really skip setup?')) { return; }

			$.ajax({
				url: reportedipWizard.ajaxUrl,
				type: 'POST',
				data: {
					action: 'reportedip_wizard_skip',
					nonce: reportedipWizard.nonce
				},
				success: function (response) {
					ReportedIPWizard.clearSession();
					if (response.success && response.data.redirect_url) {
						window.location.href = response.data.redirect_url;
					} else {
						window.location.href = reportedipWizard.dashboardUrl;
					}
				},
				error: function () {
					window.location.href = reportedipWizard.dashboardUrl;
				}
			});
		},

		// ========================================================================
		// Session cache
		// ========================================================================

		getSession: function () {
			try {
				var raw = window.sessionStorage.getItem(STORAGE_KEY);
				return raw ? JSON.parse(raw) : {};
			} catch (e) {
				return {};
			}
		},

		setSession: function (partial) {
			try {
				var current = this.getSession();
				var merged = $.extend({}, current, partial);
				window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(merged));
			} catch (e) {
				/* swallow quota errors */
			}
		},

		clearSession: function () {
			try {
				window.sessionStorage.removeItem(STORAGE_KEY);
			} catch (e) {
				/* noop */
			}
		},

		// On step re-mount: restore saved values into the form fields
		restoreFromSession: function () {
			var session = this.getSession();

			// Step 2: API-Key wiederherstellen (falls in Session)
			if (session.apiKey && $('#rip-api-key').length && !$('#rip-api-key').val()) {
				$('#rip-api-key').val(session.apiKey);
			}

			// Step 3: Monitoring toggles
			if ($('#rip-monitor-logins').length) {
				if (typeof session.monitor_failed_logins !== 'undefined') {
					$('#rip-monitor-logins').prop('checked', !!parseInt(session.monitor_failed_logins, 10));
				}
				if (typeof session.monitor_comments !== 'undefined') {
					$('#rip-monitor-comments').prop('checked', !!parseInt(session.monitor_comments, 10));
				}
				if (typeof session.monitor_xmlrpc !== 'undefined') {
					$('#rip-monitor-xmlrpc').prop('checked', !!parseInt(session.monitor_xmlrpc, 10));
				}
				if (typeof session.monitor_app_passwords !== 'undefined') {
					$('#rip-monitor-app-passwords').prop('checked', !!parseInt(session.monitor_app_passwords, 10));
				}
				if (typeof session.monitor_rest_api !== 'undefined') {
					$('#rip-monitor-rest-api').prop('checked', !!parseInt(session.monitor_rest_api, 10));
				}
				if (typeof session.block_user_enumeration !== 'undefined') {
					$('#rip-block-user-enumeration').prop('checked', !!parseInt(session.block_user_enumeration, 10));
				}
				if (typeof session.monitor_404_scans !== 'undefined') {
					$('#rip-monitor-404-scans').prop('checked', !!parseInt(session.monitor_404_scans, 10));
				}
				if (typeof session.monitor_geo_anomaly !== 'undefined') {
					$('#rip-monitor-geo-anomaly').prop('checked', !!parseInt(session.monitor_geo_anomaly, 10));
				}
				if (typeof session.auto_block !== 'undefined') {
					$('#rip-auto-block').prop('checked', !!parseInt(session.auto_block, 10));
				}
				if (typeof session.block_escalation_enabled !== 'undefined') {
					$('#rip-block-escalation').prop('checked', !!parseInt(session.block_escalation_enabled, 10));
				}
				if (typeof session.report_only_mode !== 'undefined') {
					$('#rip-report-only').prop('checked', !!parseInt(session.report_only_mode, 10));
				}
				if (session.protection_level) {
					$('input[name="protection_level"][value="' + session.protection_level + '"]').prop('checked', true);
				}
				this.updateMonitoringWarning();
			}

			// Step 4: 2FA
			if ($('#rip-2fa-enabled').length) {
				if (typeof session['2fa_enabled_global'] !== 'undefined') {
					$('#rip-2fa-enabled').prop('checked', !!parseInt(session['2fa_enabled_global'], 10));
				}
				if (session['2fa_methods']) {
					var methods = session['2fa_methods'].split(',').filter(function (m) { return m.length; });
					$('.rip-method-card').removeClass('rip-method-card--selected');
					methods.forEach(function (m) {
						$('.rip-method-card[data-method="' + m + '"]').addClass('rip-method-card--selected');
					});
					$('#rip-2fa-methods-input').val(methods.join(','));
				}
				if (session['2fa_enforce_role']) {
					$('input[name="2fa_enforce_role[]"]').prop('checked', false);
					var roles = Array.isArray(session['2fa_enforce_role']) ? session['2fa_enforce_role'] : [session['2fa_enforce_role']];
					roles.forEach(function (r) {
						$('input[name="2fa_enforce_role[]"][value="' + r + '"]').prop('checked', true);
					});
				}
				if (typeof session['2fa_trusted_devices'] !== 'undefined') {
					$('#rip-2fa-trusted-devices').prop('checked', !!parseInt(session['2fa_trusted_devices'], 10));
				}
				if (typeof session['2fa_frontend_onboarding'] !== 'undefined') {
					$('#rip-2fa-frontend-onboarding').prop('checked', !!parseInt(session['2fa_frontend_onboarding'], 10));
				}
				if (typeof session['2fa_notify_new_device'] !== 'undefined') {
					$('#rip-2fa-notify-new-device').prop('checked', !!parseInt(session['2fa_notify_new_device'], 10));
				}
				if (typeof session['2fa_xmlrpc_app_password_only'] !== 'undefined') {
					$('#rip-2fa-xmlrpc-app-password-only').prop('checked', !!parseInt(session['2fa_xmlrpc_app_password_only'], 10));
				}
				if (typeof session['2fa_enforce_grace_days'] !== 'undefined') {
					$('#rip-2fa-grace-days').val(parseInt(session['2fa_enforce_grace_days'], 10) || DEFAULTS.grace_days);
				}
				if (typeof session['2fa_max_skips'] !== 'undefined') {
					$('#rip-2fa-max-skips').val(parseInt(session['2fa_max_skips'], 10) || DEFAULTS.max_skips);
				}
				this.update2faEnabledState();
			}
		},

		// ========================================================================
		// Helpers
		// ========================================================================

		formatRole: function (role) {
			if (!role) return '-';
			var roleMap = {
				'reportedip_free': 'Free',
				'reportedip_contributor': 'Contributor',
				'reportedip_professional': 'Professional',
				'reportedip_enterprise': 'Enterprise',
				'reportedip_honeypot': 'Honeypot'
			};
			return roleMap[role] || role.replace('reportedip_', '').replace(/_/g, ' ').replace(/\b\w/g, function (l) {
				return l.toUpperCase();
			});
		},

		formatNumber: function (num) {
			if (num === undefined || num === null || num === '') return '-';
			if (num === -1 || num === '-1') return 'Unbegrenzt';
			return parseInt(num, 10).toLocaleString();
		}
	};

	$(document).ready(function () {
		ReportedIPWizard.init();
	});

})(jQuery);
