/**
 * ReportedIP Hive — Setup Wizard JavaScript.
 *
 * Each step's form is collected generically from the active step container and
 * persisted server-side before navigating, via the `reportedip_wizard_save_step`
 * AJAX endpoint. There is no sessionStorage staging: the database is the single
 * source of truth, so Back/forward/reload always reflect what was saved. Field
 * sanitisation + mapping lives in ReportedIP_Hive_Wizard_Schema (PHP).
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     1.1.0
 */

(function ($) {
	'use strict';

	var FIELD_STEPS = [ 3, 4, 5, 6, 7, 8 ];

	var ReportedIPWizard = {

		init: function () {
			if (!document.body || !document.body.classList.contains('rip-wizard-page')) {
				return;
			}
			this.bindEvents();
			this.initModeSelection();
			this.updateMonitoringWarning();
			this.updateBlockStrategyState();
			this.update2faEnabledState();
			this.update2faMethodsHidden();
			this.initStep7();
			this.initPromotePreview();
			this.initStep9();
		},

		bindEvents: function () {
			// Step 2: mode selection
			$(document).on('click', '.rip-mode-card', this.handleModeCardClick.bind(this));
			$(document).on('click', '#rip-continue-mode', this.handleContinueMode.bind(this));

			// Step 2: API key
			$(document).on('click', '#rip-validate-key', this.handleValidateApiKey.bind(this));
			$(document).on('keypress', '#rip-api-key', this.handleApiKeyEnter.bind(this));

			// Step 3: monitoring toggles → warning banner + block-strategy state
			$(document).on('change', '#rip-monitor-logins, #rip-monitor-comments, #rip-monitor-xmlrpc', this.updateMonitoringWarning.bind(this));
			$(document).on('change', '#rip-auto-block', this.updateBlockStrategyState.bind(this));

			// Step 4: 2FA method-card multi-select + enabled state
			$(document).on('click', '.rip-method-card', this.handleMethodCardClick.bind(this));
			$(document).on('change', '#rip-2fa-enabled', this.update2faEnabledState.bind(this));

			// Step 7: live slug validation + toggle-driven enable state
			$(document).on('input', '#rip-hide-login-slug', this.debounceValidateSlug.bind(this));
			$(document).on('change', '#rip-hide-login-enabled', this.toggleHideLoginFields.bind(this));

			// Skip wizard
			$(document).on('click', '#rip-skip-wizard', this.handleSkipWizard.bind(this));

			// Generic save-then-navigate for every step nav control. Back/forward
			// links carry the target in href; the standalone Save buttons advance
			// to the next step. The promote "Skip" link navigates without saving.
			$(document).on('click', '.rip-wizard__actions a[href*="step="]', function (e) {
				if (this.id === 'rip-promote-skip') {
					return;
				}
				e.preventDefault();
				ReportedIPWizard.saveAndGo(this.getAttribute('href'));
			});
			$(document).on('click', '#rip-notify-continue, #rip-save-config, #rip-promote-continue', function (e) {
				e.preventDefault();
				ReportedIPWizard.saveAndGo(ReportedIPWizard.stepUrl(ReportedIPWizard.currentStep() + 1));
			});
		},

		// ========================================================================
		// Per-step server-side persistence
		// ========================================================================

		currentStep: function () {
			var el = document.querySelector('.rip-wizard__step-content');
			return el ? (parseInt(el.getAttribute('data-step'), 10) || 0) : 0;
		},

		stepUrl: function (n) {
			var base = reportedipWizard.wizardBaseUrl || '';
			return base + (base.indexOf('?') === -1 ? '?' : '&') + 'step=' + n;
		},

		stepFromUrl: function (url) {
			var m = /[?&]step=(\d+)/.exec(url || '');
			return m ? parseInt(m[1], 10) : 0;
		},

		collectStep: function ($container) {
			var data = {};
			$container.find(':input').each(function () {
				var $el = $(this);
				var name = $el.attr('name');
				if (!name) {
					return;
				}
				if ($el.is(':checkbox')) {
					if (name.slice(-2) === '[]') {
						var arrayKey = name.slice(0, -2);
						if ($el.is(':checked')) {
							if (!data[arrayKey]) { data[arrayKey] = []; }
							data[arrayKey].push($el.val());
						}
					} else {
						data[name] = $el.is(':checked') ? 1 : 0;
					}
				} else if ($el.is(':radio')) {
					if ($el.is(':checked')) { data[name] = $el.val(); }
				} else {
					data[name] = $el.val();
				}
			});
			return data;
		},

		/**
		 * Step-4 guard: when 2FA is on the user must keep at least one method;
		 * an empty role list silently falls back to administrator. Only enforced
		 * when moving forward so Back never traps the user.
		 */
		validateStep4: function (data, forward) {
			if (!forward || !data['2fa_enabled_global']) {
				return true;
			}
			var methods = (data['2fa_methods'] || '').split(',').filter(function (m) { return m.length; });
			if (!methods.length) {
				alert((reportedipWizard.strings && reportedipWizard.strings.no2faMethod) || 'Please choose at least one method.');
				return false;
			}
			if (!data['2fa_enforce_role'] || !data['2fa_enforce_role'].length) {
				$('input[name="2fa_enforce_role[]"][value="administrator"]').prop('checked', true);
				data['2fa_enforce_role'] = ['administrator'];
			}
			return true;
		},

		saveAndGo: function (target) {
			var step = this.currentStep();
			if (FIELD_STEPS.indexOf(step) === -1) {
				window.location.href = target;
				return;
			}

			var data = this.collectStep($('.rip-wizard__step-content'));
			var forward = this.stepFromUrl(target) > step;
			if (step === 4 && !this.validateStep4(data, forward)) {
				return;
			}

			data.action = 'reportedip_wizard_save_step';
			data.nonce = reportedipWizard.nonce;
			data.step = step;

			$.ajax({
				url: reportedipWizard.ajaxUrl,
				type: 'POST',
				data: data,
				success: function (response) {
					if (response && response.success) {
						window.location.href = target;
					} else {
						alert((response && response.data && response.data.message) || (reportedipWizard.strings && reportedipWizard.strings.errorGeneric) || 'Error');
					}
				},
				error: function () {
					alert((reportedipWizard.strings && reportedipWizard.strings.errorRetry) || 'Error. Please try again.');
				}
			});
		},

		// ========================================================================
		// Step 2: Mode + API-Key
		// ========================================================================

		_validatedApiKey: null,

		initModeSelection: function () {
			if (reportedipWizard && reportedipWizard.savedApiKey) {
				this._validatedApiKey = reportedipWizard.savedApiKey;
				this.tier = (reportedipWizard.tier || '').toLowerCase();
			}

			var $selectedCard = $('.rip-mode-card--selected');
			if ($selectedCard.length) {
				this.toggleApiKeyCard($selectedCard.data('mode'));
				this.refreshContinueButton();
			} else {
				this.updateContinueButton(false);
			}

			$(document).on('input', '#rip-api-key', this.refreshContinueButton.bind(this));
		},

		handleModeCardClick: function (e) {
			var $card = $(e.currentTarget);
			var mode = $card.data('mode');

			$('.rip-mode-card').removeClass('rip-mode-card--selected');
			$card.addClass('rip-mode-card--selected');

			$('#rip-selected-mode').val(mode);
			this.toggleApiKeyCard(mode);
			this.refreshContinueButton();
		},

		toggleApiKeyCard: function (mode) {
			$('#rip-api-key-card').toggleClass('rip-is-hidden', mode !== 'community');
		},

		updateContinueButton: function (enabled) {
			$('#rip-continue-mode').prop('disabled', !enabled);
		},

		/**
		 * Step 2 Next-button gate: Local mode → always allow once a card is
		 * picked. Community mode → require a successful key-validation that
		 * still matches the current input value (we invalidate on edit).
		 */
		refreshContinueButton: function () {
			var $selectedCard = $('.rip-mode-card--selected');
			if (!$selectedCard.length) {
				this.updateContinueButton(false);
				return;
			}
			var mode = $selectedCard.data('mode');
			if (mode !== 'community') {
				this.updateContinueButton(true);
				return;
			}
			var apiKey = ($('#rip-api-key').val() || '').trim();
			var ok = apiKey.length > 0 && apiKey === this._validatedApiKey;
			this.updateContinueButton(ok);
			$('#rip-api-key-gate-hint').toggleClass('rip-is-hidden', ok);
		},

		handleContinueMode: function (e) {
			e.preventDefault();
			var mode = $('#rip-selected-mode').val();
			var $button = $(e.currentTarget);

			if (!mode) { return; }

			$button.prop('disabled', true);
			var originalText = $button.html();
			$button.html('<span class="rip-spinner"></span> ' + (reportedipWizard.strings.saving || 'Saving…'));

			$.ajax({
				url: reportedipWizard.ajaxUrl,
				type: 'POST',
				data: {
					action: 'reportedip_wizard_save_mode',
					nonce: reportedipWizard.nonce,
					mode: mode,
					api_key: 'community' === mode ? ($('#rip-api-key').val() || '').trim() : ''
				},
				success: function (response) {
					if (response.success && response.data.redirect_url) {
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

						ReportedIPWizard._validatedApiKey = apiKey;
						ReportedIPWizard.tier = (response.data.tier || response.data.user_role || '').toLowerCase();
						ReportedIPWizard.refreshContinueButton();
					} else {
						$input.addClass('rip-input--invalid').removeClass('rip-input--valid');
						var message = (response.data && response.data.message) ? response.data.message : (reportedipWizard.strings.invalid || 'Invalid API key.');
						$status.html('<span class="rip-input-status--error"><svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg> ' + message + '</span>');
						$apiInfo.addClass('rip-is-hidden');
						ReportedIPWizard._validatedApiKey = null;
						ReportedIPWizard.refreshContinueButton();
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

		updateBlockStrategyState: function () {
			var $autoBlock = $('#rip-auto-block');
			var $strategy = $('#rip-block-duration-strategy');
			if (!$autoBlock.length || !$strategy.length) { return; }
			$strategy.toggleClass('rip-is-disabled', !$autoBlock.is(':checked'));
		},

		updateMonitoringWarning: function () {
			if (!$('#rip-monitor-logins').length) { return; }
			var anyActive = $('#rip-monitor-logins').is(':checked')
				|| $('#rip-monitor-comments').is(':checked')
				|| $('#rip-monitor-xmlrpc').is(':checked');
			$('#rip-monitoring-warning').toggleClass('is-visible', !anyActive);
		},

		// ========================================================================
		// Step 4: 2FA
		// ========================================================================

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

		// ========================================================================
		// Step 7: Hide Login (slug validation)
		// ========================================================================

		initStep7: function () {
			if (!$('#rip-hide-login-enabled').length) { return; }
			this.toggleHideLoginFields();
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
			var $msg = $('#rip-hide-login-validation');
			var slug = ($slug.val() || '').toLowerCase().trim();
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

		// ========================================================================
		// Step 8: Promote — live preview of the footer badge
		// ========================================================================

		initPromotePreview: function () {
			var preview = document.getElementById('rip-promote-preview');
			if (!preview) { return; }

			var initial = preview.querySelector('rip-hive-banner');
			var label = initial ? (initial.getAttribute('data-label') || '') : '';

			function currentAlign() {
				var align = 'center';
				document.querySelectorAll('input[name="promote_align"]').forEach(function (r) {
					if (r.checked) { align = r.value; }
				});
				return align;
			}

			function render() {
				var variant = 'badge';
				document.querySelectorAll('input[name="promote_variant"]').forEach(function (r) {
					if (r.checked) { variant = r.value; }
				});
				var align = currentAlign();
				var elementAlign = align === 'below' ? 'center' : align;
				preview.classList.remove('rip-promote-preview--left', 'rip-promote-preview--center', 'rip-promote-preview--right', 'rip-promote-preview--below');
				preview.classList.add('rip-promote-preview--' + align);
				preview.innerHTML = '';
				var el = document.createElement('rip-hive-banner');
				el.setAttribute('data-variant', variant);
				el.setAttribute('data-stat', 'attacks_30d');
				el.setAttribute('data-value', '');
				el.setAttribute('data-label', label);
				el.setAttribute('data-mode', 'local');
				el.setAttribute('data-theme', 'dark');
				el.setAttribute('data-align', elementAlign);
				el.setAttribute('data-href', 'https://reportedip.de/?utm_source=hive&utm_medium=wizard-preview&utm_campaign=protected&utm_content=' + variant);
				preview.appendChild(el);
			}

			document.querySelectorAll('input[name="promote_variant"], input[name="promote_align"]').forEach(function (r) {
				r.addEventListener('change', render);
			});
		},

		// ========================================================================
		// Step 9: Setup-complete celebration trigger
		// ========================================================================

		initStep9: function () {
			var $complete = $('.rip-wizard__complete');
			if (!$complete.length) { return; }
			window.requestAnimationFrame(function () {
				$complete.addClass('rip-wizard__complete--play');
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
		// Helpers
		// ========================================================================

		formatRole: function (role) {
			if (!role) return '-';
			var roleMap = {
				'reportedip_free': 'Free',
				'reportedip_contributor': 'Contributor',
				'reportedip_professional': 'Professional',
				'reportedip_business': 'Business',
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
