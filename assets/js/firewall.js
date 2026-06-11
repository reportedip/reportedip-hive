/**
 * Firewall page interactions.
 *
 * Delegated handlers driven by data attributes replace the per-tab inline
 * scripts: `data-rip-action` buttons and selects post the named AJAX action,
 * `data-rip-copy` buttons copy a target element to the clipboard, and the
 * security-headers bulk save serialises every `[data-opt]` field. On success
 * the page reloads (after surfacing a server message, when present); on
 * failure the error is shown and the page is left untouched.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     2.1.2
 */

(function ($) {
	'use strict';

	var config  = window.reportedip_hive_ajax || {};
	var strings = config.strings || {};

	function showError(response) {
		var message = response && response.data && response.data.message
			? response.data.message
			: (strings.generic_error || 'Error');
		window.alert(message);
	}

	function postAction(payload, $control) {
		$control.prop('disabled', true);
		$.post(config.ajax_url, payload, function (response) {
			$control.prop('disabled', false);
			if (!response || !response.success) {
				showError(response);
				return;
			}
			if (response.data && response.data.message) {
				window.alert(response.data.message);
			}
			window.location.reload();
		}).fail(function () {
			$control.prop('disabled', false);
			window.alert(strings.request_failed || 'Request failed.');
		});
	}

	$(document).on('click', 'button[data-rip-action]', function (e) {
		e.preventDefault();
		var $button = $(this);
		var payload = { action: $button.data('rip-action'), nonce: config.nonce };
		if ($button.data('rip-field')) {
			payload.field = $button.data('rip-field');
		}
		postAction(payload, $button);
	});

	$(document).on('change', 'select[data-rip-action]', function () {
		var $select = $(this);
		var payload = { action: $select.data('rip-action'), nonce: config.nonce };
		payload[$select.data('rip-param') || 'value'] = $select.val();
		postAction(payload, $select);
	});

	$(document).on('click', '[data-rip-copy]', function (e) {
		e.preventDefault();
		var $button = $(this);
		var target  = document.querySelector($button.data('rip-copy'));
		if (target && navigator.clipboard) {
			navigator.clipboard.writeText(target.textContent).then(function () {
				$button.addClass('rip-button--copied');
				window.setTimeout(function () {
					$button.removeClass('rip-button--copied');
				}, 1200);
			});
		}
	});

	$(document).on('click', '.rip-csp-preset', function (e) {
		e.preventDefault();
		$('#rip-hdr-csp').val($(this).data('policy'));
	});

	$(document).on('click', '#rip-headers-save', function (e) {
		e.preventDefault();
		var $button = $(this);
		var values  = {};
		$('.rip-content [data-opt]').each(function () {
			values[$(this).data('opt')] = $(this).val();
		});
		postAction(
			{
				action: 'reportedip_hive_headers_save',
				payload: JSON.stringify(values),
				nonce: config.nonce
			},
			$button
		);
	});
})(jQuery);
