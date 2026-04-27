/**
 * Browser-side controller for the Settings Import/Export panel.
 *
 * Wires up the export form (lets the browser handle the JSON download
 * via standard form submit) and turns the import form into a two-step
 * preview-then-apply flow without a page reload.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     1.2.0
 */
(function ($) {
	'use strict';

	if (!$ || !window.reportedip_hive_ajax) {
		return;
	}

	var ajaxUrl = window.reportedip_hive_ajax.ajax_url;

	function escape(value) {
		if (value === null || value === undefined) {
			return '';
		}
		var str = typeof value === 'string' ? value : JSON.stringify(value);
		return str
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;')
			.replace(/"/g, '&quot;')
			.replace(/'/g, '&#39;');
	}

	function renderPreview(meta, diffs, file) {
		var $out = $('#rip-import-preview');
		$out.empty();

		var changedTotal = 0;
		Object.keys(diffs).forEach(function (slug) {
			diffs[slug].forEach(function (row) {
				if (row.status === 'changed') {
					changedTotal += 1;
				}
			});
		});

		var html = '';
		html += '<div class="rip-alert rip-alert--info">';
		html += '<strong>' + escape(meta.site_url || 'Unknown source') + '</strong> · ';
		html += escape(meta.exported_at || '') + ' · ';
		html += changedTotal + ' value(s) will change';
		html += '</div>';

		if (changedTotal === 0) {
			html += '<p>This file matches the current settings exactly. Nothing to import.</p>';
			$out.html(html);
			return;
		}

		html += '<form id="rip-apply-form" enctype="multipart/form-data">';
		html += '<table class="rip-table"><thead><tr>';
		html += '<th>Section</th><th>Setting</th><th>Current</th><th>From file</th>';
		html += '</tr></thead><tbody>';

		Object.keys(diffs).forEach(function (slug) {
			var rows = diffs[slug] || [];
			var sectionLabel = slug.replace(/_/g, ' ');
			var firstRow = true;
			rows.forEach(function (row) {
				if (row.status === 'unchanged') {
					return;
				}
				html += '<tr>';
				html += '<td>' + (firstRow ? '<label class="rip-section-pick rip-section-pick--inline"><input type="checkbox" name="sections[]" value="' + escape(slug) + '" checked /> ' + escape(sectionLabel) + '</label>' : '') + '</td>';
				html += '<td><code>' + escape(row.key) + '</code></td>';
				html += '<td><code>' + escape(row.current) + '</code></td>';
				html += '<td><code>' + escape(row.incoming) + '</code></td>';
				html += '</tr>';
				firstRow = false;
			});
		});

		html += '</tbody></table>';
		html += '<button type="submit" class="rip-button rip-button--primary rip-mt-3">Apply selected sections</button>';
		html += '<div id="rip-apply-result" class="rip-mt-3"></div>';
		html += '</form>';

		$out.html(html);

		var $applyForm = $('#rip-apply-form');
		$applyForm.on('submit', function (e) {
			e.preventDefault();
			submitApply($applyForm, file);
		});
	}

	function submitApply($form, file) {
		var fd = new FormData();
		fd.append('action', 'reportedip_hive_import_settings_apply');
		fd.append('_rip_ie_nonce', $('#rip-import-form input[name="_rip_ie_nonce"]').val());
		fd.append('settings_file', file);
		$form.find('input[name="sections[]"]:checked').each(function () {
			fd.append('sections[]', this.value);
		});

		$('#rip-apply-result').html('<em>Applying…</em>');

		$.ajax({
			url: ajaxUrl,
			type: 'POST',
			data: fd,
			contentType: false,
			processData: false,
			dataType: 'json'
		}).done(function (resp) {
			if (resp && resp.success) {
				var d = resp.data || {};
				var msg = '<div class="rip-alert rip-alert--success">';
				msg += 'Imported. ' + (d.written || 0) + ' values written';
				if (d.ip_added) {
					msg += ', ' + d.ip_added + ' IPs added';
				}
				if (d.skipped || d.ip_skipped) {
					msg += ' (' + ((d.skipped || 0) + (d.ip_skipped || 0)) + ' skipped)';
				}
				msg += '. Reload the page to see the new values.';
				msg += '</div>';
				$('#rip-apply-result').html(msg);
			} else {
				$('#rip-apply-result').html('<div class="rip-alert rip-alert--error">' + escape((resp && resp.data && resp.data.message) || 'Import failed.') + '</div>');
			}
		}).fail(function () {
			$('#rip-apply-result').html('<div class="rip-alert rip-alert--error">Network error.</div>');
		});
	}

	$(function () {
		var $importForm = $('#rip-import-form');
		if (!$importForm.length) {
			return;
		}

		$importForm.on('submit', function (e) {
			e.preventDefault();
			var fileInput = document.getElementById('rip-import-file');
			if (!fileInput || !fileInput.files || !fileInput.files[0]) {
				$('#rip-import-preview').html('<div class="rip-alert rip-alert--warning">Please choose a file first.</div>');
				return;
			}
			var file = fileInput.files[0];

			var fd = new FormData();
			fd.append('action', 'reportedip_hive_import_settings_preview');
			fd.append('_rip_ie_nonce', $importForm.find('input[name="_rip_ie_nonce"]').val());
			fd.append('settings_file', file);

			$('#rip-import-preview').html('<em>Reading file…</em>');

			$.ajax({
				url: ajaxUrl,
				type: 'POST',
				data: fd,
				contentType: false,
				processData: false,
				dataType: 'json'
			}).done(function (resp) {
				if (resp && resp.success) {
					renderPreview(resp.data.meta || {}, resp.data.diffs || {}, file);
				} else {
					$('#rip-import-preview').html('<div class="rip-alert rip-alert--error">' + escape((resp && resp.data && resp.data.message) || 'Could not read file.') + '</div>');
				}
			}).fail(function () {
				$('#rip-import-preview').html('<div class="rip-alert rip-alert--error">Network error.</div>');
			});
		});
	});
})(window.jQuery);
