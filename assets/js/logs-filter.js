/**
 * Activity page: type-ahead over the event-type select.
 *
 * The select carries every event type the plugin writes, which is too many to
 * scroll. The box filters options by their label, their slug and their group
 * name, so "firewall" narrows the list to that group and "form" finds the form
 * events wherever they sit. Each group also has an entry that selects the whole
 * group, the server expands it into an IN() clause.
 *
 * The box is rendered hidden and only revealed here, so a browser without
 * JavaScript keeps a plain select instead of a dead input.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     2.1.62
 */
(function () {
	'use strict';

	var input = document.getElementById('rip-log-event-search');
	var select = document.getElementById('rip-log-event-type');
	if (!input || !select) {
		return;
	}

	input.hidden = false;

	function haystack(option) {
		if (!option.dataset.ripSearch) {
			option.dataset.ripSearch = (option.textContent + ' ' + option.value).toLowerCase();
		}
		return option.dataset.ripSearch;
	}

	function filter() {
		var term = input.value.trim().toLowerCase();

		Array.prototype.forEach.call(select.children, function (node) {
			if (node.tagName !== 'OPTGROUP') {
				return;
			}

			var groupMatch = !term || node.label.toLowerCase().indexOf(term) >= 0;
			var hits = 0;

			Array.prototype.forEach.call(node.children, function (option) {
				var match = groupMatch || haystack(option).indexOf(term) >= 0 || option.selected;
				option.hidden = !match;
				if (match) {
					hits += 1;
				}
			});

			node.hidden = hits === 0;
		});
	}

	input.addEventListener('input', filter);

	/**
	 * Enter inside the box would submit the filter form with whatever is
	 * selected, which is rarely what someone means while still typing.
	 */
	input.addEventListener('keydown', function (event) {
		if (event.key === 'Enter') {
			event.preventDefault();
			select.focus();
		}
	});
}());
