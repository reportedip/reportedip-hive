/**
 * Users screen: turns the "Reset 2FA" row action into a POST to
 * admin-post.php on click, so the destructive action stays off the GET
 * surface while it still lives in the row-actions markup of WordPress.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     3.0.0
 */
(function () {
	document.addEventListener('click', function (e) {
		var a = e.target.closest('.rip-2fa-admin-reset');
		if (!a) {
			return;
		}
		e.preventDefault();
		if (!window.confirm(a.getAttribute('data-confirm'))) {
			return;
		}
		var f = document.createElement('form');
		f.method = 'post';
		f.action = a.getAttribute('data-post');
		f.style.display = 'none';
		[
			['action', 'reportedip_hive_2fa_admin_reset'],
			['user_id', a.getAttribute('data-user')],
			['_wpnonce', a.getAttribute('data-nonce')]
		].forEach(function (pair) {
			var i = document.createElement('input');
			i.type = 'hidden';
			i.name = pair[0];
			i.value = pair[1];
			f.appendChild(i);
		});
		document.body.appendChild(f);
		f.submit();
	});
})();
