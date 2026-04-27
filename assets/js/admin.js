/**
 * ReportedIP Hive Admin JavaScript.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

(function($) {
    'use strict';

    /**
     * HTML-escape a value for safe interpolation into innerHTML/.html() strings.
     * Defense-in-depth: AJAX responses (especially those proxied from the remote
     * community API) must never be trusted as raw HTML.
     */
    function escapeHtml(value) {
        if (value === null || value === undefined) {
            return '';
        }
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    // Main admin object
    const ReportedIPAdmin = {
        
        init: function() {
            this.bindEvents();
            this.initTooltips();

            // Debug / System Status page handlers
            if ($('#test-api-connection-debug').length || $('#test-database-connection').length) {
                this.initDebugTests();
            }
        },

        bindEvents: function() {
            // API connection test
            $(document).on('click', '#test-api-connection, #test-api-connection-general', this.testApiConnection);

            // IP management actions
            $(document).on('click', '.remove-whitelist', this.removeFromWhitelist);
            $(document).on('click', '.unblock-ip', this.unblockIP);
            $(document).on('click', '.whitelist-ip', this.whitelistIP);
            $(document).on('click', '.lookup-ip', this.lookupIP);
            $(document).on('click', '.block-ip', this.blockIPFromLogs);
            $(document).on('click', '.copy-ip', this.copyIPToClipboard);

            // Form submissions
            $(document).on('submit', '#add-whitelist-form', this.addToWhitelist);
            $(document).on('submit', '#block-ip-form', this.blockIP);

            // Lookup button on the lookup tab
            $(document).on('click', '#lookup-ip-button', this.performLookupTabSearch);

            // CSV Import
            $(document).on('submit', '#import-blocked-csv-form', function(e) {
                e.preventDefault();
                ReportedIPAdmin.importCSV(this, 'reportedip_hive_import_blocked_csv');
            });
            $(document).on('submit', '#import-whitelist-csv-form', function(e) {
                e.preventDefault();
                ReportedIPAdmin.importCSV(this, 'reportedip_hive_import_whitelist_csv');
            });

            // Maintenance actions
            $(document).on('click', '#cleanup-old-logs', this.cleanupOldLogs);
            $(document).on('click', '#anonymize-old-data', this.anonymizeOldData);
            $(document).on('click', '#export-logs-csv', this.exportLogs.bind(this, 'csv'));
            $(document).on('click', '#export-logs-json', this.exportLogs.bind(this, 'json'));

            // Mode card selection
            $(document).on('change', 'input[name="reportedip_hive_operation_mode"]', this.handleModeChange);
        },

        /**
         * Initialize debug/system status page test handlers
         */
        initDebugTests: function() {
            var nonce = reportedip_hive_ajax.nonce;
            var successIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg> ';
            var errorIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg> ';

            // Database test (only rendered when WP_DEBUG is active)
            $('#test-database-connection').on('click', function() {
                var $btn = $(this);
                $btn.prop('disabled', true);
                $('#system-test-results').html('<div class="rip-test-loading">Testing database...</div>');

                $.post(ajaxurl, {
                    action: 'reportedip_hive_test_database',
                    nonce: nonce
                }, function(response) {
                    $btn.prop('disabled', false);
                    if (response.success) {
                        $('#system-test-results').html('<div class="rip-test-success">' + successIcon + 'Database connection successful!</div>');
                    } else {
                        $('#system-test-results').html('<div class="rip-test-error">' + errorIcon + escapeHtml(response.data || 'Test failed') + '</div>');
                    }
                }).fail(function() {
                    $btn.prop('disabled', false);
                    $('#system-test-results').html('<div class="rip-test-error">' + errorIcon + 'Request failed. Check server logs.</div>');
                });
            });

            // API test on debug page
            $('#test-api-connection-debug').on('click', function() {
                var $btn = $(this);
                $btn.prop('disabled', true);
                $('#system-test-results').html('<div class="rip-test-loading">Testing API connection...</div>');

                $.post(ajaxurl, {
                    action: 'reportedip_hive_test_connection',
                    nonce: nonce
                }, function(response) {
                    $btn.prop('disabled', false);
                    if (response.success) {
                        var msg = (response.data && response.data.message) ? response.data.message : 'API connection successful!';
                        $('#system-test-results').html('<div class="rip-test-success">' + successIcon + escapeHtml(msg) + '</div>');
                    } else {
                        $('#system-test-results').html('<div class="rip-test-error">' + errorIcon + escapeHtml(response.data || 'API test failed') + '</div>');
                    }
                }).fail(function() {
                    $btn.prop('disabled', false);
                    $('#system-test-results').html('<div class="rip-test-error">' + errorIcon + 'Request failed. Check API endpoint configuration.</div>');
                });
            });

            // Reset settings
            $('#reset-settings').on('click', function() {
                if (!confirm(reportedip_hive_ajax.strings.confirm_reset_settings || 'Are you sure you want to reset all settings to defaults?')) {
                    return;
                }

                var $btn = $(this);
                $btn.prop('disabled', true);
                $('#reset-results').html('<div class="rip-test-loading">Resetting settings...</div>');

                $.post(ajaxurl, {
                    action: 'reportedip_hive_reset_settings',
                    nonce: nonce
                }, function(response) {
                    $btn.prop('disabled', false);
                    if (response.success) {
                        $('#reset-results').html('<div class="rip-test-success">' + successIcon + escapeHtml(response.data) + '</div>');
                        setTimeout(function() { location.reload(); }, 2000);
                    } else {
                        $('#reset-results').html('<div class="rip-test-error">' + escapeHtml(response.data || 'Reset failed') + '</div>');
                    }
                }).fail(function() {
                    $btn.prop('disabled', false);
                    $('#reset-results').html('<div class="rip-test-error">Request failed</div>');
                });
            });

            // Reset all data
            $('#reset-all-data').on('click', function() {
                if (!confirm(reportedip_hive_ajax.strings.confirm_uninstall_warn || 'WARNING: This will delete ALL plugin data. This cannot be undone!')) {
                    return;
                }
                if (!confirm(reportedip_hive_ajax.strings.confirm_uninstall_final || 'Are you absolutely sure?')) {
                    return;
                }

                var $btn = $(this);
                $btn.prop('disabled', true);
                $('#reset-results').html('<div class="rip-test-loading">Deleting all data...</div>');

                $.post(ajaxurl, {
                    action: 'reportedip_hive_reset_all_data',
                    nonce: nonce
                }, function(response) {
                    $btn.prop('disabled', false);
                    if (response.success) {
                        $('#reset-results').html('<div class="rip-test-success">' + successIcon + escapeHtml(response.data) + '</div>');
                        setTimeout(function() { location.reload(); }, 2000);
                    } else {
                        $('#reset-results').html('<div class="rip-test-error">' + escapeHtml(response.data || 'Reset failed') + '</div>');
                    }
                }).fail(function() {
                    $btn.prop('disabled', false);
                    $('#reset-results').html('<div class="rip-test-error">Request failed</div>');
                });
            });
        },

        /**
         * Handle operation mode change
         */
        handleModeChange: function(e) {
            var $input = $(this);
            var newMode = $input.val();
            var $cards = $('.rip-mode-card');

            // Update UI immediately
            $cards.removeClass('rip-mode-card--selected');
            $input.closest('.rip-mode-card').addClass('rip-mode-card--selected');

            // Show loading state
            $cards.css('opacity', '0.7').css('pointer-events', 'none');

            // Save mode via AJAX
            $.ajax({
                url: reportedip_hive_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'reportedip_hive_set_mode',
                    nonce: reportedip_hive_ajax.nonce,
                    mode: newMode
                },
                success: function(response) {
                    $cards.css('opacity', '1').css('pointer-events', 'auto');

                    if (response.success) {
                        // Show success notification
                        ReportedIPAdmin.showNotification(
                            response.data.message || 'Mode changed successfully',
                            'success'
                        );

                        // Reload page to reflect mode change
                        setTimeout(function() {
                            window.location.reload();
                        }, 1000);
                    } else {
                        ReportedIPAdmin.showNotification(
                            response.data.message || 'Failed to change mode',
                            'error'
                        );
                    }
                },
                error: function() {
                    $cards.css('opacity', '1').css('pointer-events', 'auto');
                    ReportedIPAdmin.showNotification('Network error. Please try again.', 'error');
                }
            });
        },

        testApiConnection: function(e) {
            e.preventDefault();
            
            const $button = $(this);
            const $result = $('#api-test-result');
            
            $button.prop('disabled', true).text(reportedip_hive_ajax.strings.testing_connection);
            $result.removeClass('success error').hide();
            
            $.ajax({
                url: reportedip_hive_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'reportedip_hive_test_connection',
                    nonce: reportedip_hive_ajax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        let html = '<div class="api-key-info">';
                        html += '<h4><span style="color: #28a745;">✓</span> ' + reportedip_hive_ajax.strings.connection_successful + '</h4>';
                        
                        // Key information
                        if (response.key_name) {
                            html += '<div class="key-detail"><strong>Key Name:</strong> ' + escapeHtml(response.key_name) + '</div>';
                        }
                        if (response.user_role) {
                            html += '<div class="key-detail"><strong>Account Type:</strong> ' + escapeHtml(String(response.user_role).replace('reportedip_', '').replace('_', ' ').toUpperCase()) + '</div>';
                        }
                        
                        // API limits
                        if (response.daily_limit && response.remaining_calls) {
                            const usedCalls = response.daily_limit - response.remaining_calls;
                            const usagePercent = Math.round((usedCalls / response.daily_limit) * 100);
                            
                            html += '<div class="api-usage-bar">';
                            html += '<div class="usage-header">';
                            html += '<span><strong>Daily API Usage:</strong> ' + usedCalls + ' / ' + response.daily_limit + ' calls</span>';
                            html += '<span class="usage-percent">' + usagePercent + '%</span>';
                            html += '</div>';
                            html += '<div class="usage-bar-bg">';
                            html += '<div class="usage-bar-fill" style="width: ' + usagePercent + '%; background-color: ' + (usagePercent > 90 ? '#dc3545' : usagePercent > 70 ? '#ffc107' : '#28a745') + '"></div>';
                            html += '</div>';
                            html += '<div class="usage-remaining">Remaining: ' + response.remaining_calls + ' calls</div>';
                            html += '</div>';
                        }
                        
                        // Permissions
                        if (response.permissions && Array.isArray(response.permissions)) {
                            html += '<div class="key-detail"><strong>Permissions:</strong> ' + escapeHtml(response.permissions.join(', ')) + '</div>';
                        }
                        
                        // Features
                        if (response.features) {
                            html += '<div class="features-grid">';
                            const features = response.features;
                            const featureLabels = {
                                'canCheck': 'IP Reputation Check',
                                'canReport': 'Report IPs',
                                'canBulkCheck': 'Bulk IP Check',
                                'hasWhiteLabel': 'White Label'
                            };
                            
                            for (const [key, value] of Object.entries(features)) {
                                const label = featureLabels[key] || key;
                                const icon = value ? '✓' : '✗';
                                const color = value ? '#28a745' : '#6c757d';
                                html += '<div class="feature-item" style="color: ' + color + ';">' + icon + ' ' + escapeHtml(label) + '</div>';
                            }
                            html += '</div>';
                        }
                        
                        html += '</div>';
                        
                        $result.addClass('success').html(html).show();
                    } else {
                        $result.addClass('error').html(
                            '<div class="api-error">' +
                            '<h4><span style="color: #dc3545;">✗</span> ' + escapeHtml(reportedip_hive_ajax.strings.connection_failed) + '</h4>' +
                            '<div class="error-message">' + escapeHtml(response.message || 'Unknown error') + '</div>' +
                            (response.response_code ? '<div class="error-code">HTTP Status: ' + escapeHtml(response.response_code) + '</div>' : '') +
                            '</div>'
                        ).show();
                    }
                },
                error: function() {
                    $result.addClass('error').html(
                        '<div class="api-error">' +
                        '<h4><span style="color: #dc3545;">✗</span> ' + escapeHtml(reportedip_hive_ajax.strings.connection_failed) + '</h4>' +
                        '<div class="error-message">Network error occurred</div>' +
                        '</div>'
                    ).show();
                },
                complete: function() {
                    $button.prop('disabled', false).text('Test Connection');
                }
            });
        },

        addToWhitelist: function(e) {
            e.preventDefault();
            
            const $form = $(this);
            const formData = $form.serialize();
            
            ReportedIPAdmin.showLoading($form);
            
            $.ajax({
                url: reportedip_hive_ajax.ajax_url,
                type: 'POST',
                data: formData + '&action=reportedip_hive_add_whitelist&nonce=' + reportedip_hive_ajax.nonce,
                success: function(response) {
                    if (response.success) {
                        ReportedIPAdmin.showNotification('IP address added to whitelist successfully', 'success');
                        $form[0].reset();
                        window.location.reload();
                    } else {
                        ReportedIPAdmin.showNotification(response.data || 'Failed to add IP to whitelist', 'error');
                    }
                },
                error: function() {
                    ReportedIPAdmin.showNotification('Network error occurred', 'error');
                },
                complete: function() {
                    ReportedIPAdmin.hideLoading($form);
                }
            });
        },

        removeFromWhitelist: function(e) {
            e.preventDefault();
            
            if (!confirm('Are you sure you want to remove this IP from the whitelist?')) {
                return;
            }
            
            const $button = $(this);
            const ipAddress = $button.data('ip');
            
            $button.prop('disabled', true);
            
            $.ajax({
                url: reportedip_hive_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'reportedip_hive_remove_whitelist',
                    ip_address: ipAddress,
                    nonce: reportedip_hive_ajax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        ReportedIPAdmin.showNotification('IP address removed from whitelist', 'success');
                        $button.closest('tr').fadeOut(300, function() {
                            $(this).remove();
                        });
                    } else {
                        ReportedIPAdmin.showNotification(response.data || 'Failed to remove IP from whitelist', 'error');
                        $button.prop('disabled', false);
                    }
                },
                error: function() {
                    ReportedIPAdmin.showNotification('Network error occurred', 'error');
                    $button.prop('disabled', false);
                }
            });
        },

        blockIP: function(e) {
            e.preventDefault();
            
            const $form = $(this);
            const formData = $form.serialize();
            
            ReportedIPAdmin.showLoading($form);
            
            $.ajax({
                url: reportedip_hive_ajax.ajax_url,
                type: 'POST',
                data: formData + '&action=reportedip_hive_block_ip&nonce=' + reportedip_hive_ajax.nonce,
                success: function(response) {
                    if (response.success) {
                        ReportedIPAdmin.showNotification('IP address blocked successfully', 'success');
                        $form[0].reset();
                        window.location.reload();
                    } else {
                        ReportedIPAdmin.showNotification(response.data || 'Failed to block IP address', 'error');
                    }
                },
                error: function() {
                    ReportedIPAdmin.showNotification('Network error occurred', 'error');
                },
                complete: function() {
                    ReportedIPAdmin.hideLoading($form);
                }
            });
        },

        unblockIP: function(e) {
            e.preventDefault();
            
            if (!confirm(reportedip_hive_ajax.strings.confirm_unblock)) {
                return;
            }
            
            const $button = $(this);
            const ipAddress = $button.data('ip');
            
            $button.prop('disabled', true);
            
            $.ajax({
                url: reportedip_hive_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'reportedip_hive_unblock_ip',
                    ip_address: ipAddress,
                    nonce: reportedip_hive_ajax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        ReportedIPAdmin.showNotification('IP address unblocked successfully', 'success');
                        $button.closest('tr').fadeOut(300, function() {
                            $(this).remove();
                        });
                    } else {
                        ReportedIPAdmin.showNotification(response.data || 'Failed to unblock IP address', 'error');
                        $button.prop('disabled', false);
                    }
                },
                error: function() {
                    ReportedIPAdmin.showNotification('Network error occurred', 'error');
                    $button.prop('disabled', false);
                }
            });
        },

        whitelistIP: function(e) {
            e.preventDefault();

            if (!confirm(reportedip_hive_ajax.strings.confirm_whitelist)) {
                return;
            }

            const $button = $(this);
            const ipAddress = $button.data('ip');
            const reason = prompt(reportedip_hive_ajax.strings.prompt_whitelist_reason || 'Enter reason for whitelisting (optional):') || 'Manually whitelisted from blocked list';

            $button.prop('disabled', true);

            $.ajax({
                url: reportedip_hive_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'reportedip_hive_add_whitelist',
                    ip_address: ipAddress,
                    reason: reason,
                    nonce: reportedip_hive_ajax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        ReportedIPAdmin.showNotification('IP address whitelisted successfully', 'success');
                        $button.closest('tr').fadeOut(300, function() {
                            $(this).remove();
                        });
                    } else {
                        ReportedIPAdmin.showNotification(response.data || 'Failed to whitelist IP address', 'error');
                        $button.prop('disabled', false);
                    }
                },
                error: function() {
                    ReportedIPAdmin.showNotification('Network error occurred', 'error');
                    $button.prop('disabled', false);
                }
            });
        },

        blockIPFromLogs: function(e) {
            e.preventDefault();

            const $button = $(this);
            const ipAddress = $button.data('ip');

            if (!ipAddress) {
                ReportedIPAdmin.showNotification('No IP address found', 'error');
                return;
            }

            // Show prompt for reason
            const reason = prompt(reportedip_hive_ajax.strings.prompt_block_reason || 'Enter reason for blocking this IP:', reportedip_hive_ajax.strings.prompt_block_default || 'Blocked from security logs');
            if (reason === null) return; // User cancelled

            $button.prop('disabled', true);
            const $icon = $button.find('.dashicons');
            if ($icon.length) {
                $icon.removeClass('dashicons-dismiss').addClass('dashicons-update spin');
            }

            $.ajax({
                url: reportedip_hive_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'reportedip_hive_block_ip',
                    ip_address: ipAddress,
                    reason: reason || 'Blocked from security logs',
                    duration: 24,
                    nonce: reportedip_hive_ajax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        ReportedIPAdmin.showNotification('IP address blocked successfully', 'success');
                        $button.closest('tr').fadeOut(300, function() {
                            $(this).remove();
                        });
                    } else {
                        ReportedIPAdmin.showNotification(response.data || 'Failed to block IP', 'error');
                        $button.prop('disabled', false);
                        if ($icon.length) {
                            $icon.removeClass('dashicons-update spin').addClass('dashicons-dismiss');
                        }
                    }
                },
                error: function() {
                    ReportedIPAdmin.showNotification('Request failed', 'error');
                    $button.prop('disabled', false);
                    if ($icon.length) {
                        $icon.removeClass('dashicons-update spin').addClass('dashicons-dismiss');
                    }
                }
            });
        },

        copyIPToClipboard: function(e) {
            e.preventDefault();
            e.stopPropagation();

            const $button = $(this);
            const ipAddress = $button.data('ip');

            if (!ipAddress) return;

            // Use modern clipboard API if available
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(ipAddress).then(function() {
                    ReportedIPAdmin.showCopySuccess($button);
                }).catch(function() {
                    ReportedIPAdmin.fallbackCopy(ipAddress, $button);
                });
            } else {
                ReportedIPAdmin.fallbackCopy(ipAddress, $button);
            }
        },

        fallbackCopy: function(text, $button) {
            const $temp = $('<textarea>');
            $('body').append($temp);
            $temp.val(text).select();
            try {
                document.execCommand('copy');
                ReportedIPAdmin.showCopySuccess($button);
            } catch (err) {
                ReportedIPAdmin.showNotification('Failed to copy IP address', 'error');
            }
            $temp.remove();
        },

        showCopySuccess: function($button) {
            const $icon = $button.find('.dashicons');
            $button.addClass('copied');
            $icon.removeClass('dashicons-clipboard').addClass('dashicons-yes');

            setTimeout(function() {
                $button.removeClass('copied');
                $icon.removeClass('dashicons-yes').addClass('dashicons-clipboard');
            }, 1500);
        },

        lookupIP: function(e) {
            e.preventDefault();

            const ipAddress = $(this).data('ip');

            // Switch to lookup tab with IP as URL parameter
            const $lookupTab = $('a[href*="tab=lookup"]');
            if ($lookupTab.length) {
                window.location.href = $lookupTab.attr('href') + '&lookup_ip=' + encodeURIComponent(ipAddress);
            }
        },

        performLookupTabSearch: function(e) {
            e.preventDefault();

            const ipAddress = $('#lookup-ip-address').val();
            const $results = $('#lookup-results');
            const $content = $('#lookup-results-content');
            const $button = $(this);

            if (!ipAddress) {
                ReportedIPAdmin.showNotification('Please enter an IP address', 'warning');
                return;
            }

            $button.prop('disabled', true).text('Looking up...');
            $results.hide();
            $content.empty();

            $.ajax({
                url: reportedip_hive_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'reportedip_hive_lookup_ip',
                    ip_address: ipAddress,
                    nonce: reportedip_hive_ajax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        ReportedIPAdmin.displayIPInfo(response.data, $content);
                        $results.show();
                    } else {
                        ReportedIPAdmin.showNotification(response.data || 'Failed to lookup IP address', 'error');
                    }
                },
                error: function() {
                    ReportedIPAdmin.showNotification('Network error occurred', 'error');
                },
                complete: function() {
                    $button.prop('disabled', false).text('Lookup');
                }
            });
        },

        displayIPInfo: function(data, $container) {
            const statusBadges = [];
            
            if (data.is_whitelisted) {
                statusBadges.push('<span class="status-badge whitelisted">Whitelisted</span>');
            }
            if (data.is_blocked) {
                statusBadges.push('<span class="status-badge blocked">Blocked</span>');
            }
            if (!data.is_whitelisted && !data.is_blocked) {
                statusBadges.push('<span class="status-badge clean">Clean</span>');
            }
            
            let html = `
                <div class="ip-info-card">
                    <div class="ip-info-header">
                        <h4>IP Information: ${escapeHtml(data.ip_address)}</h4>
                        <div class="ip-status">${statusBadges.join('')}</div>
                    </div>
                    <div class="ip-details">
                        <div class="detail-item">
                            <span class="detail-label">Valid:</span>
                            <span class="detail-value">${data.is_valid ? 'Yes' : 'No'}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Private:</span>
                            <span class="detail-value">${data.is_private ? 'Yes' : 'No'}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Version:</span>
                            <span class="detail-value">IPv${escapeHtml(data.ip_version || 'Unknown')}</span>
                        </div>
            `;

            if (data.country) {
                html += `
                        <div class="detail-item">
                            <span class="detail-label">Country:</span>
                            <span class="detail-value">${escapeHtml(data.country)}</span>
                        </div>
                `;
            }

            if (data.reputation) {
                html += `
                        <div class="detail-item">
                            <span class="detail-label">Abuse Confidence:</span>
                            <span class="detail-value">${escapeHtml(data.reputation.abuseConfidencePercentage)}%</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Total Reports:</span>
                            <span class="detail-value">${escapeHtml(data.reputation.totalReports)}</span>
                        </div>
                `;
            }
            
            html += `
                    </div>
                </div>
            `;
            
            if (data.recent_logs && data.recent_logs.length > 0) {
                html += `
                    <div class="ip-info-card">
                        <h4>Recent Activity</h4>
                        <table class="wp-list-table widefat fixed striped">
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Event</th>
                                    <th>Severity</th>
                                </tr>
                            </thead>
                            <tbody>
                `;
                
                data.recent_logs.forEach(function(log) {
                    var sev = escapeHtml(log.severity);
                    html += `
                        <tr>
                            <td>${escapeHtml(log.created_at)}</td>
                            <td>${escapeHtml(log.event_type)}</td>
                            <td><span class="severity-${sev}">${sev}</span></td>
                        </tr>
                    `;
                });
                
                html += `
                            </tbody>
                        </table>
                    </div>
                `;
            }
            
            $container.html(html);
        },

        cleanupOldLogs: function(e) {
            e.preventDefault();
            
            if (!confirm('Are you sure you want to clean up old logs? This action cannot be undone.')) {
                return;
            }
            
            const $button = $(this);
            $button.prop('disabled', true).text('Cleaning up...');
            
            $.ajax({
                url: reportedip_hive_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'reportedip_hive_cleanup_logs',
                    nonce: reportedip_hive_ajax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        ReportedIPAdmin.showNotification(response.data.message, 'success');
                    } else {
                        ReportedIPAdmin.showNotification(response.data || 'Failed to cleanup logs', 'error');
                    }
                },
                error: function() {
                    ReportedIPAdmin.showNotification('Network error occurred', 'error');
                },
                complete: function() {
                    $button.prop('disabled', false).text('Clean Up Old Logs');
                }
            });
        },

        anonymizeOldData: function(e) {
            e.preventDefault();
            
            if (!confirm('Are you sure you want to anonymize old data? This will remove personal information from logs.')) {
                return;
            }
            
            const $button = $(this);
            $button.prop('disabled', true).text('Anonymizing...');
            
            $.ajax({
                url: reportedip_hive_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'reportedip_hive_anonymize_data',
                    nonce: reportedip_hive_ajax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        ReportedIPAdmin.showNotification(response.data.message, 'success');
                    } else {
                        ReportedIPAdmin.showNotification(response.data || 'Failed to anonymize data', 'error');
                    }
                },
                error: function() {
                    ReportedIPAdmin.showNotification('Network error occurred', 'error');
                },
                complete: function() {
                    $button.prop('disabled', false).text('Anonymize Old Data');
                }
            });
        },

        exportLogs: function(format, e) {
            e.preventDefault();
            
            const days = prompt(reportedip_hive_ajax.strings.prompt_export_days || 'Export logs from how many days? (default: 30)', '30');
            if (days === null) return;
            
            const $button = $(this);
            $button.prop('disabled', true);
            
            $.ajax({
                url: reportedip_hive_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'reportedip_hive_export_logs',
                    format: format,
                    days: parseInt(days) || 30,
                    nonce: reportedip_hive_ajax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        // Create download link
                        const blob = new Blob([response.data], { 
                            type: format === 'csv' ? 'text/csv' : 'application/json' 
                        });
                        const url = window.URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `reportedip-logs-${new Date().toISOString().split('T')[0]}.${format}`;
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        window.URL.revokeObjectURL(url);
                        
                        ReportedIPAdmin.showNotification('Logs exported successfully', 'success');
                    } else {
                        ReportedIPAdmin.showNotification(response.data || 'Failed to export logs', 'error');
                    }
                },
                error: function() {
                    ReportedIPAdmin.showNotification('Network error occurred', 'error');
                },
                complete: function() {
                    $button.prop('disabled', false);
                }
            });
        },

        importCSV: function(form, action) {
            var $form = $(form);
            var $btn = $form.find('button[type="submit"], input[type="submit"]');
            var originalText = $btn.text();

            var formData = new FormData(form);
            formData.append('action', action);
            formData.append('nonce', reportedip_hive_ajax.nonce);

            $btn.prop('disabled', true).text('Importing...');

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: formData,
                processData: false,
                contentType: false,
                success: function(response) {
                    if (response.success) {
                        var data = response.data;
                        var msg = data.message || 'Import completed.';
                        ReportedIPAdmin.showNotification(msg, 'success');
                        // Reload page after short delay to show updated tables
                        setTimeout(function() { location.reload(); }, 1500);
                    } else {
                        ReportedIPAdmin.showNotification(response.data || 'Import failed.', 'error');
                    }
                },
                error: function() {
                    ReportedIPAdmin.showNotification('Request failed.', 'error');
                },
                complete: function() {
                    $btn.prop('disabled', false).text(originalText);
                }
            });
        },

        showLoading: function($element) {
            $element.addClass('loading');
        },

        hideLoading: function($element) {
            $element.removeClass('loading');
        },

        showNotification: function(message, type, duration) {
            type = type || 'info';
            duration = duration || 5000;
            
            const $notification = $(`
                <div class="reportedip-notification ${type}">
                    ${message}
                    <button type="button" class="notice-dismiss" style="float: right; background: none; border: none; cursor: pointer;">&times;</button>
                </div>
            `);
            
            // Insert after the first h1 or at the top of .wrap
            const $target = $('.wrap h1').first();
            if ($target.length) {
                $target.after($notification);
            } else {
                $('.wrap').prepend($notification);
            }
            
            // Auto-hide after duration
            setTimeout(function() {
                $notification.fadeOut(300, function() {
                    $(this).remove();
                });
            }, duration);
            
            // Manual dismiss
            $notification.find('.notice-dismiss').on('click', function() {
                $notification.fadeOut(300, function() {
                    $(this).remove();
                });
            });
        },

        initTooltips: function() {
            // Add tooltips to elements with data-tooltip attribute
            $('[data-tooltip]').each(function() {
                $(this).addClass('tooltip');
            });
        },

    };

    // Persistent notice dismissal
    $(document).on('click', '.reportedip-dismissible .notice-dismiss', function() {
        var $notice = $(this).closest('.reportedip-dismissible');
        var noticeId = $notice.data('notice-id');
        if (noticeId && typeof reportedip_hive_ajax !== 'undefined') {
            $.post(reportedip_hive_ajax.ajax_url, {
                action: 'reportedip_hive_dismiss_notice',
                nonce: reportedip_hive_ajax.nonce,
                notice_id: noticeId
            });
        }
    });

    // Initialize when document is ready
    $(document).ready(function() {
        ReportedIPAdmin.init();

        // Check for lookup IP in URL parameter or sessionStorage (fallback)
        const urlParams = new URLSearchParams(window.location.search);
        const urlIP = urlParams.get('lookup_ip');
        const storedIP = sessionStorage.getItem('reportedip_lookup_ip');
        const ipToLookup = urlIP || storedIP;

        if (ipToLookup) {
            // Try both the old and new input selectors
            const $lookupInput = $('input[name="lookup_ip"], #lookup-ip-address');
            if ($lookupInput.length) {
                $lookupInput.val(ipToLookup);
                if (storedIP) {
                    sessionStorage.removeItem('reportedip_lookup_ip');
                }
                // Auto-trigger the lookup
                setTimeout(function() {
                    $('#lookup-ip-button').click();
                }, 500);
            }
        }
    });

    // Export to global scope for external access
    window.ReportedIPAdmin = ReportedIPAdmin;

})(jQuery);
