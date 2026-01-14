// Alpine.js components and utilities

// Toast notification manager
window.toastManager = function() {
    return {
        toasts: [],
        nextId: 1,

        show(config) {
            const toast = {
                id: this.nextId++,
                message: config.message || 'Notification',
                type: config.type || 'info',
                visible: true
            };

            this.toasts.push(toast);

            // Auto-dismiss after 3 seconds
            setTimeout(() => {
                this.dismiss(toast.id);
            }, config.duration || 3000);
        },

        dismiss(id) {
            const toast = this.toasts.find(t => t.id === id);
            if (toast) {
                toast.visible = false;
                setTimeout(() => {
                    this.toasts = this.toasts.filter(t => t.id !== id);
                }, 300);
            }
        }
    };
};

// Global toast function
window.showToast = function(message, type = 'info', duration = 3000) {
    window.dispatchEvent(new CustomEvent('show-toast', {
        detail: { message, type, duration }
    }));
};

// htmx event handlers
document.addEventListener('DOMContentLoaded', () => {
    // Show toast on successful API calls
    document.body.addEventListener('htmx:afterRequest', (event) => {
        const xhr = event.detail.xhr;

        if (xhr.status >= 200 && xhr.status < 300) {
            try {
                const response = JSON.parse(xhr.responseText);
                if (response.message) {
                    showToast(response.message, 'success');
                }
            } catch (e) {
                // Response is not JSON, ignore
            }
        }
    });

    // Show error toast on failed API calls
    document.body.addEventListener('htmx:responseError', (event) => {
        const xhr = event.detail.xhr;
        let message = 'Request failed';

        try {
            const response = JSON.parse(xhr.responseText);
            message = response.error || response.message || message;
        } catch (e) {
            message = xhr.statusText || message;
        }

        showToast(message, 'error', 5000);
    });

    // Show error toast on network errors
    document.body.addEventListener('htmx:sendError', () => {
        showToast('Network error - please check your connection', 'error', 5000);
    });

    // Auto-populate edit modal when opened
    document.addEventListener('click', (event) => {
        const editButton = event.target.closest('[data-host]');
        if (editButton && editButton.hasAttribute('data-host')) {
            const host = editButton.dataset.host;
            const interval = editButton.dataset.interval;
            const timeout = editButton.dataset.timeout;
            const isPublic = editButton.dataset.public === 'true';

            // Populate modal fields
            const hostInput = document.getElementById('edit-host');
            const intervalInput = document.getElementById('edit-interval');
            const timeoutInput = document.getElementById('edit-timeout');
            const publicInput = document.getElementById('edit-public');

            if (hostInput) hostInput.value = host;
            if (intervalInput) intervalInput.value = interval;
            if (timeoutInput) timeoutInput.value = timeout;
            if (publicInput) publicInput.checked = isPublic;
        }
    });

    // Persist theme preference
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        document.documentElement.setAttribute('data-theme', savedTheme);
    }

    // Save theme on change
    document.addEventListener('click', (event) => {
        if (event.target.closest('[onclick*="data-theme"]')) {
            setTimeout(() => {
                const theme = document.documentElement.getAttribute('data-theme');
                localStorage.setItem('theme', theme);
            }, 100);
        }
    });
});

// Keyboard shortcuts
document.addEventListener('keydown', (event) => {
    // Ctrl/Cmd + K: Focus search
    if ((event.ctrlKey || event.metaKey) && event.key === 'k') {
        event.preventDefault();
        const searchInput = document.querySelector('input[placeholder*="Search"]');
        if (searchInput) {
            searchInput.focus();
        }
    }

    // Escape: Close modals
    if (event.key === 'Escape') {
        document.querySelectorAll('dialog[open]').forEach(dialog => {
            dialog.close();
        });
    }
});

// Auto-update stats when hosts change
document.body.addEventListener('htmx:afterSwap', () => {
    updateStats();
});

function updateStats() {
    const rows = document.querySelectorAll('#host-table tbody tr[data-host]');
    const stats = {
        total: rows.length,
        online: 0,
        offline: 0
    };

    rows.forEach(row => {
        const statusBadge = row.querySelector('.status-badge');
        if (statusBadge) {
            const status = statusBadge.textContent.trim();
            if (status === 'SSH') {
                stats.online++;
            } else if (status === 'TIMEOUT') {
                stats.offline++;
            }
        }
    });

    // Update stats display
    const totalEl = document.querySelector('.stat-value.text-primary');
    const onlineEl = document.querySelector('.stat-value.text-success');
    const offlineEl = document.querySelector('.stat-value.text-error');

    if (totalEl) totalEl.textContent = stats.total;
    if (onlineEl) onlineEl.textContent = stats.online;
    if (offlineEl) offlineEl.textContent = stats.offline;
}

// Initialize stats on page load
document.addEventListener('DOMContentLoaded', updateStats);

// Host filtering and search functionality
document.addEventListener('DOMContentLoaded', () => {
    const setupHostFiltering = () => {
        const filterRadios = document.querySelectorAll('input[name="filter"]');
        const searchInput = document.getElementById('host-search');
        const hostRows = () => document.querySelectorAll('#host-table tbody tr[data-host]');

        const applyFilters = () => {
            const filter = document.querySelector('input[name="filter"]:checked')?.value || 'all';
            const searchTerm = searchInput?.value.toLowerCase() || '';

            hostRows().forEach(row => {
                const host = row.getAttribute('data-host').toLowerCase();
                const statusBadge = row.querySelector('.status-badge');
                const status = statusBadge?.textContent.trim();

                // Check filter match
                let filterMatch = true;
                if (filter === 'online' && status !== 'SSH') {
                    filterMatch = false;
                } else if (filter === 'offline' && status === 'SSH') {
                    filterMatch = false;
                }

                // Check search match
                const searchMatch = !searchTerm || host.includes(searchTerm);

                // Show/hide row
                row.style.display = (filterMatch && searchMatch) ? '' : 'none';
            });

            // Update stats based on visible rows
            updateStats();
        };

        // Add event listeners
        filterRadios.forEach(radio => {
            radio.addEventListener('change', applyFilters);
        });

        if (searchInput) {
            searchInput.addEventListener('input', debounce(applyFilters, 300));
        }

        // Re-apply filters after htmx swaps
        document.body.addEventListener('htmx:afterSwap', () => {
            setTimeout(applyFilters, 100);
        });
    };

    // Simple debounce function
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    setupHostFiltering();
});
