// Dashboard JavaScript for dynamic data loading
class Dashboard {
    constructor() {
        this.data = null;
        this.updateInterval = null;
        this.init();
    }

    init() {
        this.loadData();
        this.setupAutoRefresh();
    }

    async loadData() {
        try {
            this.showLoading();
            const response = await fetch('/api/dashboard/data');
            if (!response.ok) throw new Error('Failed to load data');

            this.data = await response.json();
            this.renderData();
            this.hideLoading();
        } catch (error) {
            this.showError('Failed to load statistics: ' + error.message);
        }
    }

    renderData() {
        if (!this.data) return;

        // Overview stats
        document.getElementById('total-connections').textContent = this.formatNumber(this.data.overview.total_connections);
        document.getElementById('active-connections').textContent = this.formatNumber(this.data.overview.active_connections);
        document.getElementById('total-requests').textContent = this.formatNumber(this.data.overview.total_requests);
        document.getElementById('total-errors').textContent = this.formatNumber(this.data.overview.total_errors);
        document.getElementById('blocked-requests').textContent = this.formatNumber(this.data.overview.blocked_requests);
        document.getElementById('allowed-requests').textContent = this.formatNumber(this.data.overview.allowed_requests);
        document.getElementById('bandwidth-in').textContent = this.formatBytes(this.data.overview.total_bytes_in);
        document.getElementById('bandwidth-out').textContent = this.formatBytes(this.data.overview.total_bytes_out);

        // Server stats
        document.getElementById('total-servers').textContent = this.data.server_stats.total_servers;
        document.getElementById('active-servers').textContent = this.data.server_stats.active_servers;

        // Top domains
        this.renderTopDomains();

        // Security events
        this.renderSecurityEvents();

        // Recent errors
        this.renderRecentErrors();

        // Bandwidth chart
        this.renderBandwidthChart();
    }

    renderTopDomains() {
        const container = document.getElementById('top-domains');
        if (!container || !this.data.top_domains) return;

        const html = this.data.top_domains.map(domain => `
            <tr>
                <td>${this.escapeHtml(domain.domain)}</td>
                <td>${this.formatNumber(domain.request_count)}</td>
                <td>${this.formatBytes(domain.total_bytes)}</td>
                <td>${new Date(domain.last_access).toLocaleString()}</td>
            </tr>
        `).join('');

        container.innerHTML = html || '<tr><td colspan="4">No data available</td></tr>';
    }

    renderSecurityEvents() {
        const container = document.getElementById('security-events');
        if (!container || !this.data.security_events) return;

        const html = this.data.security_events.map(event => `
            <tr>
                <td>${this.escapeHtml(event.client_ip)}</td>
                <td>${this.escapeHtml(event.target_host)}</td>
                <td><span class="badge ${event.event_type}">${event.event_type}</span></td>
                <td>${this.escapeHtml(event.reason)}</td>
                <td>${new Date(event.timestamp).toLocaleString()}</td>
            </tr>
        `).join('');

        container.innerHTML = html || '<tr><td colspan="5">No events in last 24 hours</td></tr>';
    }

    renderRecentErrors() {
        const container = document.getElementById('recent-errors');
        if (!container || !this.data.recent_errors) return;

        const html = this.data.recent_errors.map(error => `
            <tr>
                <td>${this.escapeHtml(error.error_type)}</td>
                <td>${this.formatNumber(error.count)}</td>
                <td>${this.escapeHtml(error.last_message)}</td>
                <td>${new Date(error.last_occurred).toLocaleString()}</td>
                <td>
                    <button onclick="dashboard.showErrorDetails('${error.error_type}')"
                            class="btn btn-sm">Details</button>
                </td>
            </tr>
        `).join('');

        container.innerHTML = html || '<tr><td colspan="5">No errors in last 24 hours</td></tr>';
    }

    renderBandwidthChart() {
        const container = document.getElementById('bandwidth-chart');
        if (!container || !this.data.bandwidth_stats) return;

        const dailyData = this.data.bandwidth_stats.daily;
        if (!dailyData || dailyData.length === 0) {
            container.innerHTML = '<div class="no-data">No bandwidth data available</div>';
            return;
        }

        // Simple bar chart using divs
        const maxBytes = Math.max(...dailyData.map(d => Math.max(d.bytes_in, d.bytes_out)));
        const html = dailyData.map(day => {
            const inPercent = (day.bytes_in / maxBytes) * 100;
            const outPercent = (day.bytes_out / maxBytes) * 100;

            return `
                <div class="chart-bar">
                    <div class="bar-label">${day.date}</div>
                    <div class="bar-container">
                        <div class="bar in" style="height: ${inPercent}%"></div>
                        <div class="bar out" style="height: ${outPercent}%"></div>
                    </div>
                    <div class="bar-value">${this.formatBytes(day.bytes_in + day.bytes_out)}</div>
                </div>
            `;
        }).join('');

        container.innerHTML = `
            <div class="chart-container">
                <div class="chart-bars">${html}</div>
                <div class="chart-legend">
                    <span class="legend-item">
                        <span class="legend-color in"></span> Incoming
                    </span>
+                    <span class="legend-item">
                        <span class="legend-color out"></span> Outgoing
                    </span>
                </div>
            </div>
        `;
    }

    setupAutoRefresh() {
        if (this.updateInterval) {
+            clearInterval(this.updateInterval);
+        }
+        this.updateInterval = setInterval(() => this.loadData(), 30000); // Refresh every 30 seconds
+    }

+    showErrorDetails(errorType) {
+        // Navigate to detailed error view
+        window.location.href = `/dashboard/errors?type=${encodeURIComponent(errorType)}`;
+    }

+    showDomains() {
+        window.location.href = '/dashboard/domains';
+    }

+    showSecurityEvents() {
+        window.location.href = '/dashboard/security';
+    }

+    showErrors() {
+        window.location.href = '/dashboard/errors';
+    }

+    formatNumber(num) {
+        if (num >= 1000000) {
+            return (num / 1000000).toFixed(1) + 'M';
+        }
+        if (num >= 1000) {
+            return (num / 1000).toFixed(1) + 'K';
+        }
+        return num.toString();
+    }

+    formatBytes(bytes) {
+        if (bytes === 0) return '0 B';
+        const k = 1024;
+        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
+        const i = Math.floor(Math.log(bytes) / Math.log(k));
+        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
+    }

+    escapeHtml(text) {
+        const div = document.createElement('div');
+        div.textContent = text;
+        return div.innerHTML;
+    }

+    showLoading() {
+        document.getElementById('loading').style.display = 'block';
+        document.getElementById('content').style.display = 'none';
+        document.getElementById('error').style.display = 'none';
+    }

+    hideLoading() {
+        document.getElementById('loading').style.display = 'none';
+        document.getElementById('content').style.display = 'block';
+    }

+    showError(message) {
+        document.getElementById('loading').style.display = 'none';
+        document.getElementById('content').style.display = 'none';
+        document.getElementById('error').style.display = 'block';
+        document.getElementById('error').textContent = message;
+    }
+}

+// Initialize dashboard when page loads
+document.addEventListener('DOMContentLoaded', () => {
+    window.dashboard = new Dashboard();
+});

// Add CSS for dashboard styling
+const style = document.createElement('style');
+style.textContent = `
+    .badge {
+        padding: 2px 6px;
+        border-radius: 3px;
+        font-size: 0.8em;
+        font-weight: bold;
+    }
+    .badge.blocked {
+        background-color: #fee;
+        color: #c33;
+    }
+    .badge.allowed {
+        background-color: #efe;
+        color: #3a3;
+    }
+    .btn {
+        padding: 4px 8px;
+        border: 1px solid #ddd;
+        border-radius: 3px;
+        background: white;
+        cursor: pointer;
+        font-size: 0.9em;
+    }
+    .btn:hover {
+        background: #f0f0f0;
+    }
+    .chart-container {
+        padding: 20px;
+    }
+    .chart-bars {
+        display: flex;
+        align-items: end;
+        gap: 10px;
+        height: 200px;
+    }
+    .chart-bar {
+        flex: 1;
+        display: flex;
+        flex-direction: column;
+        align-items: center;
+    }
+    .bar-container {
+        height: 150px;
+        display: flex;
+        align-items: end;
+        gap: 2px;
+    }
+    .bar {
+        width: 20px;
+        background: #2563eb;
+        transition: height 0.3s;
+    }
+    .bar.in {
+        background: #3b82f6;
+    }
+    .bar.out {
+        background: #ef4444;
+    }
+    .bar-label {
+        font-size: 0.8em;
+        margin-top: 5px;
+    }
+    .bar-value {
+        font-size: 0.7em;
+        margin-top: 5px;
+    }
+    .chart-legend {
+        display: flex;
+        justify-content: center;
+        gap: 20px;
+        margin-top: 10px;
+    }
+    .legend-item {
+        display: flex;
+        align-items: center;
+        gap: 5px;
+        font-size: 0.9em;
+    }
+    .legend-color {
+        width: 12px;
+        height: 12px;
+        border-radius: 2px;
+    }
+    .no-data {
+        color: #666;
+        font-style: italic;
+    }
+`;
+document.head.appendChild(style);
