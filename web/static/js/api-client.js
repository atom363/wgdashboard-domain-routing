/**
 * API Client for Domain Routing Plugin
 */

class ApiClient {
    constructor(baseUrl = '') {
        this.baseUrl = baseUrl;
        this.token = this.getTokenFromUrl() || localStorage.getItem('auth_token') || '';
    }

    getTokenFromUrl() {
        const params = new URLSearchParams(window.location.search);
        const token = params.get('token');
        if (token) {
            localStorage.setItem('auth_token', token);
        }
        return token;
    }

    setToken(token) {
        this.token = token;
        localStorage.setItem('auth_token', token);
    }

    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };

        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }

        try {
            const response = await fetch(url, {
                ...options,
                headers
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || `HTTP error ${response.status}`);
            }

            return data;
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    }

    // Status & Health
    async getStatus() {
        return this.request('/api/status');
    }

    // WireGuard Configurations
    async getWgConfigurations() {
        return this.request('/api/wg/configurations');
    }

    async getWgPeers(configName) {
        return this.request(`/api/wg/peers/${encodeURIComponent(configName)}`);
    }

    // Routing Rules
    async getRules() {
        return this.request('/api/rules');
    }

    async getRule(ruleId) {
        return this.request(`/api/rules/${ruleId}`);
    }

    async createRule(rule) {
        return this.request('/api/rules', {
            method: 'POST',
            body: JSON.stringify(rule)
        });
    }

    async updateRule(ruleId, rule) {
        return this.request(`/api/rules/${ruleId}`, {
            method: 'PUT',
            body: JSON.stringify(rule)
        });
    }

    async deleteRule(ruleId) {
        return this.request(`/api/rules/${ruleId}`, {
            method: 'DELETE'
        });
    }

    async toggleRule(ruleId) {
        return this.request(`/api/rules/${ruleId}/toggle`, {
            method: 'POST'
        });
    }

    async applyRule(ruleId) {
        return this.request(`/api/rules/${ruleId}/apply`, {
            method: 'POST'
        });
    }

    async applyAllRules() {
        return this.request('/api/rules/apply-all', {
            method: 'POST'
        });
    }

    async cleanupRules() {
        return this.request('/api/rules/cleanup', {
            method: 'POST'
        });
    }

    // Static Routes
    async getStaticRoutes() {
        return this.request('/api/static-routes');
    }

    async getStaticRoute(routeId) {
        return this.request(`/api/static-routes/${routeId}`);
    }

    async createStaticRoute(route) {
        return this.request('/api/static-routes', {
            method: 'POST',
            body: JSON.stringify(route)
        });
    }

    async updateStaticRoute(routeId, route) {
        return this.request(`/api/static-routes/${routeId}`, {
            method: 'PUT',
            body: JSON.stringify(route)
        });
    }

    async deleteStaticRoute(routeId) {
        return this.request(`/api/static-routes/${routeId}`, {
            method: 'DELETE'
        });
    }

    async toggleStaticRoute(routeId) {
        return this.request(`/api/static-routes/${routeId}/toggle`, {
            method: 'POST'
        });
    }

    async applyStaticRoute(routeId) {
        return this.request(`/api/static-routes/${routeId}/apply`, {
            method: 'POST'
        });
    }

    async applyAllStaticRoutes() {
        return this.request('/api/static-routes/apply-all', {
            method: 'POST'
        });
    }
}

// Export singleton instance
const api = new ApiClient();
