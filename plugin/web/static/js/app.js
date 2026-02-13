/**
 * Domain Routing Manager - Main Application
 */

// DOM Elements
const elements = {
    // Status
    engineStatus: document.getElementById('engine-status'),
    rulesCount: document.getElementById('rules-count'),
    
    // Tabs
    tabBtns: document.querySelectorAll('.tab-btn'),
    tabContents: document.querySelectorAll('.tab-content'),
    
    // Domain Rules
    rulesList: document.getElementById('rules-list'),
    btnAddRule: document.getElementById('btn-add-rule'),
    btnRefresh: document.getElementById('btn-refresh'),
    btnApplyAll: document.getElementById('btn-apply-all'),
    btnCleanup: document.getElementById('btn-cleanup'),
    ruleModal: document.getElementById('rule-modal'),
    modalTitle: document.getElementById('modal-title'),
    ruleForm: document.getElementById('rule-form'),
    btnCloseModal: document.getElementById('btn-close-modal'),
    btnCancel: document.getElementById('btn-cancel'),
    deleteModal: document.getElementById('delete-modal'),
    deleteRuleName: document.getElementById('delete-rule-name'),
    btnCancelDelete: document.getElementById('btn-cancel-delete'),
    btnConfirmDelete: document.getElementById('btn-confirm-delete'),
    // Form fields
    ruleId: document.getElementById('rule-id'),
    ruleName: document.getElementById('rule-name'),
    ruleDomain: document.getElementById('rule-domain'),
    ruleTargetType: document.getElementById('rule-target-type'),
    ruleTargetConfig: document.getElementById('rule-target-config'),
    ruleTargetPeer: document.getElementById('rule-target-peer'),
    rulePriority: document.getElementById('rule-priority'),
    ruleEnabled: document.getElementById('rule-enabled'),
    wgTargetSection: document.getElementById('wg-target-section'),
    wgPeerSection: document.getElementById('wg-peer-section'),
    
    // Static Routes
    staticRoutesList: document.getElementById('static-routes-list'),
    btnAddStaticRoute: document.getElementById('btn-add-static-route'),
    btnRefreshStatic: document.getElementById('btn-refresh-static'),
    btnApplyAllStatic: document.getElementById('btn-apply-all-static'),
    staticRouteModal: document.getElementById('static-route-modal'),
    staticModalTitle: document.getElementById('static-modal-title'),
    staticRouteForm: document.getElementById('static-route-form'),
    btnCloseStaticModal: document.getElementById('btn-close-static-modal'),
    btnCancelStatic: document.getElementById('btn-cancel-static'),
    deleteStaticModal: document.getElementById('delete-static-modal'),
    deleteStaticRouteName: document.getElementById('delete-static-route-name'),
    btnCancelDeleteStatic: document.getElementById('btn-cancel-delete-static'),
    btnConfirmDeleteStatic: document.getElementById('btn-confirm-delete-static'),
    // Static form fields
    staticRouteId: document.getElementById('static-route-id'),
    staticRouteName: document.getElementById('static-route-name'),
    staticRouteDestination: document.getElementById('static-route-destination'),
    staticRouteTargetType: document.getElementById('static-route-target-type'),
    staticRouteTargetConfig: document.getElementById('static-route-target-config'),
    staticRouteTargetPeer: document.getElementById('static-route-target-peer'),
    staticRouteInterface: document.getElementById('static-route-interface'),
    staticRouteGateway: document.getElementById('static-route-gateway'),
    staticRoutePriority: document.getElementById('static-route-priority'),
    staticRouteEnabled: document.getElementById('static-route-enabled'),
    staticWgTargetSection: document.getElementById('static-wg-target-section'),
    staticWgPeerSection: document.getElementById('static-wg-peer-section'),
    staticInterfaceSection: document.getElementById('static-interface-section'),
    staticGatewaySection: document.getElementById('static-gateway-section'),
    
    // Toast
    toast: document.getElementById('toast')
};

// State
let state = {
    rules: [],
    staticRoutes: [],
    wgConfigs: [],
    deleteRuleId: null,
    deleteStaticRouteId: null
};

// Initialize
document.addEventListener('DOMContentLoaded', init);

async function init() {
    setupEventListeners();
    setupTabListeners();
    await loadStatus();
    await loadRules();
    await loadStaticRoutes();
    await loadWgConfigurations();
}

function setupTabListeners() {
    elements.tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.dataset.tab;
            
            // Update active tab button
            elements.tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            // Update active tab content
            elements.tabContents.forEach(content => {
                content.classList.remove('active');
            });
            document.getElementById(`${tabId}-tab`).classList.add('active');
        });
    });
}

function setupEventListeners() {
    // Domain Rules
    elements.btnAddRule.addEventListener('click', () => openRuleModal());
    elements.btnRefresh.addEventListener('click', () => {
        loadStatus();
        loadRules();
    });
    elements.btnApplyAll.addEventListener('click', applyAllRules);
    elements.btnCleanup.addEventListener('click', cleanupAllRules);
    
    elements.btnCloseModal.addEventListener('click', closeRuleModal);
    elements.btnCancel.addEventListener('click', closeRuleModal);
    elements.ruleForm.addEventListener('submit', handleRuleSubmit);
    
    elements.ruleTargetType.addEventListener('change', handleTargetTypeChange);
    elements.ruleTargetConfig.addEventListener('change', handleConfigChange);
    
    elements.btnCancelDelete.addEventListener('click', closeDeleteModal);
    elements.btnConfirmDelete.addEventListener('click', confirmDelete);
    
    // Static Routes
    elements.btnAddStaticRoute.addEventListener('click', () => openStaticRouteModal());
    elements.btnRefreshStatic.addEventListener('click', () => {
        loadStatus();
        loadStaticRoutes();
    });
    elements.btnApplyAllStatic.addEventListener('click', applyAllStaticRoutes);
    
    elements.btnCloseStaticModal.addEventListener('click', closeStaticRouteModal);
    elements.btnCancelStatic.addEventListener('click', closeStaticRouteModal);
    elements.staticRouteForm.addEventListener('submit', handleStaticRouteSubmit);
    
    elements.staticRouteTargetType.addEventListener('change', handleStaticTargetTypeChange);
    elements.staticRouteTargetConfig.addEventListener('change', handleStaticConfigChange);
    
    elements.btnCancelDeleteStatic.addEventListener('click', closeDeleteStaticModal);
    elements.btnConfirmDeleteStatic.addEventListener('click', confirmDeleteStatic);
    
    // Close modals on backdrop click
    elements.ruleModal.addEventListener('click', (e) => {
        if (e.target === elements.ruleModal) closeRuleModal();
    });
    elements.deleteModal.addEventListener('click', (e) => {
        if (e.target === elements.deleteModal) closeDeleteModal();
    });
    elements.staticRouteModal.addEventListener('click', (e) => {
        if (e.target === elements.staticRouteModal) closeStaticRouteModal();
    });
    elements.deleteStaticModal.addEventListener('click', (e) => {
        if (e.target === elements.deleteStaticModal) closeDeleteStaticModal();
    });
}

// Data Loading
async function loadStatus() {
    try {
        const response = await api.getStatus();
        const data = response.data;
        
        elements.engineStatus.textContent = data.engine_status;
        elements.engineStatus.className = `status-badge ${data.engine_status}`;
        const domainRulesText = `${data.active_rules}/${data.enabled_rules} domain rules active`;
        const staticRoutesText = `${data.active_static_routes || 0}/${data.enabled_static_routes || 0} static routes active`;
        elements.rulesCount.textContent = `${domainRulesText} | ${staticRoutesText}`;
    } catch (error) {
        elements.engineStatus.textContent = 'Error';
        elements.engineStatus.className = 'status-badge stopped';
        showToast('Failed to load status', 'error');
    }
}

async function loadRules() {
    elements.rulesList.innerHTML = '<div class="loading">Loading rules...</div>';
    
    try {
        const response = await api.getRules();
        state.rules = response.data;
        renderRules();
    } catch (error) {
        elements.rulesList.innerHTML = '<div class="loading">Failed to load rules</div>';
        showToast('Failed to load rules: ' + error.message, 'error');
    }
}

async function loadWgConfigurations() {
    try {
        const response = await api.getWgConfigurations();
        state.wgConfigs = response.data;
        populateConfigDropdown();
        populateStaticConfigDropdown();
    } catch (error) {
        console.error('Failed to load WG configurations:', error);
    }
}

async function loadStaticRoutes() {
    elements.staticRoutesList.innerHTML = '<div class="loading">Loading static routes...</div>';
    
    try {
        const response = await api.getStaticRoutes();
        state.staticRoutes = response.data;
        renderStaticRoutes();
    } catch (error) {
        elements.staticRoutesList.innerHTML = '<div class="loading">Failed to load static routes</div>';
        showToast('Failed to load static routes: ' + error.message, 'error');
    }
}

// Rendering
function renderRules() {
    if (state.rules.length === 0) {
        elements.rulesList.innerHTML = `
            <div class="empty-state">
                <p>No routing rules configured yet.</p>
                <button class="btn btn-primary" onclick="openRuleModal()">Add Your First Rule</button>
            </div>
        `;
        return;
    }
    
    elements.rulesList.innerHTML = state.rules.map(rule => renderRuleCard(rule)).join('');
}

function renderStaticRoutes() {
    if (state.staticRoutes.length === 0) {
        elements.staticRoutesList.innerHTML = `
            <div class="empty-state">
                <p>No static routes configured yet.</p>
                <button class="btn btn-primary" onclick="openStaticRouteModal()">Add Your First Static Route</button>
            </div>
        `;
        return;
    }
    
    elements.staticRoutesList.innerHTML = state.staticRoutes.map(route => renderStaticRouteCard(route)).join('');
}

function renderRuleCard(rule) {
    const statusClass = rule.applied_state?.status || 'not_applied';
    const disabledClass = rule.enabled ? '' : 'disabled';
    
    let targetDisplay = 'Default Gateway';
    if (rule.target_type === 'wireguard_peer') {
        targetDisplay = `WireGuard: ${rule.target_config || 'N/A'}`;
        if (rule.target_peer) {
            targetDisplay += ` (peer: ${rule.target_peer.substring(0, 8)}...)`;
        }
    }
    
    return `
        <div class="rule-card ${disabledClass}" data-rule-id="${rule.id}">
            <div class="rule-card-header">
                <span class="rule-name">${escapeHtml(rule.name)}</span>
                <div class="rule-status">
                    <span class="rule-status-badge ${statusClass}">${statusClass.replace('_', ' ')}</span>
                </div>
            </div>
            <div class="rule-details">
                <div class="rule-detail">
                    <span class="rule-detail-label">Domain</span>
                    <span class="rule-detail-value">${escapeHtml(rule.domain)}</span>
                </div>
                <div class="rule-detail">
                    <span class="rule-detail-label">Target</span>
                    <span class="rule-detail-value">${escapeHtml(targetDisplay)}</span>
                </div>
                <div class="rule-detail">
                    <span class="rule-detail-label">Priority</span>
                    <span class="rule-detail-value">${rule.priority}</span>
                </div>
                <div class="rule-detail">
                    <span class="rule-detail-label">Mark/Table</span>
                    <span class="rule-detail-value">${rule.fwmark}/${rule.routing_table}</span>
                </div>
            </div>
            <div class="rule-actions">
                <button class="btn btn-small" onclick="editRule(${rule.id})">Edit</button>
                <button class="btn btn-small" onclick="toggleRule(${rule.id})">${rule.enabled ? 'Disable' : 'Enable'}</button>
                <button class="btn btn-small" onclick="applyRule(${rule.id})">Apply</button>
                <button class="btn btn-small btn-danger" onclick="deleteRule(${rule.id})">Delete</button>
            </div>
        </div>
    `;
}

function renderStaticRouteCard(route) {
    const statusClass = route.applied_state?.status || 'not_applied';
    const disabledClass = route.enabled ? '' : 'disabled';
    
    let targetDisplay = 'Default Gateway';
    if (route.target_type === 'wireguard_peer') {
        targetDisplay = `WireGuard: ${route.target_config || 'N/A'}`;
        if (route.target_peer) {
            targetDisplay += ` (peer: ${route.target_peer.substring(0, 8)}...)`;
        }
    } else if (route.target_type === 'interface') {
        targetDisplay = `Interface: ${route.interface || route.target_config || 'N/A'}`;
    }
    
    let gatewayDisplay = route.gateway || 'Auto-detect';
    if (route.interface && !route.gateway) {
        gatewayDisplay = `dev ${route.interface}`;
    }
    
    return `
        <div class="rule-card ${disabledClass}" data-route-id="${route.id}">
            <div class="rule-card-header">
                <span class="rule-name">${escapeHtml(route.name)}</span>
                <div class="rule-status">
                    <span class="rule-status-badge ${statusClass}">${statusClass.replace('_', ' ')}</span>
                </div>
            </div>
            <div class="rule-details">
                <div class="rule-detail">
                    <span class="rule-detail-label">Destination</span>
                    <span class="rule-detail-value">${escapeHtml(route.destination)}</span>
                </div>
                <div class="rule-detail">
                    <span class="rule-detail-label">Target</span>
                    <span class="rule-detail-value">${escapeHtml(targetDisplay)}</span>
                </div>
                <div class="rule-detail">
                    <span class="rule-detail-label">Gateway</span>
                    <span class="rule-detail-value">${escapeHtml(gatewayDisplay)}</span>
                </div>
                <div class="rule-detail">
                    <span class="rule-detail-label">Priority</span>
                    <span class="rule-detail-value">${route.priority}</span>
                </div>
            </div>
            <div class="rule-actions">
                <button class="btn btn-small" onclick="editStaticRoute(${route.id})">Edit</button>
                <button class="btn btn-small" onclick="toggleStaticRoute(${route.id})">${route.enabled ? 'Disable' : 'Enable'}</button>
                <button class="btn btn-small" onclick="applyStaticRoute(${route.id})">Apply</button>
                <button class="btn btn-small btn-danger" onclick="deleteStaticRoute(${route.id})">Delete</button>
            </div>
        </div>
    `;
}

function populateConfigDropdown() {
    elements.ruleTargetConfig.innerHTML = '<option value="">Select configuration...</option>';
    state.wgConfigs.forEach(config => {
        const option = document.createElement('option');
        option.value = config.name;
        option.textContent = `${config.name} (${config.peer_count} peers)`;
        elements.ruleTargetConfig.appendChild(option);
    });
}

async function populatePeerDropdown(configName) {
    elements.ruleTargetPeer.innerHTML = '<option value="">Any peer (use interface routing)</option>';
    
    if (!configName) return;
    
    try {
        const response = await api.getWgPeers(configName);
        response.data.forEach(peer => {
            const option = document.createElement('option');
            option.value = peer.public_key;
            option.textContent = peer.name || peer.public_key.substring(0, 12) + '...';
            elements.ruleTargetPeer.appendChild(option);
        });
    } catch (error) {
        console.error('Failed to load peers:', error);
    }
}

function populateStaticConfigDropdown() {
    elements.staticRouteTargetConfig.innerHTML = '<option value="">Select configuration...</option>';
    state.wgConfigs.forEach(config => {
        const option = document.createElement('option');
        option.value = config.name;
        option.textContent = `${config.name} (${config.peer_count} peers)`;
        elements.staticRouteTargetConfig.appendChild(option);
    });
}

async function populateStaticPeerDropdown(configName) {
    elements.staticRouteTargetPeer.innerHTML = '<option value="">Any peer</option>';
    
    if (!configName) return;
    
    try {
        const response = await api.getWgPeers(configName);
        response.data.forEach(peer => {
            const option = document.createElement('option');
            option.value = peer.public_key;
            option.textContent = peer.name || peer.public_key.substring(0, 12) + '...';
            elements.staticRouteTargetPeer.appendChild(option);
        });
    } catch (error) {
        console.error('Failed to load peers:', error);
    }
}

// Modal Handling
function openRuleModal(rule = null) {
    elements.ruleForm.reset();
    elements.ruleId.value = '';
    
    if (rule) {
        elements.modalTitle.textContent = 'Edit Rule';
        elements.ruleId.value = rule.id;
        elements.ruleName.value = rule.name;
        elements.ruleDomain.value = rule.domain;
        elements.ruleTargetType.value = rule.target_type;
        elements.rulePriority.value = rule.priority;
        elements.ruleEnabled.checked = rule.enabled;
        
        if (rule.target_type === 'wireguard_peer') {
            elements.ruleTargetConfig.value = rule.target_config || '';
            handleTargetTypeChange();
            // Load peers and set value after
            if (rule.target_config) {
                populatePeerDropdown(rule.target_config).then(() => {
                    elements.ruleTargetPeer.value = rule.target_peer || '';
                });
            }
        }
    } else {
        elements.modalTitle.textContent = 'Add Rule';
    }
    
    handleTargetTypeChange();
    elements.ruleModal.classList.remove('hidden');
}

function closeRuleModal() {
    elements.ruleModal.classList.add('hidden');
}

function handleTargetTypeChange() {
    const isWg = elements.ruleTargetType.value === 'wireguard_peer';
    elements.wgTargetSection.classList.toggle('hidden', !isWg);
    elements.wgPeerSection.classList.toggle('hidden', !isWg);
}

function handleConfigChange() {
    populatePeerDropdown(elements.ruleTargetConfig.value);
}

// Static Route Modal Handling
function openStaticRouteModal(route = null) {
    elements.staticRouteForm.reset();
    elements.staticRouteId.value = '';
    
    if (route) {
        elements.staticModalTitle.textContent = 'Edit Static Route';
        elements.staticRouteId.value = route.id;
        elements.staticRouteName.value = route.name;
        elements.staticRouteDestination.value = route.destination;
        elements.staticRouteTargetType.value = route.target_type;
        elements.staticRoutePriority.value = route.priority;
        elements.staticRouteEnabled.checked = route.enabled;
        
        handleStaticTargetTypeChange();
        
        if (route.target_type === 'wireguard_peer') {
            elements.staticRouteTargetConfig.value = route.target_config || '';
            if (route.target_config) {
                populateStaticPeerDropdown(route.target_config).then(() => {
                    elements.staticRouteTargetPeer.value = route.target_peer || '';
                });
            }
        } else if (route.target_type === 'interface') {
            elements.staticRouteInterface.value = route.interface || '';
            elements.staticRouteGateway.value = route.gateway || '';
        } else if (route.target_type === 'default_gateway') {
            elements.staticRouteGateway.value = route.gateway || '';
        }
    } else {
        elements.staticModalTitle.textContent = 'Add Static Route';
    }
    
    handleStaticTargetTypeChange();
    elements.staticRouteModal.classList.remove('hidden');
}

function closeStaticRouteModal() {
    elements.staticRouteModal.classList.add('hidden');
}

function handleStaticTargetTypeChange() {
    const targetType = elements.staticRouteTargetType.value;
    elements.staticWgTargetSection.classList.toggle('hidden', targetType !== 'wireguard_peer');
    elements.staticWgPeerSection.classList.toggle('hidden', targetType !== 'wireguard_peer');
    elements.staticInterfaceSection.classList.toggle('hidden', targetType !== 'interface');
    elements.staticGatewaySection.classList.toggle('hidden', targetType !== 'default_gateway' && targetType !== 'interface');
}

function handleStaticConfigChange() {
    populateStaticPeerDropdown(elements.staticRouteTargetConfig.value);
}

async function handleStaticRouteSubmit(e) {
    e.preventDefault();
    
    const route = {
        name: elements.staticRouteName.value.trim(),
        destination: elements.staticRouteDestination.value.trim(),
        target_type: elements.staticRouteTargetType.value,
        target_config: elements.staticRouteTargetConfig.value || null,
        target_peer: elements.staticRouteTargetPeer.value || null,
        interface: elements.staticRouteInterface.value || null,
        gateway: elements.staticRouteGateway.value || null,
        priority: parseInt(elements.staticRoutePriority.value) || 100,
        enabled: elements.staticRouteEnabled.checked
    };
    
    try {
        const routeId = elements.staticRouteId.value;
        if (routeId) {
            await api.updateStaticRoute(routeId, route);
            showToast('Static route updated successfully', 'success');
        } else {
            await api.createStaticRoute(route);
            showToast('Static route created successfully', 'success');
        }
        closeStaticRouteModal();
        await loadStaticRoutes();
        await loadStatus();
    } catch (error) {
        showToast('Failed to save static route: ' + error.message, 'error');
    }
}

async function handleRuleSubmit(e) {
    e.preventDefault();
    
    const rule = {
        name: elements.ruleName.value.trim(),
        domain: elements.ruleDomain.value.trim(),
        target_type: elements.ruleTargetType.value,
        target_config: elements.ruleTargetConfig.value || null,
        target_peer: elements.ruleTargetPeer.value || null,
        priority: parseInt(elements.rulePriority.value) || 100,
        enabled: elements.ruleEnabled.checked
    };
    
    try {
        const ruleId = elements.ruleId.value;
        if (ruleId) {
            await api.updateRule(ruleId, rule);
            showToast('Rule updated successfully', 'success');
        } else {
            await api.createRule(rule);
            showToast('Rule created successfully', 'success');
        }
        closeRuleModal();
        await loadRules();
        await loadStatus();
    } catch (error) {
        showToast('Failed to save rule: ' + error.message, 'error');
    }
}

// Rule Actions
function editRule(ruleId) {
    const rule = state.rules.find(r => r.id === ruleId);
    if (rule) {
        openRuleModal(rule);
    }
}

async function toggleRule(ruleId) {
    try {
        await api.toggleRule(ruleId);
        await loadRules();
        await loadStatus();
        showToast('Rule toggled', 'success');
    } catch (error) {
        showToast('Failed to toggle rule: ' + error.message, 'error');
    }
}

async function applyRule(ruleId) {
    try {
        const response = await api.applyRule(ruleId);
        showToast(response.message, response.status ? 'success' : 'warning');
        await loadRules();
        await loadStatus();
    } catch (error) {
        showToast('Failed to apply rule: ' + error.message, 'error');
    }
}

function deleteRule(ruleId) {
    const rule = state.rules.find(r => r.id === ruleId);
    if (rule) {
        state.deleteRuleId = ruleId;
        elements.deleteRuleName.textContent = rule.name;
        elements.deleteModal.classList.remove('hidden');
    }
}

function closeDeleteModal() {
    elements.deleteModal.classList.add('hidden');
    state.deleteRuleId = null;
}

async function confirmDelete() {
    if (!state.deleteRuleId) return;
    
    try {
        await api.deleteRule(state.deleteRuleId);
        showToast('Rule deleted', 'success');
        closeDeleteModal();
        await loadRules();
        await loadStatus();
    } catch (error) {
        showToast('Failed to delete rule: ' + error.message, 'error');
    }
}

async function applyAllRules() {
    try {
        const response = await api.applyAllRules();
        showToast(response.message, 'success');
        await loadRules();
        await loadStatus();
    } catch (error) {
        showToast('Failed to apply rules: ' + error.message, 'error');
    }
}

// Static Route Actions
function editStaticRoute(routeId) {
    const route = state.staticRoutes.find(r => r.id === routeId);
    if (route) {
        openStaticRouteModal(route);
    }
}

async function toggleStaticRoute(routeId) {
    try {
        await api.toggleStaticRoute(routeId);
        await loadStaticRoutes();
        await loadStatus();
        showToast('Static route toggled', 'success');
    } catch (error) {
        showToast('Failed to toggle static route: ' + error.message, 'error');
    }
}

async function applyStaticRoute(routeId) {
    try {
        const response = await api.applyStaticRoute(routeId);
        showToast(response.message, response.status ? 'success' : 'warning');
        await loadStaticRoutes();
        await loadStatus();
    } catch (error) {
        showToast('Failed to apply static route: ' + error.message, 'error');
    }
}

function deleteStaticRoute(routeId) {
    const route = state.staticRoutes.find(r => r.id === routeId);
    if (route) {
        state.deleteStaticRouteId = routeId;
        elements.deleteStaticRouteName.textContent = route.name;
        elements.deleteStaticModal.classList.remove('hidden');
    }
}

function closeDeleteStaticModal() {
    elements.deleteStaticModal.classList.add('hidden');
    state.deleteStaticRouteId = null;
}

async function confirmDeleteStatic() {
    if (!state.deleteStaticRouteId) return;
    
    try {
        await api.deleteStaticRoute(state.deleteStaticRouteId);
        showToast('Static route deleted', 'success');
        closeDeleteStaticModal();
        await loadStaticRoutes();
        await loadStatus();
    } catch (error) {
        showToast('Failed to delete static route: ' + error.message, 'error');
    }
}

async function applyAllStaticRoutes() {
    try {
        const response = await api.applyAllStaticRoutes();
        showToast(response.message, 'success');
        await loadStaticRoutes();
        await loadStatus();
    } catch (error) {
        showToast('Failed to apply static routes: ' + error.message, 'error');
    }
}

async function cleanupAllRules() {
    if (!confirm('This will remove all applied routing rules from the system. Continue?')) {
        return;
    }
    
    try {
        await api.cleanupRules();
        showToast('All rules cleaned up', 'success');
        await loadRules();
        await loadStatus();
    } catch (error) {
        showToast('Failed to cleanup rules: ' + error.message, 'error');
    }
}

// Utilities
function showToast(message, type = 'info') {
    elements.toast.textContent = message;
    elements.toast.className = `toast ${type}`;
    elements.toast.classList.remove('hidden');
    
    setTimeout(() => {
        elements.toast.classList.add('hidden');
    }, 3000);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
