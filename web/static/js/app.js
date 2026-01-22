/**
 * Domain Routing Manager - Main Application
 */

// DOM Elements
const elements = {
    engineStatus: document.getElementById('engine-status'),
    rulesCount: document.getElementById('rules-count'),
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
    toast: document.getElementById('toast'),
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
    wgPeerSection: document.getElementById('wg-peer-section')
};

// State
let state = {
    rules: [],
    wgConfigs: [],
    deleteRuleId: null
};

// Initialize
document.addEventListener('DOMContentLoaded', init);

async function init() {
    setupEventListeners();
    await loadStatus();
    await loadRules();
    await loadWgConfigurations();
}

function setupEventListeners() {
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
    
    // Close modals on backdrop click
    elements.ruleModal.addEventListener('click', (e) => {
        if (e.target === elements.ruleModal) closeRuleModal();
    });
    elements.deleteModal.addEventListener('click', (e) => {
        if (e.target === elements.deleteModal) closeDeleteModal();
    });
}

// Data Loading
async function loadStatus() {
    try {
        const response = await api.getStatus();
        const data = response.data;
        
        elements.engineStatus.textContent = data.engine_status;
        elements.engineStatus.className = `status-badge ${data.engine_status}`;
        elements.rulesCount.textContent = `${data.active_rules}/${data.enabled_rules} active`;
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
    } catch (error) {
        console.error('Failed to load WG configurations:', error);
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
