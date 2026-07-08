document.addEventListener('DOMContentLoaded', () => {
    // --- State Engine Configuration ---
    let state = {
        activeFilter: 'all',
        token: sessionStorage.getItem('vault_token'),
        email: sessionStorage.getItem('vault_email'),
        entries: []
    };

    // --- DOM Elements Registry ---
    const authView = document.getElementById('auth-view');
    const appDashboardView = document.getElementById('app-dashboard-view');
    const authForm = document.getElementById('auth-form');
    const authToggleBtn = document.getElementById('auth-toggle-btn');
    const entryModal = document.getElementById('entry-modal');
    const entryForm = document.getElementById('entry-form');
    const searchBar = document.getElementById('search-bar');
    const categoryMenu = document.getElementById('category-menu');
    const genPassBtn = document.getElementById('gen-pass-btn');
    
    // --- Initial Routing Evaluation ---
    if (state.token) {
        showDashboard();
    } else {
        showAuth();
    }

    function showAuth() {
        authView.classList.remove('hidden');
        appDashboardView.classList.add('hidden');
    }

    function showDashboard() {
        authView.classList.add('hidden');
        appDashboardView.classList.remove('hidden');
        document.getElementById('user-display').textContent = state.email || "Operator";
        fetchPasswords();
    }

    // Auth Switcher View Toggling
    let isLoginMode = true;
    authToggleBtn.addEventListener('click', () => {
        isLoginMode = !isLoginMode;
        document.getElementById('auth-submit-btn').textContent = isLoginMode ? 'Unlock Vault' : 'Create System Vault';
        document.getElementById('auth-subtitle').textContent = isLoginMode ? 'Sign in to your encrypted vault' : 'Initialize a master-encrypted vault';
        document.getElementById('auth-toggle-text').textContent = isLoginMode ? 'New operator?' : 'Already initialized?';
        authToggleBtn.textContent = isLoginMode ? 'Initialize Vault' : 'Sign In';
    });

    // --- Authentication Network API Layer ---
    authForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('auth-email').value;
        const password = document.getElementById('auth-password').value;
        const endpoint = isLoginMode ? '/api/auth/login' : '/api/auth/register';

        try {
            const res = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, master_password: password })
            });
            const data = await res.json();

            if (!res.ok) throw new Error(data.error || 'Identity verification rejected');

            if (isLoginMode) {
                sessionStorage.setItem('vault_token', data.token);
                sessionStorage.setItem('vault_email', data.email);
                state.token = data.token;
                state.email = data.email;
                authForm.reset();
                showToast('Matrix Vault decrypted successfully', 'success');
                showDashboard();
            } else {
                showToast('Secure Vault allocation ready. Please authenticate.', 'success');
                isLoginMode = true;
                authToggleBtn.click();
            }
        } catch (err) {
            showToast(err.message, 'error');
        }
    });

    // --- Vault Records CRUD Orchestration ---
    async function fetchPasswords() {
        if (!state.token) return;
        try {
            const res = await fetch('/api/passwords', {
                headers: { 'Authorization': `Bearer ${state.token}` }
            });
            if (res.status === 401) return handleLogout();
            
            state.entries = await res.json();
            applyFiltersAndRender();
        } catch (err) {
            showToast('Synchronized data pipeline disrupted', 'error');
        }
    }

    entryForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const payload = {
            name: document.getElementById('entry-name').value,
            website: document.getElementById('entry-url').value,
            username: document.getElementById('entry-user').value,
            password: document.getElementById('entry-pass').value,
            category: document.getElementById('entry-cat').value
        };

        try {
            const res = await fetch('/api/passwords', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${state.token}`
                },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Failed to complete data serialization');

            showToast('Credential locked and written into secure segment', 'success');
            entryModal.classList.add('hidden');
            entryForm.reset();
            fetchPasswords(); 
        } catch (err) {
            showToast(err.message, 'error');
        }
    });

    // --- Smart Rendering & Filtering Logic ---
    function applyFiltersAndRender() {
        const searchTerm = searchBar.value.toLowerCase();
        const filtered = state.entries.filter(entry => {
            const matchesSearch = 
                (entry.name?.toLowerCase().includes(searchTerm)) || 
                (entry.website?.toLowerCase().includes(searchTerm)) ||
                (entry.username?.toLowerCase().includes(searchTerm));
            
            const matchesCategory = state.activeFilter === 'all' || entry.category === state.activeFilter;
            return matchesSearch && matchesCategory;
        });
        renderCards(filtered);
    }

    function renderCards(entries) {
        const grid = document.getElementById('vault-entries');
        if(!grid) return;
        grid.innerHTML = '';
        
        if (entries.length === 0) {
            grid.innerHTML = `<div style="grid-column: 1/-1; text-align: center; color: var(--text-muted); padding: 4rem 1rem; border: 1px dashed rgba(255,255,255,0.03); border-radius:12px;">No credentials found matching selected segment parameters.</div>`;
            return;
        }

        const fragment = document.createDocumentFragment();
        entries.forEach(entry => {
            const card = document.createElement('div');
            card.className = 'vault-card glass';
            
            const name = entry.name || 'Undefined Service';
            const website = entry.website || 'No target link configured';
            const username = entry.username || '---';
            const password = entry.password || '';
            const category = entry.category || 'Other';
            const id = entry.id || '';

            card.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                    <div>
                        <h3 style="font-size:1.1rem; font-weight:600; margin-bottom:2px;">${name}</h3>
                        <span style="color:var(--text-muted); font-size:0.8rem;">${website}</span>
                    </div>
                    <div style="display:flex; gap:10px; align-items:center;">
                        <span class="text-xs" style="background:rgba(99,102,241,0.12); color:var(--neon-blue); padding:3px 8px; border-radius:4px; font-weight:500;">${category}</span>
                        <button class="btn-danger-minimal delete-btn" data-id="${id}" title="Purge Record">🗑️</button>
                    </div>
                </div>
                
                <div class="secure-field-group">
                    <div class="secure-field">
                        <span class="text-sm" style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:80%; font-weight:500;">${username}</span>
                        <span class="action-icon copy-btn" data-val="${username}" title="Copy Identity">📋</span>
                    </div>
                    <div class="secure-field">
                        <input type="password" value="${password}" class="pw-input-mask" readonly>
                        <div style="display:flex; gap:10px; align-items:center;">
                            <span class="action-icon toggle-visibility" title="Reveal">👁️</span>
                            <span class="action-icon copy-btn" data-val="${password}" title="Copy Ciphertext">📋</span>
                        </div>
                    </div>
                </div>
            `;
            fragment.appendChild(card);
        });
        grid.appendChild(fragment);
    }

    // Listeners for inputs
    searchBar.addEventListener('input', applyFiltersAndRender);

    categoryMenu.addEventListener('click', (e) => {
        const item = e.target.closest('.cat-item');
        if (!item) return;
        
        document.querySelectorAll('.cat-item').forEach(el => el.classList.remove('active'));
        item.classList.add('active');
        state.activeFilter = item.getAttribute('data-cat');
        applyFiltersAndRender();
    });

    // --- On-Demand Password Generator Tool ---
    genPassBtn.addEventListener('click', () => {
        const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
        let generatedValue = "";
        for (let i = 0, n = charset.length; i < 20; ++i) {
            generatedValue += charset.charAt(Math.floor(Math.random() * n));
        }
        document.getElementById('entry-pass').value = generatedValue;
        showToast('High-entropy password injected', 'success');
    });

    // --- Component Event Delegation Engine ---
    document.getElementById('app-dashboard-view').addEventListener('click', async (e) => {
        if (e.target.classList.contains('copy-btn')) {
            const val = e.target.getAttribute('data-val');
            if(val && val !== '---') {
                await navigator.clipboard.writeText(val);
                showToast('Data captured to clipboard buffer', 'success');
            }
        }
        
        if (e.target.classList.contains('toggle-visibility')) {
            const input = e.target.closest('.secure-field').querySelector('.pw-input-mask');
            if(input) {
                input.type = input.type === 'password' ? 'text' : 'password';
                e.target.textContent = input.type === 'password' ? '👁️' : '🔒';
            }
        }

        if (e.target.classList.contains('delete-btn')) {
            const entryId = e.target.getAttribute('data-id');
            if (!entryId) return;
            
            if (confirm('Confirm permanent deletion from data layer? Action is non-reversible.')) {
                try {
                    const res = await fetch(`/api/passwords/${entryId}`, {
                        method: 'DELETE',
                        headers: { 'Authorization': `Bearer ${state.token}` }
                    });
                    if (!res.ok) throw new Error('Data drop operation rejected by server');

                    showToast('Record successfully destroyed', 'success');
                    state.entries = state.entries.filter(entry => entry.id != entryId);
                    applyFiltersAndRender();
                } catch (err) {
                    showToast(err.message, 'error');
                }
            }
        }
    });

    // --- Modal Layer Window Events ---
    document.getElementById('open-modal-btn').addEventListener('click', () => entryModal.classList.remove('hidden'));
    document.getElementById('close-modal-btn').addEventListener('click', () => entryModal.classList.add('hidden'));
    document.getElementById('logout-btn').addEventListener('click', handleLogout);

    function handleLogout() {
        sessionStorage.clear();
        state.token = null;
        state.email = null;
        state.entries = [];
        showAuth();
        showToast('Secure Vault locked', 'success');
    }

    function showToast(msg, type = 'success') {
        const container = document.getElementById('toast-container');
        if(!container) return;
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = msg;
        container.appendChild(toast);
        setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 300);
        }, 2800);
    }
});