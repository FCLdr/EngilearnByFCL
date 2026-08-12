// auth.js — Système de compte Engilearn
(function() {
    const TOKEN_KEY = 'engilearn_token';
    const USER_KEY = 'engilearn_user';

    const isHome = location.pathname === '/' || location.pathname === '/Engilearn.html' || location.pathname.endsWith('/Engilearn.html');

    const USER_ICON = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`;
    const LOGOUT_ICON = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>`;

    async function checkAuth() {
        const token = localStorage.getItem(TOKEN_KEY);

        if (!token) {
            // Pas de token — laisse le bouton "Se connecter" visible (déjà dans le HTML)
            if (!isHome) {
                window.location.href = '/auth.html';
            }
            return false;
        }

        try {
            const res = await fetch('/api/auth/me', {
                headers: { 'Authorization': 'Bearer ' + token }
            });
            if (!res.ok) throw new Error('Invalid token');
            const data = await res.json();
            injectUserMenu(data.username);
            return true;
        } catch {
            localStorage.removeItem(TOKEN_KEY);
            localStorage.removeItem(USER_KEY);
            if (!isHome) {
                window.location.href = '/auth.html';
            }
            return false;
        }
    }

    function injectUserMenu(username) {
        const placeholder = document.getElementById('navAccount');
        if (placeholder) {
            placeholder.innerHTML = `
                <span style="color:var(--muted);font-size:.9rem;display:flex;align-items:center;gap:6px;">
                    ${USER_ICON} ${escapeHtml(username)}
                </span>
                <button onclick="logout()" title="Déconnexion" style="padding:8px 14px;border-radius:10px;border:1px solid var(--border);background:var(--glass);color:var(--text);cursor:pointer;font-size:.85rem;transition:.2s;display:flex;align-items:center;gap:6px;">
                    ${LOGOUT_ICON} Déconnexion
                </button>
            `;
            return;
        }

        // Fallback : injecter dans .nav si pas de placeholder
        const nav = document.querySelector('.nav');
        if (!nav || nav.querySelector('.account-area')) return;

        const div = document.createElement('div');
        div.className = 'account-area';
        div.style.cssText = 'display:flex;align-items:center;gap:12px;';
        div.innerHTML = `
            <span style="color:var(--muted);font-size:.9rem;display:flex;align-items:center;gap:6px;">
                ${USER_ICON} ${escapeHtml(username)}
            </span>
            <button onclick="logout()" title="Déconnexion" style="padding:8px 14px;border-radius:10px;border:1px solid var(--border);background:var(--glass);color:var(--text);cursor:pointer;font-size:.85rem;transition:.2s;display:flex;align-items:center;gap:6px;">
                ${LOGOUT_ICON} Déconnexion
            </button>
        `;
        nav.appendChild(div);
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    window.logout = function() {
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(USER_KEY);
        window.location.href = '/auth.html';
    };

    window.api = async function(url, options = {}) {
        const token = localStorage.getItem(TOKEN_KEY);
        options.headers = options.headers || {};
        options.headers['Authorization'] = 'Bearer ' + token;
        const res = await fetch(url, options);
        if (res.status === 401) {
            localStorage.removeItem(TOKEN_KEY);
            localStorage.removeItem(USER_KEY);
            window.location.href = '/auth.html';
            throw new Error('Unauthorized');
        }
        return res;
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', checkAuth);
    } else {
        checkAuth();
    }
})();
