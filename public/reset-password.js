// reset-password.js — client logic for the password-reset landing page.
//
// Supabase embeds the recovery session in the URL hash fragment:
//   /reset-password#access_token=...&type=recovery&...
//
// Hash fragments are NEVER sent to the server, so the raw token is never
// logged in access logs.  This script:
//   1. Reads and immediately removes the hash from the browser URL.
//   2. Shows the appropriate UI state (loading → form | error).
//   3. On submit, POSTs { token, password } to /reset-password.
//   4. Transitions to success or surfaces a server error inline.

(function initResetPassword() {

    // ── Helpers ─────────────────────────────────────────────────────────────
    const STATE_IDS = ['stateLoading', 'stateError', 'stateForm', 'stateSuccess'];

    function show(id) {
        STATE_IDS.forEach((s) => {
            const el = document.getElementById(s);
            if (!el) return;
            // Toggle rp-hidden: remove it for the target state, add it for all others.
            el.classList.toggle('rp-hidden', s !== id);
        });
    }

    // ── Step 1: Extract recovery token ──────────────────────────────────────
    //
    // Supabase sends the token in one of two ways depending on project settings:
    //
    // Old flow:  /reset-password#access_token=...&type=recovery  (hash fragment)
    // New flow:  /reset-password?token_hash=...&type=recovery    (query param)
    //
    // We check both so this page works regardless of which flow Supabase uses.

    const hashParams  = new URLSearchParams(window.location.hash.slice(1));
    const queryParams = new URLSearchParams(window.location.search);

    const accessToken = hashParams.get('access_token');   // old flow
    const tokenHash   = queryParams.get('token_hash');    // new PKCE flow
    const type        = queryParams.get('type') || hashParams.get('type');

    // Remove tokens from the address bar immediately.
    history.replaceState(null, '', window.location.pathname);


    // ── Step 3: Show form (legacy) or exchange token_hash first (PKCE) ───────
    let token = accessToken;

    if (tokenHash) {
        // PKCE flow: exchange token_hash server-side for a usable access_token.
        try {
            const resp = await fetch('/verify-reset-token', {
                method  : 'POST',
                headers : { 'Content-Type': 'application/x-www-form-urlencoded' },
                body    : new URLSearchParams({ token_hash: tokenHash, type: 'recovery' })
            });
            if (!resp.ok) { show('stateError'); return; }
            const data = await resp.json();
            token = data.access_token;
            if (!token) { show('stateError'); return; }
        } catch (_) {
            show('stateError');
            return;
        }
    }

    show('stateForm');

    // ── Password-strength live feedback ─────────────────────────────────────
    const pwInput    = document.getElementById('rpPassword');
    const ruleUpper  = document.getElementById('rp-rule-upper');
    const ruleLower  = document.getElementById('rp-rule-lower');
    const ruleLength = document.getElementById('rp-rule-length');
    const ruleSpec   = document.getElementById('rp-rule-special');

    function applyRule(el, passes) {
        if (!el) return;
        const icon = el.querySelector('.rule-icon');
        el.classList.toggle('rule-ok', passes);
        if (icon) icon.textContent = passes ? '●' : '○';
    }

    if (pwInput) {
        pwInput.addEventListener('input', () => {
            const v = pwInput.value;
            applyRule(ruleUpper,  /[A-Z]/.test(v));
            applyRule(ruleLower,  /[a-z]/.test(v));
            applyRule(ruleLength, v.length >= 8);
            applyRule(ruleSpec,   /[!@#$%^&*()\-_=+[\]{};':",.<>/?\\|`~]/.test(v));
        });
    }

    // ── Show / hide password toggle ─────────────────────────────────────────
    const toggleBtn = document.getElementById('rpToggleBtn');
    if (toggleBtn && pwInput) {
        toggleBtn.addEventListener('click', () => {
            const isText = pwInput.type === 'text';
            pwInput.type = isText ? 'password' : 'text';
            toggleBtn.setAttribute('aria-label', isText ? 'Show password' : 'Hide password');
        });
    }

    // ── Step 4: Form submission ──────────────────────────────────────────────
    const form      = document.getElementById('resetForm');
    const confirmEl = document.getElementById('rpConfirm');
    const errMsg    = document.getElementById('rpErrMsg');
    const submitBtn = document.getElementById('rpSubmitBtn');

    function showError(msg) {
        if (!errMsg) return;
        errMsg.textContent = msg;
        errMsg.classList.remove('rp-hidden');
    }

    function clearError() {
        if (!errMsg) return;
        errMsg.classList.add('rp-hidden');
        errMsg.textContent = '';
    }

    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        clearError();

        const password = pwInput ? pwInput.value : '';
        const confirm  = confirmEl ? confirmEl.value : '';

        // ── Client-side validation ───────────────────────────────────────────
        if (password.length < 8) {
            return showError('Password must be at least 8 characters.');
        }
        if (!/[A-Z]/.test(password)) {
            return showError('Password must contain at least one uppercase letter.');
        }
        if (!/[a-z]/.test(password)) {
            return showError('Password must contain at least one lowercase letter.');
        }
        if (!/[!@#$%^&*()\-_=+[\]{};':",.<>/?\\|`~]/.test(password)) {
            return showError('Password must contain at least one special character.');
        }
        if (password !== confirm) {
            return showError('Passwords do not match.');
        }

        // ── Submit ───────────────────────────────────────────────────────────
        submitBtn.disabled    = true;
        submitBtn.textContent = 'Updating…';

        try {
            const resp = await fetch('/reset-password', {
                method  : 'POST',
                headers : { 'Content-Type': 'application/x-www-form-urlencoded' },
                body    : new URLSearchParams({ token, password })
            });

            if (resp.ok) {
                show('stateSuccess');
                return;
            }

            // Surface the server's error message (policy violation, expired token, etc.)
            const data = await resp.json().catch(() => ({}));
            showError(data.error || 'Something went wrong. Please try again.');
            submitBtn.disabled    = false;
            submitBtn.textContent = 'Update password';

        } catch (networkErr) {
            console.error('[reset-password] Network error:', networkErr);
            showError('Network error — please check your connection and try again.');
            submitBtn.disabled    = false;
            submitBtn.textContent = 'Update password';
        }
    });

}());