// ─────────────────────────────────────────────────────────────────────────────
// script.js — Frontend logic: auth forms, hCaptcha widgets, eye tracking
//
// hCAPTCHA INTEGRATION OVERVIEW
// ──────────────────────────────
// Supabase requires a captchaToken on every signUp / signInWithPassword call
// when hCaptcha is enabled in the project's Auth settings.
//
// Flow:
//   1. DOMContentLoaded → fetchConfig() hits GET /config on our Express server.
//   2. Server returns { hcaptchaSiteKey } from .env (the PUBLIC site key).
//   3. hCaptcha script fires window.onHcaptchaLoad when the CDN script is ready.
//   4. tryRenderWidgets() runs once BOTH promises resolve — whichever finishes
//      last — and renders one widget per form using hcaptcha.render().
//   5. Signup form: token lives in hcaptcha.getResponse(signupWidgetId).
//      Login form:  token lives in hcaptcha.getResponse(signinWidgetId).
//   6. Both tokens are sent in the POST body to our Express server, which
//      forwards them to supabase.auth as `options.captchaToken`.
//   7. Supabase verifies the token against hCaptcha's API using the SECRET KEY
//      stored only in the Supabase dashboard — we never touch it.
//   8. Tokens are SINGLE-USE. hcaptcha.reset(widgetId) is called after every
//      submit attempt (success or failure) to generate a fresh token next time.
// ─────────────────────────────────────────────────────────────────────────────

// ── DOM refs ───────────────────────────────────────────────────────────────────
const body      = document.getElementById('mainBody');
const panel     = document.getElementById('rightPanel');
const leftPanel = document.querySelector('.left');
const irisL     = document.getElementById('irisL');
const irisR     = document.getElementById('irisR');
const browL     = document.getElementById('browL');
const browR     = document.getElementById('browR');
const cursor    = document.getElementById('cursor');
const eyeLbl    = document.getElementById('eyeLabel');
const warnTxt   = document.getElementById('warnText');
const errMsg    = document.getElementById('errMsg');

// ── State ──────────────────────────────────────────────────────────────────────
let attempts    = 0;
let isAngry     = false;
let currentFlow = 'signin';

// hCaptcha widget IDs returned by hcaptcha.render() — used to read / reset tokens.
let signupWidgetId = null;
let signinWidgetId = null;
let forgotWidgetId = null;

// Guards for the dual-async init path (config fetch + hCaptcha script load).
let hcaptchaSiteKey  = null;   // set after /config responds
let hcaptchaReady    = false;  // set when window.onHcaptchaLoad fires

const allPanels = ['panelSignup', 'panelSignin', 'panelForgot'];

// ── hCaptcha init ──────────────────────────────────────────────────────────────

// Called by the hCaptcha CDN script via ?onload=onHcaptchaLoad.
// May fire before or after fetchConfig() resolves — tryRenderWidgets handles both.
window.onHcaptchaLoad = function () {
    hcaptchaReady = true;
    tryRenderWidgets();
};

// Fetch the public site key from our own server (never hardcoded here).
async function fetchConfig() {
    try {
        const resp   = await fetch('/config');
        const config = await resp.json();
        if (config.hcaptchaSiteKey) {
            hcaptchaSiteKey = config.hcaptchaSiteKey;
            tryRenderWidgets();
        } else {
            console.warn('[hCaptcha] No site key returned from /config — widgets will not render.');
        }
    } catch (err) {
        console.error('[hCaptcha] Failed to load config:', err);
    }
}

// Render both widgets once both async conditions are satisfied.
// Safe to call multiple times — checks both guards before acting.
function tryRenderWidgets() {
    if (!hcaptchaReady || !hcaptchaSiteKey) return;

    // Render signup widget (light theme — white form background)
    const signupEl = document.getElementById('captcha-signup');
    if (signupEl && signupWidgetId === null) {
        signupWidgetId = hcaptcha.render(signupEl, {
            sitekey  : hcaptchaSiteKey,
            theme    : 'light',
            size     : 'normal'
        });
    }

    // Render signin widget
    const signinEl = document.getElementById('captcha-signin');
    if (signinEl && signinWidgetId === null) {
        signinWidgetId = hcaptcha.render(signinEl, {
            sitekey  : hcaptchaSiteKey,
            theme    : 'light',
            size     : 'normal'
        });
    }

}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Read a captcha token by widget ID. Returns '' if widget not ready yet.
function getCaptchaToken(widgetId) {
    if (widgetId === null || typeof hcaptcha === 'undefined') return '';
    return hcaptcha.getResponse(widgetId) || '';
}

// Reset a widget (mandatory after every submit — tokens are single-use).
function resetCaptcha(widgetId) {
    if (widgetId === null || typeof hcaptcha === 'undefined') return;
    hcaptcha.reset(widgetId);
}

// Show a captcha-specific validation error and shake the widget container.
function shakeCaptchaError(errorElId, containerId) {
    const errorEl    = document.getElementById(errorElId);
    const containerEl = document.getElementById(containerId);
    if (errorEl)    errorEl.style.display = 'block';
    if (containerEl) {
        containerEl.classList.add('shake');
        setTimeout(() => containerEl.classList.remove('shake'), 450);
    }
}

function clearCaptchaError(errorElId) {
    const errorEl = document.getElementById(errorElId);
    if (errorEl) errorEl.style.display = 'none';
}

// ── Panel switching ────────────────────────────────────────────────────────────

function showPanel(id) {
    allPanels.forEach(p => {
        const el = document.getElementById(p);
        el.style.display = 'none';
        el.classList.remove('active');
    });
    const target = document.getElementById(id);
    target.style.display = 'block';
    target.classList.add('active');
}

function switchTab(t) {
    currentFlow = t;
    document.getElementById('tabSignup').classList.toggle('active', t === 'signup');
    document.getElementById('tabSignin').classList.toggle('active', t === 'signin');
    showPanel(t === 'signup' ? 'panelSignup' : 'panelSignin');
    if (t === 'signup' && isAngry) resetAngry();
}

// ── Password complexity rules ──────────────────────────────────────────────────

function checkPwComplexity(val) {
    const setRule = (id, pass) => {
        const el = document.getElementById(id);
        el.classList.toggle('pass', pass);
        el.classList.toggle('fail', !pass);
        el.querySelector('.rule-icon').textContent = pass ? '✓' : '○';
    };
    setRule('rule-upper',   /[A-Z]/.test(val));
    setRule('rule-lower',   /[a-z]/.test(val));
    setRule('rule-length',  val.length >= 8);
    setRule('rule-special', /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(val));
}

// ── Signup form (fetch-based) ──────────────────────────────────────────────────
//
// Converted from native form POST so that:
//   a) The captchaToken can be read from the widget and included in the body.
//   b) Server errors display in the UI instead of raw JSON in the browser.
//   c) The success redirect (/success) is driven by the fetch response.

function initSignupForm() {
    const form = document.getElementById('signupForm');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const nameInput  = document.getElementById('suName');
        const emailInput = document.getElementById('suEmail');
        const pwInput    = document.getElementById('suPassword');
        const signupBtn  = document.getElementById('signupBtn');
        const suErrMsg   = document.getElementById('suErrMsg');
        let   isValid    = true;

        // ── Field validation ──────────────────────────────────────────────────
        if (!nameInput.value.trim()) {
            nameInput.classList.add('shake');
            setTimeout(() => nameInput.classList.remove('shake'), 450);
            isValid = false;
        }
        if (!emailInput.value.trim()) {
            emailInput.classList.add('shake');
            setTimeout(() => emailInput.classList.remove('shake'), 450);
            isValid = false;
        }
        const pw = pwInput.value;
        if (pw.length < 8 || !/[A-Z]/.test(pw) || !/[a-z]/.test(pw) || !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(pw)) {
            pwInput.classList.add('shake');
            setTimeout(() => pwInput.classList.remove('shake'), 450);
            isValid = false;
        }

        if (confirmInput && pw !== confirmInput.value) {
            confirmInput.classList.add('shake');
            setTimeout(() => confirmInput.classList.remove('shake'), 450);
            isValid = false;
        }

        // ── hCaptcha validation ───────────────────────────────────────────────
        const captchaToken = getCaptchaToken(signupWidgetId);
        if (!captchaToken) {
            shakeCaptchaError('captcha-signup-error', 'captcha-signup');
            isValid = false;
        } else {
            clearCaptchaError('captcha-signup-error');
        }

        if (!isValid) return;

        signupBtn.disabled    = true;
        signupBtn.textContent = 'Creating account…';
        if (suErrMsg) suErrMsg.style.display = 'none';

        try {
            const resp = await fetch('/signup', {
                method  : 'POST',
                headers : { 'Content-Type': 'application/x-www-form-urlencoded' },
                body    : new URLSearchParams({
                    name         : nameInput.value.trim(),
                    email        : emailInput.value.trim(),
                    password     : pwInput.value,
                    captchaToken                       // ← token passed to server
                })
            });

            // Token is single-use — always reset after any submit.
            resetCaptcha(signupWidgetId);

            if (resp.ok) {
                const { redirect } = await resp.json();
                window.location.href = redirect || '/success';
                return;
            }

            // Server returned an error — show it in the UI.
            const { error } = await resp.json();
            if (suErrMsg) {
                suErrMsg.textContent  = error || 'Registration failed. Please try again.';
                suErrMsg.style.display = 'block';
            }
            signupBtn.disabled    = false;
            signupBtn.textContent = 'Signup';

        } catch (networkErr) {
            console.error('Signup request failed:', networkErr);
            resetCaptcha(signupWidgetId);
            if (suErrMsg) {
                suErrMsg.textContent  = 'Network error — please try again.';
                suErrMsg.style.display = 'block';
            }
            signupBtn.disabled    = false;
            signupBtn.textContent = 'Signup';
        }
    });
}

// ── Login form (fetch-based) ───────────────────────────────────────────────────

function initLoginForm() {
    const form = document.getElementById('signinForm');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (isAngry) return;

        const emailInput = document.getElementById('siEmail');
        const pwInput    = document.getElementById('siPassword');
        const loginBtn   = document.getElementById('loginBtn');
        let   isValid    = true;

        // ── Field validation ──────────────────────────────────────────────────
        if (!emailInput.value.trim()) {
            emailInput.classList.add('shake');
            setTimeout(() => emailInput.classList.remove('shake'), 450);
            isValid = false;
        }
        if (!pwInput.value) {
            pwInput.classList.add('shake');
            setTimeout(() => pwInput.classList.remove('shake'), 450);
            isValid = false;
        }

        // ── hCaptcha validation ───────────────────────────────────────────────
        const captchaToken = getCaptchaToken(signinWidgetId);
        if (!captchaToken) {
            shakeCaptchaError('captcha-signin-error', 'captcha-signin');
            isValid = false;
        } else {
            clearCaptchaError('captcha-signin-error');
        }

        if (!isValid) return;

        loginBtn.disabled    = true;
        loginBtn.textContent = 'Signing in…';

        try {
            const resp = await fetch('/login', {
                method  : 'POST',
                headers : { 'Content-Type': 'application/x-www-form-urlencoded' },
                body    : new URLSearchParams({
                    email        : emailInput.value,
                    password     : pwInput.value,
                    captchaToken                       // ← token passed to server
                })
            });

            // Token is single-use — always reset, even on success.
            resetCaptcha(signinWidgetId);

            if (resp.ok) {
                const { redirect } = await resp.json();
                window.location.href = redirect || '/private';
                return;
            }

            // ── Real server-side failure → trigger attempt UI ─────────────────
            attempts++;
            sessionStorage.setItem('loginAttempts', String(attempts)); // survive reload
            const dot = document.getElementById('dot' + attempts);
            if (dot) dot.classList.add('used');

            if (errMsg) {
                errMsg.textContent   = 'Wrong password';
                errMsg.style.display = 'inline';
            }
            pwInput.classList.add('shake');
            setTimeout(() => pwInput.classList.remove('shake'), 450);

            if (attempts >= 3) {
                triggerAngry();
            } else {
                loginBtn.disabled    = false;
                loginBtn.textContent = 'Sign In';
            }

        } catch (networkErr) {
            console.error('Login request failed:', networkErr);
            resetCaptcha(signinWidgetId);
            loginBtn.disabled    = false;
            loginBtn.textContent = 'Sign In';
            if (errMsg) {
                errMsg.textContent   = 'Network error — please try again.';
                errMsg.style.display = 'inline';
            }
        }
    });
}

// ── Forgot-password panel ──────────────────────────────────────────────────────

function showForgotPanel() {
    showPanel('panelForgot');

    // Render the forgot captcha widget lazily — only once the panel is visible.
    // Rendering while the panel is hidden (display:none) produces a zero-size
    // widget that never appears. We defer until the user actually opens this panel.
    if (hcaptchaReady && hcaptchaSiteKey) {
        const forgotEl = document.getElementById('captcha-forgot');
        if (forgotEl && forgotWidgetId === null) {
            forgotWidgetId = hcaptcha.render(forgotEl, {
                sitekey  : hcaptchaSiteKey,
                theme    : 'light',
                size     : 'normal'
            });
        }
    }
    // Hide tabs while in forgot-password flow; back link handles navigation.
    const tabs = document.getElementById('mainTabs');
    if (tabs) tabs.classList.add('tabs--hidden');
    // Reset the panel to its form state in case it was previously in sent state.
    const formState = document.getElementById('forgotFormState');
    const sentState = document.getElementById('forgotSentState');
    if (formState) formState.style.display = '';
    if (sentState) sentState.style.display = 'none';
    const fpErr = document.getElementById('fpErrMsg');
    if (fpErr) fpErr.style.display = 'none';
    const fpEmail = document.getElementById('fpEmail');
    if (fpEmail) fpEmail.value = '';
    const fpBtn = document.getElementById('fpSubmitBtn');
    if (fpBtn) { fpBtn.disabled = false; fpBtn.textContent = 'Send reset link'; }
}

function backToSignin() {
    const tabs = document.getElementById('mainTabs');
    if (tabs) tabs.classList.remove('tabs--hidden');
    resetCaptcha(forgotWidgetId);
    switchTab('signin');
}

function initForgotPasswordForm() {
    const form = document.getElementById('forgotForm');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const emailInput = document.getElementById('fpEmail');
        const submitBtn  = document.getElementById('fpSubmitBtn');
        const fpErr      = document.getElementById('fpErrMsg');

        if (!emailInput.value.trim()) {
            emailInput.classList.add('shake');
            setTimeout(() => emailInput.classList.remove('shake'), 450);
            return;
        }

        submitBtn.disabled    = true;
        submitBtn.textContent = 'Sending…';
        if (fpErr) fpErr.style.display = 'none';

        // Validate captcha token before submitting.
        const captchaToken = getCaptchaToken(forgotWidgetId);
        if (!captchaToken) {
            shakeCaptchaError('captcha-forgot-error', 'captcha-forgot');
            submitBtn.disabled    = false;
            submitBtn.textContent = 'Send reset link';
            return;
        }
        clearCaptchaError('captcha-forgot-error');

        try {
            const resp = await fetch('/forgot-password', {
                method  : 'POST',
                headers : { 'Content-Type': 'application/x-www-form-urlencoded' },
                body    : new URLSearchParams({ email: emailInput.value.trim(), captchaToken })
            });

            // Always show the sent state regardless of whether the email is
            // registered — this prevents user-enumeration attacks.
            resetCaptcha(forgotWidgetId);

            if (resp.ok || resp.status === 404) {
                const formState = document.getElementById('forgotFormState');
                const sentState = document.getElementById('forgotSentState');
                if (formState) formState.style.display = 'none';
                if (sentState) sentState.style.display = '';
                return;
            }

            // Only surface a real error (e.g. rate-limit, server fault).
            const data = await resp.json().catch(() => ({}));
            if (fpErr) {
                fpErr.textContent  = data.error || 'Something went wrong. Please try again.';
                fpErr.style.display = 'block';
            }
            submitBtn.disabled    = false;
            submitBtn.textContent = 'Send reset link';

        } catch (networkErr) {
            console.error('[forgot-password] Network error:', networkErr);
            resetCaptcha(forgotWidgetId);
            if (fpErr) {
                fpErr.textContent  = 'Network error — please try again.';
                fpErr.style.display = 'block';
            }
            submitBtn.disabled    = false;
            submitBtn.textContent = 'Send reset link';
        }
    });
}



function triggerAngry() {
    isAngry = true;
    sessionStorage.setItem('loginAttempts', String(attempts)); // persist across reloads
    body.classList.add('angry');
    leftPanel.classList.add('angry-mode');
    browL.setAttribute('d', 'M 20,5 Q 90,12 160,20');
    browR.setAttribute('d', 'M 20,20 Q 90,12 160,5');
    eyeLbl.textContent = 'I  S E E  Y O U';
    warnTxt.classList.add('show');
    const btn = document.getElementById('loginBtn');
    btn.textContent      = '🔒 Account Locked';
    btn.style.background = '#5c0000';
    btn.disabled         = true;
}

function resetAngry() {
    isAngry  = false;
    attempts = 0;
    sessionStorage.removeItem('loginAttempts'); // clear persisted lockout
    body.classList.remove('angry');
    leftPanel.classList.remove('angry-mode');
    browL.setAttribute('d', 'M 20,16 Q 90,16 160,16');
    browR.setAttribute('d', 'M 20,16 Q 90,16 160,16');
    eyeLbl.textContent = 'watching you';
    warnTxt.classList.remove('show');
    [1, 2, 3].forEach(i => {
        const dot = document.getElementById('dot' + i);
        if (dot) dot.classList.remove('used');
    });
    if (errMsg) errMsg.style.display = 'none';
    const btn = document.getElementById('loginBtn');
    btn.textContent      = 'Sign In';
    btn.style.background = '';
    btn.disabled         = false;

    // Reset the signin captcha so the user gets a fresh token after unlock.
    resetCaptcha(signinWidgetId);
}

// ── Password visibility toggle ─────────────────────────────────────────────────

function togglePwVisibility(inputId, btn) {
    const input  = document.getElementById(inputId);
    const hidden = input.type === 'password';
    input.type   = hidden ? 'text' : 'password';
    btn.querySelector('.eye-icon').innerHTML = hidden
        ? '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/>'
        : '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
}

// ── Eye tracking ───────────────────────────────────────────────────────────────

function trackEye(wrap, e) {
    if (!wrap) return;
    const r  = wrap.parentElement.getBoundingClientRect();
    const cx = r.left + r.width  / 2;
    const cy = r.top  + r.height / 2;
    const dx = e.clientX - cx;
    const dy = e.clientY - cy;
    const d  = Math.sqrt(dx * dx + dy * dy) || 1;
    const c  = Math.min(d, 24);
    wrap.style.transform = `translate(calc(-50% + ${(dx/d)*c}px), calc(-50% + ${(dy/d)*c}px))`;
}

document.addEventListener('mousemove', (e) => {
    if (panel) {
        const r = panel.getBoundingClientRect();
        cursor.style.display = e.clientX >= r.left ? 'block' : 'none';
        cursor.style.left    = e.clientX + 'px';
        cursor.style.top     = e.clientY + 'px';
    }
    trackEye(irisL, e);
    trackEye(irisR, e);
});

// ── Init ───────────────────────────────────────────────────────────────────────
if (window.location.hash.includes('type=recovery') || window.location.search.includes('type=recovery')) {
    window.location.replace('/reset-password' + window.location.hash + window.location.search);
}
document.addEventListener('DOMContentLoaded', () => {

    // ── Wire tab buttons (replaces onclick= in HTML) ──────────────────────────
    const tabSignup = document.getElementById('tabSignup');
    const tabSignin = document.getElementById('tabSignin');
    if (tabSignup) tabSignup.addEventListener('click', () => switchTab('signup'));
    if (tabSignin) tabSignin.addEventListener('click', () => switchTab('signin'));

    // ── Wire switch-row links (replaces onclick= in HTML) ─────────────────────
    const linkToSignin = document.getElementById('linkToSignin');
    const linkToSignup = document.getElementById('linkToSignup');
    if (linkToSignin) linkToSignin.addEventListener('click', () => switchTab('signin'));
    if (linkToSignup) linkToSignup.addEventListener('click', () => switchTab('signup'));

    // ── Wire password complexity checker (replaces oninput= in HTML) ──────────
    const suPassword = document.getElementById('suPassword');
    if (suPassword) suPassword.addEventListener('input', () => checkPwComplexity(suPassword.value));

    const suConfirm = document.getElementById('suConfirmPassword');
    const suMatchContainer = document.getElementById('suMatchContainer');
    const suRuleMatch = document.getElementById('su-rule-match');

    function checkSignupMatch() {
        if (!suConfirm || !suConfirm.value) {
            if (suMatchContainer) suMatchContainer.style.display = 'none';
            return;
        }
        if (suMatchContainer) suMatchContainer.style.display = 'flex';
        
        const matches = suPassword.value === suConfirm.value;
        if (suRuleMatch) {
            suRuleMatch.classList.toggle('pass', matches);
            suRuleMatch.classList.toggle('fail', !matches);
            suRuleMatch.querySelector('.rule-icon').textContent = matches ? '✓' : '✗';
        }
    }

    if (suPassword) suPassword.addEventListener('input', checkSignupMatch);
    if (suConfirm)  suConfirm.addEventListener('input', checkSignupMatch);

    // ── Wire password visibility toggle (replaces onclick= in HTML) ───────────
    const pwToggleBtn = document.getElementById('pwToggleBtn');
    if (pwToggleBtn) {
        // Inject the default eye SVG that was previously inline in the HTML.
        pwToggleBtn.innerHTML = '<svg class="eye-icon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
        pwToggleBtn.addEventListener('click', () => togglePwVisibility('siPassword', pwToggleBtn));
    }

    // ── Wire logout button in dashboard pages (replaces onclick= in HTML) ─────
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) logoutBtn.addEventListener('click', () => { window.location.href = '/logout'; });

    // ── Wire forgot-password links ────────────────────────────────────────────
    const forgotLink          = document.getElementById('forgotLink');
    const backToSigninBtn     = document.getElementById('backToSigninBtn');
    const backToSigninFromSent = document.getElementById('backToSigninFromSent');
    if (forgotLink)           forgotLink.addEventListener('click',  () => showForgotPanel());
    if (forgotLink)           forgotLink.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') showForgotPanel(); });
    if (backToSigninBtn)      backToSigninBtn.addEventListener('click',  () => backToSignin());
    if (backToSigninFromSent) backToSigninFromSent.addEventListener('click', () => backToSignin());

    if (document.getElementById('tabSignup')) {
        switchTab('signin');
        if (errMsg) errMsg.style.display = 'none';
        initSignupForm();
        initLoginForm();
        initForgotPasswordForm();
    }

    fetchConfig();

    // ── REM-3 FIX: Server-side lockout check on page load ────────────────────
    // After 3 failed attempts the server rate-limiter is the real enforcement,
    // but the UI lockout (triggerAngry) can be bypassed by reloading the page,
    // resetting the client-side `attempts` counter to 0.
    // On DOMContentLoaded we check how many attempts the server has already
    // recorded by probing /login with a dummy OPTIONS-like HEAD call — but
    // the cleanest approach without a dedicated endpoint is to persist the
    // attempt count in sessionStorage so a page reload can't reset it.
    const stored = parseInt(sessionStorage.getItem('loginAttempts') || '0', 10);
    if (stored >= 3) {
        // Restore the locked UI without re-counting any attempts.
        attempts = stored;
        triggerAngry();
    } else {
        attempts = stored;
        // Restore any previously used dots.
        for (let i = 1; i <= stored; i++) {
            const dot = document.getElementById('dot' + i);
            if (dot) dot.classList.add('used');
        }
    }
});