// dashboard.js — shared logic for private.html and callback.html.
// Loaded as an external file so a strict Content Security Policy can apply.
//
// User identity is read from data attributes on <body> — set server-side
// in the HTML attribute context (HTML-escaped), never inside a <script> block.
// This avoids any JS syntax errors in the template before server substitution.

// ── User identity ──────────────────────────────────────────────────────────
(function initUser() {
    const body = document.getElementById('mainBody');
    if (!body) return;
    window.USER = {
        name:  body.dataset.userName  || '',
        email: body.dataset.userEmail || ''
    };
}());

// ── Eye tracking ───────────────────────────────────────────────────────────
(function initDashboardEyes() {
    const eyes = [
        document.getElementById('irisL'),
        document.getElementById('irisR'),
    ].filter(Boolean);

    if (eyes.length === 0) return;

    document.addEventListener('mousemove', (e) => {
        eyes.forEach((wrap) => {
            const outer = wrap.closest('.eye-outer');
            if (!outer) return;
            const rect  = outer.getBoundingClientRect();
            const cx    = rect.left + rect.width  / 2;
            const cy    = rect.top  + rect.height / 2;
            const dx    = e.clientX - cx;
            const dy    = e.clientY - cy;
            const angle = Math.atan2(dy, dx);
            const dist  = Math.min(Math.hypot(dx, dy), 14);
            const tx    = Math.cos(angle) * dist;
            const ty    = Math.sin(angle) * dist;
            wrap.style.transform = `translate(calc(-50% + ${tx}px), calc(-50% + ${ty}px))`;
        });
    });
}());

// ── Session / logout ───────────────────────────────────────────────────────
// Wire the Sign out button via addEventListener — no onclick= in HTML.
(function initLogout() {
    const btn = document.getElementById('logoutBtn');
    if (btn) btn.addEventListener('click', () => { window.location.href = '/logout'; });
}());