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
// VUL-F02 FIX: logout fires a POST request instead of navigating to GET /logout.
// Using fetch() means the browser never sends a GET to /logout, so a crafted
// <img src="/logout"> on a third-party page cannot force a session termination.
// On success the server redirects to /, which window.location.replace() follows.
(function initLogout() {
    const btn = document.getElementById('logoutBtn');
    if (!btn) return;
    btn.addEventListener('click', async () => {
        try {
            // POST to /logout — server clears the cookie and returns 302.
            // We ignore resp.url because on some hosts (e.g. Render) the
            // redirect URL resolves back to /logout. Always navigate to / directly.
            await fetch('/logout', { method: 'POST', redirect: 'manual' });
        } catch (_) {
            // Network error is fine — the server already cleared the cookie.
        } finally {
            // Always send the browser to the login page regardless of network result.
            window.location.replace('/');
        }
    });
}());