// callback-handler.js — OAuth callback landing page logic.
//
// Supabase SSO redirects the browser to /callback with the session tokens
// embedded in the URL hash fragment (#access_token=...&refresh_token=...).
// This script:
//   1. Extracts the access_token from the hash.
//   2. Posts it to /set-cookie (which validates it server-side before storing).
//   3. Replaces the URL hash so the token is not visible in browser history.
//   4. Redirects to /private once the cookie is set.
//
// If no hash token is present the cookie was already set (server rendered the
// full dashboard) so no action is needed — dashboard.js handles the rest.

(async function handleOAuthCallback() {
    const loadingState = document.getElementById('loadingState');
    const mainContent  = document.getElementById('mainContent');

    // Parse the URL hash fragment into a key→value map.
    const hash   = window.location.hash.slice(1);
    const params = new URLSearchParams(hash);
    const token  = params.get('access_token');

    if (!token) {
        // No hash token — the server already rendered the full dashboard
        // (authenticated via cookie). Show the content and stop.
        if (loadingState) loadingState.style.display = 'none';
        if (mainContent)  mainContent.style.display  = '';
        return;
    }

    // Clear the hash from the browser URL immediately so the raw token
    // is not stored in browser history or visible in the address bar.
    history.replaceState(null, '', window.location.pathname);

    try {
        const resp = await fetch('/set-cookie', {
            method  : 'POST',
            headers : { 'Content-Type': 'application/x-www-form-urlencoded' },
            body    : new URLSearchParams({ token })
        });

        if (resp.ok) {
            // Cookie is set and validated — go to the authenticated dashboard.
            window.location.replace('/private');
        } else {
            // Token was rejected by the server (expired, malformed, etc.).
            console.error('[callback] /set-cookie rejected token — redirecting to login.');
            window.location.replace('/');
        }
    } catch (err) {
        console.error('[callback] Network error during token exchange:', err);
        window.location.replace('/');
    }
}());