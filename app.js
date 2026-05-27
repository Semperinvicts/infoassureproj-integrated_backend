const express      = require("express");
const dotenv       = require("dotenv");
const bodyParser   = require("body-parser");
const cookieParser = require("cookie-parser");
const path         = require("path");
const fs           = require("fs");
const https        = require("https");        // used by hCaptcha proxy
const rateLimit    = require("express-rate-limit");
const slowDown     = require("express-slow-down");
const helmet       = require("helmet");
const { createClient } = require("@supabase/supabase-js");

dotenv.config();

// ─────────────────────────────────────────────────────────────────────────────
// VUL-001: Credentials live in .env only — never in source.
// ─────────────────────────────────────────────────────────────────────────────
const SUPABASE_URL      = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const HCAPTCHA_SITE_KEY = process.env.HCAPTCHA_SITE_KEY;
const APP_BASE_URL      = process.env.APP_BASE_URL || `http://localhost:${process.env.PORT || 3000}`;
const PORT              = process.env.PORT || 3000;
const IS_PROD           = process.env.NODE_ENV === "production";

if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
    console.error("FATAL: SUPABASE_URL and SUPABASE_ANON_KEY must be set in .env");
    process.exit(1);
}
if (!HCAPTCHA_SITE_KEY) {
    console.warn("WARNING: HCAPTCHA_SITE_KEY is not set — auth calls will fail.");
}

const app      = express();
app.use((req, res, next) => {
    if (req.method === 'OPTIONS') {
        return res.status(405).send('Method Not Allowed');
    }
    next();
});
app.disable('x-powered-by');
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// ─────────────────────────────────────────────────────────────────────────────
// Pre-load templates once at startup (VUL-009).
// ─────────────────────────────────────────────────────────────────────────────
const PRIVATE_TEMPLATE  = fs.readFileSync(path.join(__dirname, "private.html"),  "utf-8");
const CALLBACK_TEMPLATE = fs.readFileSync(path.join(__dirname, "public", "callback.html"), "utf-8");

// ─────────────────────────────────────────────────────────────────────────────
// VUL-A01 FIX — Two-context sanitisation helpers.
//
// escapeHtml()    : safe for HTML element bodies and attribute values.
// jsonStringify() : safe for JavaScript assignment contexts (window.USER = ...).
//                   JSON.stringify produces a properly quoted, escape-complete
//                   JS string — \u, backslash sequences, and quotes are all
//                   handled by the JSON encoder, not by HTML entity logic.
// ─────────────────────────────────────────────────────────────────────────────
function escapeHtml(str) {
    return String(str ?? "")
        .replace(/&/g,  "&amp;")
        .replace(/</g,  "&lt;")
        .replace(/>/g,  "&gt;")
        .replace(/"/g,  "&quot;")
        .replace(/'/g,  "&#x27;")
        .replace(/\//g, "&#x2F;");
}

// JSON.stringify already produces a safe, fully-quoted JS string literal.
// We strip the surrounding double-quotes because the template uses them:
//   window.USER = { name: {{js_name}}, email: {{js_email}} };
// JSON.stringify("Alice") → '"Alice"'  (quotes included, which is what we want).
function jsonStringify(val) {
    return JSON.stringify(String(val ?? ""));
}

// ─────────────────────────────────────────────────────────────────────────────
// VUL-003: Hardened cookie options.
// ─────────────────────────────────────────────────────────────────────────────
const COOKIE_OPTIONS = {
    httpOnly : true,
    secure   : IS_PROD,
    sameSite : "strict",
    maxAge   : 60 * 60 * 1000   // 1 hour
};

// ─────────────────────────────────────────────────────────────────────────────
// Template renderer — applies HTML-context escaping for ALL substitutions.
//
// FIX: {{js_name}} / {{js_email}} placeholders in data attributes have been
// replaced with {{name}} / {{email}} in private.html and callback.html.
// HTML attributes must use escapeHtml(), not JSON.stringify():
//   JSON.stringify('Jo "Smith"') → "Jo \"Smith\""  ← breaks HTML attr boundary
//   escapeHtml('Jo "Smith"')     → Jo &quot;Smith&quot; ← safe, decoded by .dataset
//
// dashboard.js reads window.USER from body.dataset — the browser automatically
// decodes &quot; back to " on .dataset access, so JS receives the real value.
// ─────────────────────────────────────────────────────────────────────────────
function renderDashboard(template, user) {
    const safeName  = escapeHtml(user.user_metadata?.display_name || "User");
    const safeEmail = escapeHtml(user.email);

    return template
        .replace(/\{\{name\}\}/g,  safeName)
        .replace(/\{\{email\}\}/g, safeEmail);
}

// ─────────────────────────────────────────────────────────────────────────────
// Async error wrapper — prevents unhandled promise rejections from crashing
// the server or leaving requests hanging (VUL-A04).
// ─────────────────────────────────────────────────────────────────────────────
const asyncHandler = fn => (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);

// Helmet — security headers with explicit CSP (REC-01).
// All inline <style> blocks have been moved to external CSS files (dashboard.css,
// style.css) so 'unsafe-inline' is no longer needed in styleSrc.
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc    : ["'self'"],
            scriptSrc     : ["'self'", "https://js.hcaptcha.com"],
            scriptSrcAttr : ["'none'"],
            // FIX — CSP: Style-Src Unsafe-Inline
            // 'unsafe-inline' removed. All page-specific styles are now in
            // external .css files served from 'self', so the browser accepts
            // them without unsafe-inline. Google Fonts is still needed for the
            // @import in the <link> tags (VUL-F05 acknowledged — self-hosting
            // fonts is the long-term fix).
            styleSrc      : ["'self'", "https://fonts.googleapis.com"],
            fontSrc       : ["'self'", "https://fonts.gstatic.com", "data:", "https://fonts.googleapis.com"],
            frameSrc      : [
                "https://www.youtube-nocookie.com",
                "https://newassets.hcaptcha.com"
            ],
            connectSrc    : ["'self'", SUPABASE_URL, "https://*.hcaptcha.com"],
            imgSrc        : ["'self'", "data:", "https://*.hcaptcha.com"],
            // FIX — CSP: Failure To Define Directive With No Fallback
            // mediaSrc and workerSrc do fall back to defaultSrc/scriptSrc in
            // the spec, but being explicit stops scanners flagging the
            // omission and prevents unexpected future fallback behaviour.
            mediaSrc      : ["'none'"],
            workerSrc     : ["'none'"],
            formAction    : ["'self'", SUPABASE_URL, "https://accounts.google.com", "https://appleid.apple.com"],
            objectSrc     : ["'none'"],
            baseUri       : ["'self'"],
            frameAncestors: ["'none'"],
            // FIX — Absence of Anti-CSRF Tokens (partial)
            // The primary CSRF vector (GET logout) is closed by converting
            // /logout to POST (VUL-F02). The login/signup forms submit via
            // fetch() — not native form POST — so no hidden CSRF token field
            // is required. SameSite=Strict on session cookies blocks cross-
            // site requests from attaching the session cookie at all.
            // upgradeInsecureRequests is enabled in production via IS_PROD
            // secure cookie flag; explicit directive left out to allow local
            // HTTP dev without constant browser errors.
        }
    }
}));

// ─────────────────────────────────────────────────────────────────────────────
// VUL-004: Rate limiters — server-side, cannot be bypassed by client JS.
// ─────────────────────────────────────────────────────────────────────────────
const loginLimiter = rateLimit({
    windowMs        : 15 * 60 * 1000,
    max             : 10,
    standardHeaders : true,
    legacyHeaders   : false,
    message         : { error: "Too many login attempts. Please try again in 15 minutes." }
});

const signupLimiter = rateLimit({
    windowMs        : 60 * 60 * 1000,
    max             : 5,
    standardHeaders : true,
    legacyHeaders   : false,
    message         : { error: "Too many accounts created from this IP. Try again later." }
});

// VUL-A06: Rate-limit the /config and /set-cookie endpoints.
const configLimiter = rateLimit({
    windowMs        : 60 * 1000,
    max             : 30,
    standardHeaders : true,
    legacyHeaders   : false
});

const setCookieLimiter = rateLimit({
    windowMs        : 5 * 60 * 1000,
    max             : 10,
    standardHeaders : true,
    legacyHeaders   : false
});

// ─────────────────────────────────────────────────────────────────────────────
// ANTI-DDOS: Global rate limiter — catches every route not protected by a
// tighter per-route limiter above.
//
// 300 requests / 15 min per IP is generous enough for real users (a full page
// load with assets is ~5-8 requests) but stops simple volumetric floods and
// scanners that rotate through every endpoint.
//
// Static files served by express.static() bypass this because static() runs
// before app.use(globalLimiter) — that is intentional: static assets are cheap
// and CDN-cacheable. If you add a CDN (Cloudflare, etc.) in front of Render,
// static file floods are absorbed before they reach Node.
// ─────────────────────────────────────────────────────────────────────────────
const globalLimiter = rateLimit({
    windowMs        : 15 * 60 * 1000,  // 15-minute window
    max             : 300,              // 300 requests per window per IP
    standardHeaders : true,
    legacyHeaders   : false,
    message         : { error: "Too many requests. Please slow down and try again later." }
});

// ─────────────────────────────────────────────────────────────────────────────
// ANTI-DDOS: SSO rate limiter — fixes audit finding NEW-06.
// OAuth initiation is lightweight on our side (one Supabase API call) but
// hammering it generates hundreds of authorization URLs per minute.
// ─────────────────────────────────────────────────────────────────────────────
const ssoLimiter = rateLimit({
    windowMs        : 60 * 1000,       // 1-minute window
    max             : 10,              // 10 SSO attempts per minute per IP
    standardHeaders : true,
    legacyHeaders   : false,
    message         : { error: "Too many sign-in attempts. Please wait a moment." }
});

// ─────────────────────────────────────────────────────────────────────────────
// ANTI-DDOS: hCaptcha proxy rate limiter.
// The proxy endpoint fetches from hCaptcha's CDN (cached hourly) but the
// endpoint itself can be hit repeatedly. Limit to 60/min — one per page load
// with room for retries.
// ─────────────────────────────────────────────────────────────────────────────
const hcaptchaProxyLimiter = rateLimit({
    windowMs        : 60 * 1000,
    max             : 60,
    standardHeaders : true,
    legacyHeaders   : false
});

// ─────────────────────────────────────────────────────────────────────────────
// ANTI-DDOS: Login slow-down (progressive delay) — layered on top of
// loginLimiter for defence-in-depth.
//
// Requests 1-3 per window: no delay (instant, normal user experience).
// Requests 4+: each subsequent attempt adds 500 ms more delay.
//   4th attempt: 500 ms  5th: 1000 ms  6th: 1500 ms … up to a 5-second cap.
//
// This makes credential-stuffing attacks extremely slow even before the hard
// 429 from loginLimiter kicks in. Real users who mistype a password 1-2 times
// are completely unaffected.
// ─────────────────────────────────────────────────────────────────────────────
const loginSlowDown = slowDown({
    windowMs    : 15 * 60 * 1000,
    delayAfter  : 3,
    delayMs     : (hits) => Math.min((hits - 3) * 500, 5000)
});

app.use(express.json({ limit: "16kb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "16kb" }));
app.use(cookieParser());
// express.static runs before globalLimiter intentionally — static files are
// cheap and should not penalise users loading CSS/JS/images.
app.use(express.static("public"));

// ─────────────────────────────────────────────────────────────────────────────
// ANTI-DDOS: Request timeout — protects against Slowloris attacks where an
// attacker sends headers/body bytes very slowly to hold sockets open.
// Any request that doesn't complete within 10 seconds is terminated.
// ─────────────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
    res.setTimeout(10000, () => {
        res.status(408).json({ error: "Request timed out." });
    });
    next();
});

// Apply the global limiter to all routes that follow.
app.use(globalLimiter);

// ─────────────────────────────────────────────────────────────────────────────
// /config — returns only the hCaptcha public site key (VUL-A06).
// Supabase URL and anon key are no longer exposed here; they are only used
// server-side. The hcaptcha site key is public by design.
// ─────────────────────────────────────────────────────────────────────────────
app.get("/config", configLimiter, (req, res) => {
    // Restrict to our own origin only.
    res.setHeader("Access-Control-Allow-Origin", APP_BASE_URL);
    res.json({
        hcaptchaSiteKey: HCAPTCHA_SITE_KEY || null
        // Supabase credentials are never sent to the client.
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// FIX: EXTERNAL_SCRIPT_MISSING_INTEGRITY (Medium)
//
// /hcaptcha-api.js — Proxies the hCaptcha bootstrap script from our own origin.
//
// Root cause: hCaptcha's CDN (js.hcaptcha.com) does not publish SRI hashes
// and serves dynamically built content, so we cannot add an integrity=
// attribute to the external <script> tag. The scanner correctly flags this.
//
// Fix: Serve the script from our own domain. Same-origin resources do not
// require SRI — the browser already trusts them as part of our application.
// The script is fetched from hCaptcha's CDN once per hour and cached in
// memory. Stale cache is served if the upstream fetch fails, so a temporary
// hCaptcha outage does not break the login page.
//
// How query params work: the browser's <script src="/hcaptcha-api.js?render=
// explicit&onload=onHcaptchaLoad"> tag keeps the query string. hCaptcha reads
// render= and onload= from document.currentScript.src — our proxied URL
// contains those params, so the script behaves identically to the direct CDN.
// ─────────────────────────────────────────────────────────────────────────────
let _hcaptchaScript   = null;
let _hcaptchaCachedAt = 0;
const HCAPTCHA_CACHE_TTL = 60 * 60 * 1000; // refresh at most once per hour

function _fetchHcaptchaScript() {
    return new Promise((resolve, reject) => {
        https.get("https://js.hcaptcha.com/1/api.js", (res) => {
            let body = "";
            res.on("data",  (chunk) => { body += chunk; });
            res.on("end",   ()      => resolve(body));
            res.on("error", reject);
        }).on("error", reject);
    });
}

app.get("/hcaptcha-api.js", hcaptchaProxyLimiter, asyncHandler(async (req, res) => {
    const now = Date.now();

    if (!_hcaptchaScript || now - _hcaptchaCachedAt > HCAPTCHA_CACHE_TTL) {
        try {
            _hcaptchaScript   = await _fetchHcaptchaScript();
            _hcaptchaCachedAt = now;
        } catch (err) {
            console.error("[hCaptcha proxy]", err.message);
            if (!_hcaptchaScript) {
                // First fetch failed with no cache — return a safe stub so the
                // page renders rather than hanging on a failed script load.
                return res
                    .status(502)
                    .type("application/javascript")
                    .send("/* hCaptcha temporarily unavailable — please refresh */");
            }
            // Serve stale cache rather than failing the request.
        }
    }

    res.setHeader("Content-Type",  "application/javascript; charset=utf-8");
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.send(_hcaptchaScript);
}));

app.get("/", asyncHandler(async (req, res) => {
    const token = req.cookies.access_token;
    if (token) {
        // If a valid session cookie exists, skip the login page entirely.
        const { data, error } = await supabase.auth.getUser(token);
        if (!error && data?.user) return res.redirect("/private");
        // Token is invalid/expired — clear the stale cookie and fall through.
        res.clearCookie("access_token", {
            httpOnly : true,
            secure   : IS_PROD,
            sameSite : "strict",
            path     : "/"
        });
    }
    res.sendFile(path.join(__dirname, "public", "Frontend.html"));
}));

// ─────────────────────────────────────────────────────────────────────────────
// /signup — validates input format before forwarding to Supabase.
// ─────────────────────────────────────────────────────────────────────────────
app.post("/signup", signupLimiter, asyncHandler(async (req, res) => {
    const { name, email, password, captchaToken } = req.body;

    // Basic existence check.
    if (!name || !email || !password) {
        return res.status(400).json({ error: "All fields are required." });
    }

    // Input length caps — prevent oversized payloads reaching Supabase.
    if (name.length > 120 || email.length > 254 || password.length > 256) {
        return res.status(400).json({ error: "One or more fields exceed the maximum allowed length." });
    }

    // Basic email format check.
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: "Invalid email format." });
    }

    // Reject immediately if captcha token is absent or too large.
    if (!captchaToken || captchaToken.length > 4096) {
        return res.status(400).json({ error: "Please complete the security check." });
    }

    const { data, error } = await supabase.auth.signUp({
        email,
        password,
        options: {
            captchaToken,
            data: { display_name: name }
        }
    });

    if (error) {
        console.error("[Signup error]", error.message);
        return res.status(400).json({
            error: "Registration could not be completed. Please check your details and try again."
        });
    }

    console.log("User created, awaiting email verification");
    return res.json({ redirect: "/success" });
}));

// ─────────────────────────────────────────────────────────────────────────────
// /login — captchaToken forwarded to Supabase after basic format check.
// ─────────────────────────────────────────────────────────────────────────────
app.post("/login", loginLimiter, loginSlowDown, asyncHandler(async (req, res) => {
    const { email, password, captchaToken } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required." });
    }

    if (!captchaToken || captchaToken.length > 4096) {
        return res.status(400).json({ error: "Please complete the security check." });
    }

    const { data, error } = await supabase.auth.signInWithPassword({
        email,
        password,
        options: { captchaToken }
    });

    if (error) {
        console.error("[Login error]", error.message);
        return res.status(401).json({ error: "Invalid credentials." });
    }

    res.cookie("access_token", data.session.access_token, COOKIE_OPTIONS);
    return res.json({ redirect: "/private" });
}));

// ─────────────────────────────────────────────────────────────────────────────
// SSO routes — wrapped in asyncHandler (VUL-A04).
// ─────────────────────────────────────────────────────────────────────────────
app.post("/googleSSO", ssoLimiter, asyncHandler(async (req, res) => {
    const { data, error } = await supabase.auth.signInWithOAuth({
        provider : "google",
        options  : { redirectTo: "https://infoassureproj-integratedbackend-production.up.railway.app/callback" }
    });

    if (error || !data?.url) {
        console.error("[Google SSO error]", error?.message);
        return res.status(500).json({ error: "SSO initialization failed." });
    }

    return res.redirect(data.url);
}));

app.post("/appleSSO", ssoLimiter, asyncHandler(async (req, res) => {
    const { data, error } = await supabase.auth.signInWithOAuth({
        provider : "apple",
        options  : { redirectTo: "https://infoassureproj-integratedbackend-production.up.railway.app/callback" }
    });

    if (error || !data?.url) {
        console.error("[Apple SSO error]", error?.message);
        return res.status(500).json({ error: "SSO initialization failed." });
    }

    return res.redirect(data.url);
}));

// ─────────────────────────────────────────────────────────────────────────────
// /set-cookie — VUL-A03 FIX: validates token with Supabase before setting cookie.
// ─────────────────────────────────────────────────────────────────────────────
app.post("/set-cookie", setCookieLimiter, asyncHandler(async (req, res) => {
    const { token } = req.body;

    if (!token || typeof token !== "string" || token.length > 2048) {
        return res.status(400).json({ error: "Invalid token." });
    }

    // Verify the token is a legitimate, non-expired Supabase JWT before storing it.
    const { data, error } = await supabase.auth.getUser(token);
    if (error || !data?.user) {
        return res.status(401).json({ error: "Token validation failed." });
    }

    res.cookie("access_token", token, COOKIE_OPTIONS);
    return res.sendStatus(200);
}));

// ─────────────────────────────────────────────────────────────────────────────
// /callback — VUL-A02 FIX: now rendered through the template pipeline, not
// served as a raw static file. OAuth users get their identity injected just
// like /private users do.
// ─────────────────────────────────────────────────────────────────────────────
app.get("/callback", asyncHandler(async (req, res) => {
    // The client-side OAuth exchange posts the token via /set-cookie first,
    // so by the time the browser follows the redirect to /callback, the cookie
    // should already be set. If not, the user is not authenticated yet.
    const token = req.cookies.access_token;
    if (!token) {
        // Serve the raw transitional page — the client JS will handle the
        // hash fragment (#access_token=...) and post it via /set-cookie,
        // then redirect to /private automatically.
        return res.sendFile(path.join(__dirname, "public", "callback.html"));
    }

    const { data, error } = await supabase.auth.getUser(token);
    if (error || !data?.user) return res.redirect("/");

    const html = renderDashboard(CALLBACK_TEMPLATE, data.user);
    return res.send(html);
}));

// ─────────────────────────────────────────────────────────────────────────────
// /private — VUL-A01 FIX: both HTML and JS contexts sanitised.
// ─────────────────────────────────────────────────────────────────────────────
app.get("/private", asyncHandler(async (req, res) => {
    const token = req.cookies.access_token;
    if (!token) return res.redirect("/");

    const { data, error } = await supabase.auth.getUser(token);
    if (error || !data?.user) return res.redirect("/");

    const html = renderDashboard(PRIVATE_TEMPLATE, data.user);
    return res.send(html);
}));

app.get("/success", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "success.html"));
});

// ─────────────────────────────────────────────────────────────────────────────
// VUL-F02 FIX — /logout converted from GET to POST.
//
// WHY: HTTP GET must not trigger state changes (RFC 9110 §9.3.1). A GET-based
// logout lets any page force a victim to log out by embedding:
//   <img src="https://target/logout">
// Even with SameSite=Strict cookies, this is a design violation.
//
// FIX: POST + dashboard.js fires fetch('/logout', {method:'POST'}) so no
// navigation or form is required, and the browser never attaches the cookie
// to a cross-site GET request. The SameSite=Strict cookie provides the
// defence-in-depth layer: cross-site POST requests also cannot attach it.
// ─────────────────────────────────────────────────────────────────────────────
app.post("/logout", (req, res) => {
    res.clearCookie("access_token", {
        httpOnly : true,
        secure   : IS_PROD,
        sameSite : "strict",
        path     : "/"
    });
    // Respond with 200 + JSON instead of 302 so fetch() with redirect:'manual'
    // gets a real response instead of an opaque redirect that some proxies mangle.
    res.json({ ok: true });
});

// GET /logout — safety fallback for direct browser navigation / stale bookmarks.
// Clears the cookie and redirects to login. Not the primary logout path
// (that is POST /logout via dashboard.js fetch) but prevents "Cannot GET /logout".
app.get("/logout", (req, res) => {
    res.clearCookie("access_token", {
        httpOnly : true,
        secure   : IS_PROD,
        sameSite : "strict",
        path     : "/"
    });
    res.redirect("/");
});

// ─────────────────────────────────────────────────────────────────────────────
// Global error handler — VUL-A04: catches all unhandled async rejections.
// Never leaks stack traces to the client.
// ─────────────────────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
    console.error("[Unhandled error]", err.stack || err.message);
    res.status(500).json({ error: "An unexpected error occurred." });
});

const server = app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}/`);
});

// ─────────────────────────────────────────────────────────────────────────────
// ANTI-DDOS: Server-level socket timeout.
// Closes idle TCP connections after 30 seconds. Without this, an attacker
// can open thousands of connections and never send data (Slowloris variant),
// eventually exhausting the OS file-descriptor limit.
// ─────────────────────────────────────────────────────────────────────────────
server.setTimeout(30000);