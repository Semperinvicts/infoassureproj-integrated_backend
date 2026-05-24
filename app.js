const express      = require("express");
const dotenv       = require("dotenv");
const bodyParser   = require("body-parser");
const cookieParser = require("cookie-parser");
const path         = require("path");
const fs           = require("fs");
const rateLimit    = require("express-rate-limit");
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
// Shared template renderer — applies both HTML and JS context escaping.
// Used by /private and /callback to avoid code duplication.
// ─────────────────────────────────────────────────────────────────────────────
function renderDashboard(template, user) {
    const safeName  = escapeHtml(user.user_metadata?.display_name || "User");
    const safeEmail = escapeHtml(user.email);
    const jsName    = jsonStringify(user.user_metadata?.display_name || "User");
    const jsEmail   = jsonStringify(user.email);

    return template
        .replace(/\{\{name\}\}/g,     safeName)
        .replace(/\{\{email\}\}/g,    safeEmail)
        .replace(/\{\{js_name\}\}/g,  jsName)
        .replace(/\{\{js_email\}\}/g, jsEmail);
}

// ─────────────────────────────────────────────────────────────────────────────
// Async error wrapper — prevents unhandled promise rejections from crashing
// the server or leaving requests hanging (VUL-A04).
// ─────────────────────────────────────────────────────────────────────────────
const asyncHandler = fn => (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);

// Helmet — security headers with explicit CSP (REC-01).
// 'unsafe-inline' removed from scriptSrc — all onclick/oninput handlers have
// been moved to addEventListener calls in script.js and dashboard.js instead.
// styleSrc retains 'unsafe-inline' because hCaptcha injects inline styles into
// its widget iframe — removing it breaks the captcha widget rendering.
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc    : ["'self'"],
            scriptSrc     : ["'self'", "https://js.hcaptcha.com"],
            // scriptSrcAttr omitted — no inline event handlers remain in HTML.
            frameSrc      : [
                "https://www.youtube-nocookie.com",
                "https://newassets.hcaptcha.com"
            ],
            connectSrc    : ["'self'", SUPABASE_URL, "https://*.hcaptcha.com"],
            styleSrc      : ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],
            fontSrc       : ["https://fonts.gstatic.com", "data:"],
            imgSrc        : ["'self'", "data:", "https://*.hcaptcha.com"],
            formAction    : ["'self'", SUPABASE_URL, "https://accounts.google.com", "https://appleid.apple.com"],
            objectSrc     : ["'none'"],
            baseUri       : ["'self'"],
            frameAncestors: ["'none'"]
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

app.use(express.json({ limit: "16kb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "16kb" }));
app.use(cookieParser());
app.use(express.static("public"));

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

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "Frontend.html"));
});

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
app.post("/login", loginLimiter, asyncHandler(async (req, res) => {
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
app.post("/googleSSO", asyncHandler(async (req, res) => {
    const { data, error } = await supabase.auth.signInWithOAuth({
        provider : "google",
        options  : { redirectTo: `${APP_BASE_URL}/callback` }
    });

    if (error || !data?.url) {
        console.error("[Google SSO error]", error?.message);
        return res.status(500).json({ error: "SSO initialization failed." });
    }

    return res.redirect(data.url);
}));

app.post("/appleSSO", asyncHandler(async (req, res) => {
    const { data, error } = await supabase.auth.signInWithOAuth({
        provider : "apple",
        options  : { redirectTo: `${APP_BASE_URL}/callback` }
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

app.get("/logout", (req, res) => {
    res.clearCookie("access_token", { path: "/" });
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

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}/`);
});