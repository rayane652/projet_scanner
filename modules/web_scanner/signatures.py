import logging

logger = logging.getLogger(__name__)

_RE_COMPILED = {}


def _compile_pat(pattern, flags=0):
    key = (pattern, flags)
    if key in _RE_COMPILED:
        return _RE_COMPILED[key]
    try:
        import re as _re
        c = _re.compile(pattern, flags)
        _RE_COMPILED[key] = c
        return c
    except _re.error as e:
        logger.debug("Bad regex: %r - %s", pattern, e)
        _RE_COMPILED[key] = None
        return None


TECH_SIGNATURES = {
    "wordpress": {"n": "WordPress", "c": "CMS",
        "h": [("x-powered-by", r"wordpress", 80)],
        "m": {"generator": (r"WordPress\s*([\d.]+)?", 100)},
        "t": [("wp-content", 80), ("wp-json", 80), ("wp-includes", 80), ("xmlrpc.php", 70)],
        "u": [("/wp-content/", 100), ("/wp-admin/", 100), ("/wp-includes/", 100), ("/wp-json/", 100)],
        "k": [("wordpress_", 80), ("wordpress_logged_in", 80)],
        "s": [("wp-content", 80), ("wp-includes", 80)]},
    "drupal": {"n": "Drupal", "c": "CMS",
        "h": [("x-drupal-cache", r".", 80), ("x-generator", r"drupal", 100)],
        "m": {"generator": (r"Drupal\s*([\d.]+)?", 100)},
        "t": [("drupal", 70), ("sites/default", 80), ("drupal.js", 80)],
        "u": [("/sites/default/", 80), ("/node/", 50)]},
    "joomla": {"n": "Joomla", "c": "CMS",
        "m": {"generator": (r"Joomla!?\s*([\d.]+)?", 100)},
        "t": [("joomla", 70), ("com_content", 70), ("option=com_", 70)],
        "u": [("/components/", 50), ("option=com_", 70)]},
    "magento": {"n": "Magento", "c": "CMS",
        "h": [("x-magento-init", r".", 80), ("x-magento-cache", r".", 80)],
        "t": [("mage/", 70), ("Magento_", 70), ("requirejs-config", 70)],
        "u": [("/pub/", 50), ("/static/version", 70)],
        "k": [("mage-cache-sessid", 80), ("mage-cache-storage", 80)]},
    "shopify": {"n": "Shopify", "c": "E-Commerce",
        "h": [("x-shopid", r".", 100), ("x-shopify-stage", r".", 100)],
        "t": [("myshopify.com", 100), ("cdn.shopify.com", 100)],
        "k": [("shopify_", 80), ("cart", 50)]},
    "ghost": {"n": "Ghost", "c": "CMS",
        "h": [("x-ghost-cache-status", r".", 80)],
        "m": {"generator": (r"Ghost\s*([\d.]+)?", 100)},
        "t": [("ghost", 70), ("ghost-portal", 70)]},
    "strapi": {"n": "Strapi", "c": "CMS",
        "h": [("x-strapi", r".", 80)],
        "t": [("strapi-admin", 70)],
        "u": [("/admin/", 50), ("/content-manager/", 70)]},
    "squarespace": {"n": "Squarespace", "c": "CMS",
        "t": [("static.squarespace.com", 100), ("squarespace-cdn", 70)]},
    "wix": {"n": "Wix", "c": "CMS",
        "t": [("wixstatic.com", 100), ("wix-bolt", 70), ("wixCode", 70)]},
    # ── Frameworks ──
    "laravel": {"n": "Laravel", "c": "Framework",
        "h": [("x-powered-by", r"laravel", 80)],
        "k": [("laravel_session", 100), ("xsrf-token", 70)],
        "t": [("csrf-token", 70), ("livewire", 70)],
        "u": [("/artisan", 100)]},
    "django": {"n": "Django", "c": "Framework",
        "h": [("x-powered-by", r"django", 80), ("x-django", r".", 80)],
        "k": [("csrftoken", 80), ("sessionid", 50)],
        "t": [("csrfmiddlewaretoken", 80)],
        "u": [("/static/admin/", 80)]},
    "flask": {"n": "Flask", "c": "Framework",
        "h": [("server", r"werkzeug", 100)],
        "k": [("session", 50)]},
    "fastapi": {"n": "FastAPI", "c": "Framework",
        "h": [("server", r"uvicorn", 80)],
        "u": [("/docs", 70), ("/redoc", 70), ("/openapi.json", 70)]},
    "symfony": {"n": "Symfony", "c": "Framework",
        "h": [("x-powered-by", r"symfony", 80), ("x-debug-token", r".", 80)],
        "k": [("symfony", 70)],
        "t": [("sf_", 50)],
        "u": [("/_profiler/", 100), ("/_wdt/", 80)]},
    "ruby_on_rails": {"n": "Ruby on Rails", "c": "Framework",
        "h": [("x-powered-by", r"rails", 80), ("x-runtime", r".", 50)],
        "k": [("_session_id", 80), ("_rails", 70)],
        "t": [("csrf-param", 70), ("turbolinks", 70)]},
    "express": {"n": "Express", "c": "Framework",
        "h": [("x-powered-by", r"express", 100)],
        "k": [("express:sess", 70)]},
    "spring_boot": {"n": "Spring Boot", "c": "Framework",
        "h": [("x-application-context", r".", 80)],
        "t": [("whitelabel error page", 80)],
        "u": [("/actuator/", 100), ("/actuator/health", 100)]},
    "asp_net": {"n": "ASP.NET", "c": "Framework",
        "h": [("x-aspnet-version", r".", 80), ("x-powered-by", r"asp\.net", 80)],
        "k": [(".aspxauth", 80), ("asp.net_sessionid", 70), ("aspsessionid", 70)],
        "t": [("__viewstate", 100), ("__eventvalidation", 100)],
        "u": [(".aspx", 70), (".asmx", 60)]},
    "next_js": {"n": "Next.js", "c": "Framework",
        "h": [("x-nextjs-cache", r".", 80), ("x-powered-by", r"next\.js", 80)],
        "t": [("__NEXT_DATA__", 100), ("_next/static", 100), ("__nxtpg", 100)],
        "u": [("/_next/", 100)]},
    "nuxt_js": {"n": "Nuxt.js", "c": "Framework",
        "t": [("__nuxt", 100), ("_nuxt/", 100)],
        "u": [("/_nuxt/", 100)]},
    "gatsby": {"n": "Gatsby", "c": "Framework",
        "t": [("___gatsby", 100), ("gatsby-", 70)],
        "u": [("/page-data/", 100)]},
    "vue_js": {"n": "Vue.js", "c": "Framework",
        "t": [("__vue__", 100), ("vue.js", 80), ("v-bind", 50), ("v-if", 50), ("v-model", 50)]},
    "react": {"n": "React", "c": "Framework",
        "t": [("data-reactroot", 100), ("data-reactid", 100), ("reactroot", 80), ("__react", 70)],
        "u": [("/_next/static/", 50)]},
    "angular": {"n": "Angular", "c": "Framework",
        "t": [("ng-app", 100), ("ng-version", 100), ("angular", 70), ("_ng", 50)]},
    "svelte": {"n": "Svelte", "c": "Framework",
        "t": [("svelte-", 70), ("__svelte", 80)]},
    "astro": {"n": "Astro", "c": "Framework",
        "t": [("__astro", 80), ("astro-", 70)]},
    "remix": {"n": "Remix", "c": "Framework",
        "t": [("__remix", 80)],
        "u": [("/_remix", 70)]},
    # ── Frontend Libraries ──
    "jquery": {"n": "jQuery", "c": "JavaScript Library",
        "t": [("jquery", 70), ("jquery.js", 100), ("jquery.min.js", 100)],
        "s": [("jquery", 70)]},
    "bootstrap": {"n": "Bootstrap", "c": "CSS Framework",
        "t": [("bootstrap", 70), ("bootstrap.css", 100), ("bootstrap.min.css", 100), ("bootstrap.bundle", 100)]},
    "tailwind": {"n": "Tailwind CSS", "c": "CSS Framework",
        "t": [("tailwindcss", 100), ("@tailwind", 100)]},
    "bulma": {"n": "Bulma", "c": "CSS Framework",
        "t": [("bulma", 70), ("bulma.io", 100)]},
    "materialize": {"n": "Materialize", "c": "CSS Framework",
        "t": [("materialize", 70), ("materialize.css", 100)]},
    "alpine": {"n": "Alpine.js", "c": "JavaScript Library",
        "t": [("alpinejs", 100), ("x-data", 60), ("x-init", 50)]},
    "htmx": {"n": "HTMX", "c": "JavaScript Library",
        "t": [("htmx", 70), ("htmx.org", 100), ("hx-get", 60), ("hx-post", 60)]},
    "mootools": {"n": "MooTools", "c": "JavaScript Library",
        "t": [("mootools", 70), ("mootools.js", 100)]},
    "prototype": {"n": "Prototype", "c": "JavaScript Library",
        "t": [("prototype", 70), ("prototype.js", 100)]},
    "backbone": {"n": "Backbone.js", "c": "JavaScript Library",
        "t": [("backbone", 70), ("backbone.js", 100)]},
    "ember": {"n": "Ember", "c": "JavaScript Library",
        "t": [("ember", 70), ("ember.js", 100)]},
    # ── Web Servers ──
    "nginx": {"n": "Nginx", "c": "Web Server",
        "h": [("server", r"nginx(?:/([\d.]+))?", 80)]},
    "apache": {"n": "Apache", "c": "Web Server",
        "h": [("server", r"apache(?:/([\d.]+))?", 80)]},
    "iis": {"n": "IIS", "c": "Web Server",
        "h": [("server", r"microsoft-iis(?:/([\d.]+))?", 80)]},
    "caddy": {"n": "Caddy", "c": "Web Server",
        "h": [("server", r"caddy(?:/([\d.]+))?", 100)]},
    "tomcat": {"n": "Apache Tomcat", "c": "Web Server",
        "h": [("server", r"apache-coyote(?:/([\d.]+))?", 80)],
        "k": [("jsessionid", 70)]},
    "jetty": {"n": "Jetty", "c": "Web Server",
        "h": [("server", r"jetty(?:/([\d.]+))?", 80)]},
    "lighttpd": {"n": "Lighttpd", "c": "Web Server",
        "h": [("server", r"lighttpd(?:/([\d.]+))?", 80)]},
    "gunicorn": {"n": "Gunicorn", "c": "Web Server",
        "h": [("server", r"gunicorn", 80)]},
    "litespeed": {"n": "LiteSpeed", "c": "Web Server",
        "h": [("server", r"litespeed", 80)]},
    "openresty": {"n": "OpenResty", "c": "Web Server",
        "h": [("server", r"openresty", 80)]},
    # ── CDN / Proxy ──
    "cloudflare": {"n": "Cloudflare", "c": "CDN",
        "h": [("server", r"cloudflare", 80), ("cf-ray", r".", 100), ("cf-cache-status", r".", 80)],
        "k": [("__cfduid", 80), ("cf_clearance", 80), ("__cf_bm", 80)]},
    "akamai": {"n": "Akamai", "c": "CDN",
        "h": [("x-akamai-transformed", r".", 80)]},
    "fastly": {"n": "Fastly", "c": "CDN",
        "h": [("x-fastly-request-id", r".", 100), ("x-served-by", r"fastly", 80)]},
    "cloudfront": {"n": "CloudFront", "c": "CDN",
        "h": [("x-amz-cf-id", r".", 100), ("x-amz-cf-pop", r".", 100)]},
    "varnish": {"n": "Varnish", "c": "CDN",
        "h": [("x-varnish", r".", 80), ("x-cache", r"varnish", 70)]},
    "haproxy": {"n": "HAProxy", "c": "CDN",
        "h": [("server", r"haproxy", 80)]},
    "sucuri": {"n": "Sucuri", "c": "Security",
        "h": [("x-sucuri-id", r".", 80), ("server", r"sucuri", 70)]},
    "incapsula": {"n": "Incapsula", "c": "CDN",
        "h": [("x-iinfo", r".", 70)],
        "k": [("incap_ses_", 80), ("visid_incap_", 80)]},
    # ── Analytics / Monitoring ──
    "google_analytics": {"n": "Google Analytics", "c": "Analytics",
        "t": [("google-analytics.com/ga.js", 100), ("google-analytics.com/analytics.js", 100), ("googletagmanager.com/gtag/js", 100)],
        "s": [("google-analytics.com", 80), ("googletagmanager.com", 80)]},
    "gtm": {"n": "Google Tag Manager", "c": "Analytics",
        "t": [("googletagmanager.com/gtm.js", 100), ("gtm.start", 80)]},
    "matomo": {"n": "Matomo", "c": "Analytics",
        "t": [("matomo.js", 100), ("piwik.js", 100)],
        "k": [("pk_id.", 80), ("pk_ses.", 80), ("piwik_", 70)]},
    "hotjar": {"n": "Hotjar", "c": "Analytics",
        "t": [("hotjar", 70), ("static.hotjar.com", 100)]},
    "sentry": {"n": "Sentry", "c": "Monitoring",
        "h": [("x-sentry-error", r".", 80)],
        "t": [("sentry", 70), ("sentry.js", 100)]},
    "new_relic": {"n": "New Relic", "c": "Monitoring",
        "t": [("NREUM", 100), ("nr-", 70)]},
    "datadog": {"n": "Datadog", "c": "Monitoring",
        "t": [("datadog", 70), ("dd-rum", 70), ("datadog-rum", 70)]},
    "posthog": {"n": "PostHog", "c": "Analytics",
        "t": [("posthog", 70), ("ph-", 50)]},
    "plausible": {"n": "Plausible", "c": "Analytics",
        "t": [("plausible", 70), ("plausible.io", 100)]},
    # ── PHP / Language ──
    "php": {"n": "PHP", "c": "Language",
        "h": [("x-powered-by", r"php(?:/([\d.]+))?", 80)],
        "k": [("phpsessid", 100)],
        "u": [(".php", 60)]},
    "nodejs": {"n": "Node.js", "c": "Language",
        "t": [("node.js", 70), ("node_modules", 70)]},
    "python": {"n": "Python", "c": "Language",
        "h": [("server", r"python", 50)]},
    # ── E-Commerce ──
    "woocommerce": {"n": "WooCommerce", "c": "E-Commerce",
        "t": [("woocommerce", 100), ("wc-", 70)],
        "u": [("/product/", 70), ("/cart/", 70), ("/checkout/", 70)],
        "k": [("woocommerce_", 70)]},
    "prestashop": {"n": "PrestaShop", "c": "E-Commerce",
        "h": [("powered-by", r"prestashop", 80)],
        "k": [("prestashop", 70)]},
    # ── Security / Auth ──
    "recaptcha": {"n": "reCAPTCHA", "c": "Security",
        "t": [("google.com/recaptcha/", 100), ("recaptcha/api.js", 100), ("g-recaptcha", 80)],
        "s": [("recaptcha", 80)]},
    "hcaptcha": {"n": "hCaptcha", "c": "Security",
        "t": [("hcaptcha.com", 100), ("js.hcaptcha.com", 100)]},
    "turnstile": {"n": "Cloudflare Turnstile", "c": "Security",
        "t": [("challenges.cloudflare.com/turnstile", 100), ("turnstile", 70)]},
    "auth0": {"n": "Auth0", "c": "Authentication",
        "t": [("auth0.com", 100), ("cdn.auth0.com", 100)]},
    "firebase": {"n": "Firebase", "c": "Backend",
        "t": [("firebaseapp.com", 100), ("firebaseio.com", 100)]},
    "supabase": {"n": "Supabase", "c": "Backend",
        "t": [("supabase.co", 100), ("supabase.io", 100)]},
    # ── API / Tools ──
    "graphql": {"n": "GraphQL", "c": "API",
        "t": [("graphql", 70)],
        "u": [("/graphql", 80), ("/graphiql", 80), ("/voyager", 80)]},
    "swagger": {"n": "Swagger", "c": "API",
        "t": [("swagger-ui", 100), ("swagger.json", 100), ("openapi.json", 100)],
        "u": [("/swagger.json", 100), ("/swagger-ui/", 100), ("/api-docs", 80), ("/openapi.json", 100)]},
    "socket_io": {"n": "Socket.IO", "c": "API",
        "t": [("socket.io", 100), ("socket.io.js", 100)],
        "u": [("/socket.io/", 100)]},
    # ── Tools ──
    "elasticsearch": {"n": "Elasticsearch", "c": "Database",
        "h": [("x-elastic-product", r".", 100)],
        "u": [("/_cat/", 80), ("/_search", 70)]},
    "kibana": {"n": "Kibana", "c": "Tool",
        "h": [("kbn-", r".", 70)],
        "t": [("kibana", 70)],
        "u": [("/app/kibana", 80), ("/api/status", 60)]},
    "jenkins": {"n": "Jenkins", "c": "Tool",
        "h": [("x-jenkins", r".", 100)],
        "t": [("jenkins", 70)],
        "u": [("/jenkins/", 70), ("/cli/", 50)]},
    "grafana": {"n": "Grafana", "c": "Tool",
        "h": [("x-grafana-", r".", 70)]},
    "prometheus": {"n": "Prometheus", "c": "Tool",
        "u": [("/metrics", 100), ("/api/v1/query", 70)]},
    "keycloak": {"n": "Keycloak", "c": "Authentication",
        "u": [("/auth/realms/", 100), ("/auth/admin/", 70)]},
    "phpmyadmin": {"n": "phpMyAdmin", "c": "Tool",
        "u": [("/phpmyadmin/", 80), ("/phpMyAdmin/", 80), ("/pma/", 70)],
        "t": [("phpmyadmin", 70), ("pma_", 70)],
        "k": [("phpmyadmin", 70)]},
    "cpanel": {"n": "cPanel", "c": "Tool",
        "u": [("/cpanel/", 70), ("/cpsess", 70)]},
    # ── Web Fonts ──
    "font_awesome": {"n": "Font Awesome", "c": "Web Font",
        "t": [("font-awesome", 100), ("fontawesome", 70), ("fontawesome.com", 100)]},
    "google_fonts": {"n": "Google Fonts", "c": "Web Font",
        "t": [("fonts.googleapis.com", 100), ("fonts.gstatic.com", 100)]},
    # ── Hosting ──
    "github_pages": {"n": "GitHub Pages", "c": "Hosting",
        "h": [("server", r"github\.com", 80)]},
    "netlify": {"n": "Netlify", "c": "Hosting",
        "h": [("server", r"netlify", 80)]},
    "vercel": {"n": "Vercel", "c": "Hosting",
        "h": [("x-vercel-id", r".", 100), ("x-vercel-cache", r".", 80)]},
    # ── Build Tools ──
    "webpack": {"n": "Webpack", "c": "Build Tool",
        "t": [("__webpack_require__", 100), ("webpackJsonp", 100)]},
    "vite": {"n": "Vite", "c": "Build Tool",
        "h": [("server", r"vite", 80)],
        "t": [("vite", 70), ("@vite", 70)]},
    # ── WAF ──
    "modsecurity": {"n": "ModSecurity", "c": "WAF",
        "h": [("server", r"mod_security", 80)],
        "t": [("mod_security", 70), ("ModSecurity", 70)]},
    "wordfence": {"n": "Wordfence", "c": "Security",
        "h": [("x-wordfence", r".", 80)],
        "k": [("wordfence_", 80)]},
}

KEY_MAP = {"n": "name", "c": "category", "h": "header", "m": "meta", "t": "html",
           "u": "url", "k": "cookie", "s": "script"}

WAF_SIGNATURES = [
    {"n": "Cloudflare", "id": "cloudflare", "h": {"server": r"cloudflare", "cf-ray": r"."}},
    {"n": "ModSecurity", "id": "modsecurity", "h": {"server": r"mod_security|modsecurity"},
     "t": [r"ModSecurity", r"mod_security"]},
    {"n": "AWS WAF", "id": "aws_waf", "h": {"x-amzn-requestid": r".", "x-amz-id-2": r"."}},
    {"n": "Sucuri WAF", "id": "sucuri", "h": {"x-sucuri-id": r"."}},
    {"n": "Barracuda WAF", "id": "barracuda", "h": {"x-bwaf-": r"."},
     "k": ["barra_counter_session"]},
    {"n": "F5 BIG-IP", "id": "f5", "h": {"x-cnection": r"."},
     "k": ["bigipserver", "f5_"]},
    {"n": "Akamai WAF", "id": "akamai", "h": {"x-akamai-transformed": r"."}},
    {"n": "Imperva WAF", "id": "imperva", "h": {"x-iinfo": r"."},
     "k": ["incap_ses_", "visid_incap_"]},
    {"n": "Wordfence", "id": "wordfence", "h": {"x-wordfence": r"."}},
    {"n": "StackPath", "id": "stackpath", "h": {"server": r"stackpath"}},
    {"n": "Comodo WAF", "id": "comodo", "h": {"server": r"comodo", "x-cwaf-": r"."}},
    {"n": "Radware WAF", "id": "radware", "k": ["radware", "alteon"]},
    {"n": "Fortinet WAF", "id": "fortinet", "k": ["fgd_", "fortigate"],
     "h": {"server": r"fortigate|fortinet|fortiwaf"}},
    {"n": "Citrix NetScaler", "id": "netscaler", "k": ["ns_af", "citrix_ns_id"],
     "h": {"x-ns-": r"."}},
    {"n": "SiteGround WAF", "id": "siteground", "h": {"x-sg-": r"."}},
]

KNOWN_FAVICON_HASHES = {
    "174568520": "WordPress", "536742289": "Drupal", "444325997": "Joomla",
    "116323821": "Magento", "1521961014": "Shopify", "1771120266": "Laravel",
    "1896338650": "phpMyAdmin", "-1633795266": "GitLab", "1283598554": "Grafana",
    "-1096052703": "Jenkins", "1925957156": "Kibana", "2117069829": "SonarQube",
    "1492707294": "cPanel", "109740280": "Confluence", "-1791349838": "JIRA",
    "810843933": "Zabbix", "1708666937": "OpenVPN", "-1929912512": "pfSense",
}


def _validate_waf():
    valid = []
    for sig in WAF_SIGNATURES:
        ok = True
        for hdr, pat in sig.get("h", {}).items():
            if _compile_pat(pat) is None:
                logger.warning("Removing WAF %s: bad header pattern %r", sig.get("n"), pat)
                ok = False
                break
        for pat in sig.get("t", []):
            if _compile_pat(pat) is None:
                logger.warning("Removing WAF %s: bad HTML pattern %r", sig.get("n"), pat)
                ok = False
                break
        if ok:
            valid.append(sig)
    return valid


def _validate_tech():
    valid = {}
    for key, sig in TECH_SIGNATURES.items():
        ok = True
        for item in sig.get("h", []):
            if len(item) >= 2 and _compile_pat(item[1]) is None:
                logger.warning("Removing %s: bad header pattern", sig.get("n", key))
                ok = False
                break
        if not ok:
            continue
        for meta_name, (pat, _) in sig.get("m", {}).items():
            if _compile_pat(pat) is None:
                logger.warning("Removing %s: bad meta pattern", sig.get("n", key))
                ok = False
                break
        if not ok:
            continue
        for item in sig.get("t", []):
            if _compile_pat(item[0]) is None:
                logger.warning("Removing %s: bad HTML pattern", sig.get("n", key))
                ok = False
                break
        if not ok:
            continue
        for item in sig.get("u", []):
            if _compile_pat(item[0]) is None:
                logger.warning("Removing %s: bad URL pattern", sig.get("n", key))
                ok = False
                break
        if not ok:
            continue
        for item in sig.get("k", []):
            if _compile_pat(item[0]) is None:
                logger.warning("Removing %s: bad cookie pattern", sig.get("n", key))
                ok = False
                break
        if not ok:
            continue
        for item in sig.get("s", []):
            if _compile_pat(item[0]) is None:
                logger.warning("Removing %s: bad script pattern", sig.get("n", key))
                ok = False
                break
        if ok:
            valid[key] = sig
    return valid


WAF_SIGNATURES = _validate_waf()
TECH_SIGNATURES = _validate_tech()
