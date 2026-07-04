package com.twelvevectors.gatedhouse;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;

/**
 * Web Security Filter that guards standard HTML pages/resources using session-based token verification.
 * On authentication failure, redirects the user's browser to a configurable login path (supports absolute and relative paths).
 *
 * <p><b>Deep linking (optional).</b> When {@code deepLinkEnabled} is true (the default), a request that
 * is bounced to login has its original path captured in a short-lived {@code gh_return} cookie so the
 * callback can send the user back where they were (see {@link LoginFlow#consumeReturnTo}). When it is
 * false, no {@code gh_return} cookie is ever set and login lands on a fixed home URL, preserving the
 * classic behaviour. Only same-origin relative navigations (GET) are captured; the callback re-validates.
 */
public final class GatedhouseWebFilter implements Filter {

    public static final String CONTEXT_ATTR = "com.twelvevectors.gatedhouse.context";
    public static final String DEFAULT_GATEDHOUSE_ATTR = "com.twelvevectors.gatedhouse.Gatedhouse";
    public static final String DEFAULT_LOGIN_PATH = "/auth/login";
    public static final String DEFAULT_SESSION_TOKEN_ATTR = "access_token";
    /** Cookie holding the original relative path to return to after login; read by {@link LoginFlow#consumeReturnTo}. */
    public static final String RETURN_COOKIE = "gh_return";
    private static final int RETURN_COOKIE_TTL_SECONDS = 600; // 10 min — same order as the login flow

    private Gatedhouse gatedhouse;
    private String gatedhouseAttr = DEFAULT_GATEDHOUSE_ATTR;
    private String loginPath = DEFAULT_LOGIN_PATH;
    private String sessionTokenAttr = DEFAULT_SESSION_TOKEN_ATTR;
    private boolean deepLinkEnabled = true;

    /**
     * No-arg constructor for container-managed instantiation.
     */
    public GatedhouseWebFilter() {}

    /**
     * Programmatic constructor with default login configuration.
     */
    public GatedhouseWebFilter(Gatedhouse gatedhouse) {
        this(gatedhouse, DEFAULT_LOGIN_PATH, DEFAULT_SESSION_TOKEN_ATTR);
    }

    /**
     * Detailed programmatic constructor (deep linking enabled).
     */
    public GatedhouseWebFilter(Gatedhouse gatedhouse, String loginPath, String sessionTokenAttr) {
        this(gatedhouse, loginPath, sessionTokenAttr, true);
    }

    /**
     * Full programmatic constructor.
     *
     * @param deepLinkEnabled when false, no {@code gh_return} cookie is set and login lands on a fixed
     *                        home URL (classic behaviour); when true, the original path is captured so
     *                        the callback can deep-link back to it.
     */
    public GatedhouseWebFilter(Gatedhouse gatedhouse, String loginPath, String sessionTokenAttr,
                               boolean deepLinkEnabled) {
        this.gatedhouse = gatedhouse;
        this.loginPath = loginPath;
        this.sessionTokenAttr = sessionTokenAttr;
        this.deepLinkEnabled = deepLinkEnabled;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        if (gatedhouse == null) {
            String attrParam = filterConfig.getInitParameter("gatedhouseAttr");
            if (attrParam != null && !attrParam.trim().isEmpty()) {
                gatedhouseAttr = attrParam.trim();
            }
            gatedhouse = (Gatedhouse) filterConfig.getServletContext().getAttribute(gatedhouseAttr);
            if (gatedhouse == null) {
                throw new ServletException("Gatedhouse instance not found in ServletContext attribute '" + gatedhouseAttr + "'");
            }
        }

        String pathParam = filterConfig.getInitParameter("loginPath");
        if (pathParam != null && !pathParam.trim().isEmpty()) {
            loginPath = pathParam.trim();
        }

        String tokenParam = filterConfig.getInitParameter("sessionTokenAttr");
        if (tokenParam != null && !tokenParam.trim().isEmpty()) {
            sessionTokenAttr = tokenParam.trim();
        }

        String deepLinkParam = filterConfig.getInitParameter("deepLinkEnabled");
        if (deepLinkParam != null && !deepLinkParam.trim().isEmpty()) {
            deepLinkEnabled = Boolean.parseBoolean(deepLinkParam.trim());
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        var req = (HttpServletRequest) request;
        var resp = (HttpServletResponse) response;

        // Apply robust security headers
        resp.setHeader("X-Content-Type-Options", "nosniff");
        resp.setHeader("X-Frame-Options", "DENY");
        resp.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

        String token = null;
        HttpSession session = req.getSession(false);
        if (session != null) {
            token = (String) session.getAttribute(sessionTokenAttr);
        }

        if (token == null || token.trim().isEmpty()) {
            performLoginRedirect(req, resp);
            return;
        }

        try {
            AuthenticatedSubject subject = gatedhouse.verifyToken(token);
            GatedContext ctx = GatedContext.fromSubject(subject);
            req.setAttribute(CONTEXT_ATTR, ctx);
            chain.doFilter(request, response);
        } catch (TokenVerificationException e) {
            // Token is invalid or expired — remove it from the session and redirect
            if (session != null) {
                session.removeAttribute(sessionTokenAttr);
            }
            performLoginRedirect(req, resp);
        } catch (Exception e) {
            performLoginRedirect(req, resp);
        }
    }

    private void performLoginRedirect(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (deepLinkEnabled) {
            captureReturnTo(req, resp);
        }
        String redirectTarget;
        if (loginPath.startsWith("http://") || loginPath.startsWith("https://") || loginPath.startsWith("//")) {
            redirectTarget = loginPath;
        } else {
            redirectTarget = req.getContextPath() + loginPath;
        }
        resp.sendRedirect(redirectTarget);
    }

    /**
     * Stash the original relative path in the {@code gh_return} cookie so the callback can deep-link
     * back to it. Only plain GET navigations are captured — a bounced POST/PUT/… can't be safely
     * replayed, and the cookie value is always a same-origin relative path, never an absolute URL.
     */
    private void captureReturnTo(HttpServletRequest req, HttpServletResponse resp) {
        if (!"GET".equalsIgnoreCase(req.getMethod())) {
            return;
        }
        String uri = req.getRequestURI();
        if (uri == null || uri.isEmpty()) {
            return;
        }
        String returnTo = uri;
        String query = req.getQueryString();
        if (query != null && !query.isEmpty()) {
            returnTo = uri + "?" + query;
        }
        Cookie c = new Cookie(RETURN_COOKIE, returnTo);
        c.setHttpOnly(true);
        c.setSecure(true);
        c.setPath("/");
        c.setMaxAge(RETURN_COOKIE_TTL_SECONDS);
        c.setAttribute("SameSite", "Lax"); // rides the top-level callback navigation
        resp.addCookie(c);
    }

    @Override
    public void destroy() {}
}
