// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

package com.twelvevectors.gatedhouse;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;

/**
 * Web Security Filter that guards standard HTML pages/resources using session-based token verification.
 * On authentication failure, redirects the user's browser to a configurable login path (supports absolute and relative paths).
 */
public final class GatedhouseWebFilter implements Filter {

    public static final String CONTEXT_ATTR = "com.twelvevectors.gatedhouse.context";
    public static final String DEFAULT_GATEDHOUSE_ATTR = "com.twelvevectors.gatedhouse.Gatedhouse";
    public static final String DEFAULT_LOGIN_PATH = "/auth/login";
    public static final String DEFAULT_SESSION_TOKEN_ATTR = "access_token";

    private Gatedhouse gatedhouse;
    private String gatedhouseAttr = DEFAULT_GATEDHOUSE_ATTR;
    private String loginPath = DEFAULT_LOGIN_PATH;
    private String sessionTokenAttr = DEFAULT_SESSION_TOKEN_ATTR;

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
     * Detailed programmatic constructor.
     */
    public GatedhouseWebFilter(Gatedhouse gatedhouse, String loginPath, String sessionTokenAttr) {
        this.gatedhouse = gatedhouse;
        this.loginPath = loginPath;
        this.sessionTokenAttr = sessionTokenAttr;
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
        String redirectTarget;
        if (loginPath.startsWith("http://") || loginPath.startsWith("https://") || loginPath.startsWith("//")) {
            redirectTarget = loginPath;
        } else {
            redirectTarget = req.getContextPath() + loginPath;
        }
        resp.sendRedirect(redirectTarget);
    }

    @Override
    public void destroy() {}
}
