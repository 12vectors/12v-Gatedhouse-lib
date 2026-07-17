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

import java.io.IOException;

/**
 * API Security Filter that enforces standard Authorization Bearer token validation.
 * On failure, returns a clean 401 JSON response.
 */
public final class GatedhouseApiFilter implements Filter {

    public static final String CONTEXT_ATTR = "com.twelvevectors.gatedhouse.context";
    public static final String DEFAULT_GATEDHOUSE_ATTR = "com.twelvevectors.gatedhouse.Gatedhouse";

    private Gatedhouse gatedhouse;
    private String gatedhouseAttr = DEFAULT_GATEDHOUSE_ATTR;

    /**
     * No-arg constructor for container-managed instantiation.
     * Looks up the Gatedhouse instance from the ServletContext.
     */
    public GatedhouseApiFilter() {}

    /**
     * Programmatic constructor.
     */
    public GatedhouseApiFilter(Gatedhouse gatedhouse) {
        this.gatedhouse = gatedhouse;
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

        String auth = req.getHeader("Authorization");
        if (auth == null || !auth.startsWith("Bearer ")) {
            sendJsonError(resp, 401, "unauthorized", "Missing or invalid Bearer token");
            return;
        }

        String token = auth.substring(7).trim();
        try {
            AuthenticatedSubject subject = gatedhouse.verifyToken(token);
            GatedContext ctx = GatedContext.fromSubject(subject);
            req.setAttribute(CONTEXT_ATTR, ctx);
            chain.doFilter(request, response);
        } catch (TokenVerificationException e) {
            sendJsonError(resp, 401, "unauthorized", "Token verification failed: " + e.getMessage());
        } catch (Exception e) {
            sendJsonError(resp, 401, "unauthorized", "Authentication failed");
        }
    }

    @Override
    public void destroy() {}

    /**
     * Extracts the verified GatedContext from the request.
     */
    public static GatedContext getContext(HttpServletRequest req) {
        GatedContext ctx = (GatedContext) req.getAttribute(CONTEXT_ATTR);
        if (ctx == null) {
            throw new UnauthorizedException("Authentication required");
        }
        return ctx;
    }

    /**
     * Asserts that the authenticated context has admin privileges.
     */
    public static GatedContext requireAdmin(HttpServletRequest req) {
        GatedContext ctx = getContext(req);
        if (!ctx.isAdmin()) {
            throw new ForbiddenException("Admin access required");
        }
        return ctx;
    }

    /**
     * Asserts that the authenticated identity is a human user.
     */
    public static GatedContext requireHuman(HttpServletRequest req) {
        GatedContext ctx = getContext(req);
        if (!ctx.isHuman()) {
            throw new ForbiddenException("Human identity required");
        }
        return ctx;
    }

    /**
     * Asserts that the authenticated context carries a specific scope.
     */
    public static GatedContext requireScope(HttpServletRequest req, String scope) {
        GatedContext ctx = getContext(req);
        if (!ctx.hasScope(scope)) {
            throw new ForbiddenException("Scope '" + scope + "' required");
        }
        return ctx;
    }

    private static void sendJsonError(HttpServletResponse resp, int status, String error, String detail)
            throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        resp.getWriter().write("{\"error\":\"" + error + "\",\"detail\":\"" + detail + "\"}");
    }

    public static class ForbiddenException extends RuntimeException {
        public ForbiddenException(String message) {
            super(message);
        }
    }

    public static class UnauthorizedException extends RuntimeException {
        public UnauthorizedException(String message) {
            super(message);
        }
    }
}
