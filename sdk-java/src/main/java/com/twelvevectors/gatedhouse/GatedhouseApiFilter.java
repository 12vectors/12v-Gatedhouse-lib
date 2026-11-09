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
 * A missing or invalid token gets a 401 JSON response carrying the RFC 6750
 * {@code WWW-Authenticate: Bearer} challenge and a stable {@code reason} code;
 * an identity-provider outage gets a 503 with {@code Retry-After}.
 * {@link ForbiddenException} / {@link UnauthorizedException} thrown by the
 * application (via {@link #requireAdmin} etc.) become 403 / 401; every other
 * application exception propagates unchanged.
 */
public final class GatedhouseApiFilter implements Filter {

    public static final String CONTEXT_ATTR = "com.twelvevectors.gatedhouse.context";
    public static final String DEFAULT_GATEDHOUSE_ATTR = "com.twelvevectors.gatedhouse.Gatedhouse";

    /** RFC 6750 challenge sent on every 401 response ({@code WWW-Authenticate: Bearer}). */
    public static final String WWW_AUTHENTICATE_CHALLENGE = "Bearer";

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

        FilterSupport.applySecurityHeaders(resp);

        String token = FilterSupport.bearerToken(req.getHeader("Authorization"));
        if (token == null) {
            FilterSupport.sendUnauthorized(resp, "missing_token", "Missing or invalid Bearer token");
            return;
        }

        // Only verification is guarded here. Any other exception from
        // verifyToken (e.g. no token verifier configured) is a server fault
        // and propagates to the container as a 500, never a 401.
        AuthenticatedSubject subject;
        try {
            subject = gatedhouse.verifyToken(token);
        } catch (TokenVerificationException e) {
            if (FilterSupport.isOutage(e)) {
                FilterSupport.sendUnavailable(resp);
            } else {
                FilterSupport.sendUnauthorized(
                    resp, FilterSupport.reasonCode(e.reason()), "Token verification failed");
            }
            return;
        }
        req.setAttribute(CONTEXT_ATTR, GatedContext.fromSubject(subject));

        // The application runs outside the verification guard: its failures
        // keep their own status. Only this filter's helper exceptions
        // (requireAdmin, requireScope, ...) are translated, and only while
        // the response can still be changed.
        try {
            chain.doFilter(request, response);
        } catch (ForbiddenException e) {
            if (resp.isCommitted()) {
                throw e;
            }
            FilterSupport.sendForbidden(resp, e.getMessage());
        } catch (UnauthorizedException e) {
            if (resp.isCommitted()) {
                throw e;
            }
            FilterSupport.sendUnauthorized(resp, null, e.getMessage());
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
