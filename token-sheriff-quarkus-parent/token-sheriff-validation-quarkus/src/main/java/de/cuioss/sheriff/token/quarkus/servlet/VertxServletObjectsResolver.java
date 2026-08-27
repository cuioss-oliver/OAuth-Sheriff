/*
 * Copyright © 2025-present CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.sheriff.token.quarkus.servlet;

import de.cuioss.sheriff.token.quarkus.annotation.ServletObjectsResolver;
import de.cuioss.tools.logging.CuiLogger;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpServerRequest;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import java.util.*;

import static de.cuioss.sheriff.token.quarkus.TokenSheriffQuarkusLogMessages.ERROR;

/**
 * Vertx-based implementation for resolving HTTP request data within Quarkus JAX-RS request contexts.
 *
 * <p>This implementation uses Vertx {@link HttpServerRequest} to access HTTP context directly,
 * reading headers from the Vertx MultiMap and URI/method from the Vertx request.</p>
 *
 * <p><strong>Usage:</strong> This resolver should only be used within active Quarkus JAX-RS request contexts.
 * Outside of REST requests, CDI will throw {@link jakarta.enterprise.inject.IllegalProductException}
 * because the underlying {@code @RequestScoped} HttpServerRequest producer cannot provide a valid instance.</p>
 *
 * <p><strong>CDI Usage:</strong></p>
 * <pre>{@code
 * @Inject
 * @ServletObjectsResolver
 * HttpRequestResolver resolver;
 * }</pre>
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@ApplicationScoped
@ServletObjectsResolver
public class VertxServletObjectsResolver implements HttpRequestResolver {

    private static final CuiLogger LOGGER = new CuiLogger(VertxServletObjectsResolver.class);

    private final Instance<HttpServerRequest> vertxRequestInstance;

    @Inject
    public VertxServletObjectsResolver(Instance<HttpServerRequest> vertxRequestInstance) {
        this.vertxRequestInstance = vertxRequestInstance;
    }

    /**
     * Resolves HTTP headers directly from the Vertx {@link HttpServerRequest#headers()} MultiMap.
     *
     * <p>Header names are normalized to lowercase per RFC 9113 (HTTP/2) and RFC 7230 (HTTP/1.1)
     * using {@link Locale#ROOT} for locale-independent conversion.</p>
     *
     * @return Map of HTTP headers with lowercase header names from the current Vertx context
     * @throws IllegalStateException if no active Vertx request context is available
     */
    @Override
    public Map<String, List<String>> resolveHeaderMap() throws IllegalStateException {
        LOGGER.debug("Resolving header map directly from Vertx context");

        HttpServerRequest vertxRequest = getVertxRequest();
        MultiMap headers = vertxRequest.headers();
        Map<String, List<String>> headerMap = new HashMap<>();

        for (String name : headers.names()) {
            // Normalize header name to lowercase per RFC 9113 (HTTP/2) and RFC 7230 (HTTP/1.1)
            headerMap.put(name.toLowerCase(Locale.ROOT), headers.getAll(name));
        }

        LOGGER.debug("Resolved %s headers directly from Vertx context", headerMap.size());
        return headerMap;
    }

    @Override
    public String resolveRequestUri() {
        HttpServerRequest vertxRequest = getVertxRequest();
        return vertxRequest.absoluteURI();
    }

    @Override
    public String resolveRequestMethod() {
        HttpServerRequest vertxRequest = getVertxRequest();
        return vertxRequest.method().name();
    }

    private HttpServerRequest getVertxRequest() {
        if (vertxRequestInstance.isUnsatisfied()) {
            LOGGER.error(ERROR.VERTX_REQUEST_CONTEXT_UNAVAILABLE);
            throw new IllegalStateException("Vertx HttpServerRequest bean is not available in CDI context");
        }
        HttpServerRequest request = vertxRequestInstance.get();
        if (request == null) {
            LOGGER.error(ERROR.VERTX_REQUEST_CONTEXT_UNAVAILABLE);
            throw new IllegalStateException("Vertx HttpServerRequest is null - no active request context available");
        }
        return request;
    }
}
