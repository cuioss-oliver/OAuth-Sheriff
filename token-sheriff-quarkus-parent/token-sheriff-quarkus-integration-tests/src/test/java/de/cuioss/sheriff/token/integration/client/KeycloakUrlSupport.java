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
package de.cuioss.sheriff.token.integration.client;

import java.net.URI;

/**
 * Bridges the two Keycloak base URLs the client integration tests must reconcile.
 * <p>
 * The integration realm is imported with a fixed {@code frontendUrl} of
 * {@code https://keycloak:8443} (see {@code src/main/docker/keycloak/integration-realm.json}).
 * Keycloak therefore emits that <em>Docker-internal</em> authority in every URL it generates —
 * the {@code issuer} in the discovery document, the {@code login-actions} form-action URL on the
 * login page, and the discovery-advertised endpoints such as the
 * {@code pushed_authorization_request_endpoint}. The application container reaches that authority
 * over the {@code jwt-integration} Docker network, which is why the app's issuer configuration is
 * pinned to {@code https://keycloak:8443/realms/...}.
 * <p>
 * The {@code *IT} tests, however, run on the CI runner <em>outside</em> the Docker network. There the
 * container is only reachable through the host port mapping {@code 1443:8443}
 * (see {@code docker-compose.yml}), i.e. {@code https://localhost:1443}; the {@code keycloak} DNS name
 * and the internal port {@code 8443} do not resolve. Tests that build their own request URL against
 * {@code https://localhost:1443} connect fine, but any test that <em>follows a Keycloak-emitted URL</em>
 * would connect to {@code https://keycloak:8443} and fail with a {@code java.net.ConnectException}.
 * <p>
 * This helper rewrites such Keycloak-emitted URLs to the externally reachable base while preserving the
 * path, query, and fragment. Rewriting to {@code localhost} additionally keeps the session cookies
 * (set by Keycloak on the {@code localhost} domain during the authorization request) valid for the
 * follow-up login POST.
 */
final class KeycloakUrlSupport {

    /**
     * Externally reachable Keycloak base — the host port mapping {@code 1443:8443} from
     * {@code docker-compose.yml}. This is the only authority the CI runner can connect to.
     */
    static final String EXTERNAL_BASE = "https://localhost:1443";

    /**
     * Docker-internal Keycloak base that Keycloak emits in generated URLs, taken from the integration
     * realm's {@code frontendUrl}. This is what the discovery {@code issuer} resolves to.
     */
    static final String INTERNAL_BASE = "https://keycloak:8443";

    /** Issuer the integration realm advertises (its {@code frontendUrl} plus the realm path). */
    static final String INTERNAL_ISSUER = INTERNAL_BASE + "/realms/integration";

    private KeycloakUrlSupport() {
        // utility class
    }

    /**
     * Rewrites a Keycloak-emitted URL to the externally reachable {@link #EXTERNAL_BASE}, preserving the
     * path, raw query, and raw fragment. The original authority (typically {@code keycloak:8443}) is
     * discarded, so the result is reachable from the CI runner regardless of which internal host
     * Keycloak embedded. A URL that is already relative (path only) is simply anchored to the external
     * base.
     *
     * @param keycloakEmittedUrl an absolute or path-only URL produced by Keycloak
     * @return the same resource anchored at {@link #EXTERNAL_BASE}
     */
    static String toExternal(String keycloakEmittedUrl) {
        URI uri = URI.create(keycloakEmittedUrl);
        StringBuilder rewritten = new StringBuilder(EXTERNAL_BASE);
        if (uri.getRawPath() != null) {
            rewritten.append(uri.getRawPath());
        }
        if (uri.getRawQuery() != null) {
            rewritten.append('?').append(uri.getRawQuery());
        }
        if (uri.getRawFragment() != null) {
            rewritten.append('#').append(uri.getRawFragment());
        }
        return rewritten.toString();
    }
}
