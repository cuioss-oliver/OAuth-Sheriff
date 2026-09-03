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
package de.cuioss.sheriff.token.client.quarkus.config;

/**
 * MicroProfile Config property keys for the Token-Sheriff OIDC/OAuth confidential client
 * ({@code CLIENT-21}). All keys share the {@value #PREFIX} prefix.
 * <p>
 * Configuration is read directly through MicroProfile {@code Config} (see {@link ClientConfigMapper})
 * rather than a {@code @ConfigMapping} interface — matching the {@code token-sheriff-validation-quarkus}
 * extension's deliberate choice to keep the configuration surface native-image-safe and to avoid
 * eager {@code @ConfigMapping} validation failing when the extension is on the classpath but the
 * application does not use the client. Every key is optional; a client is considered configured only
 * when both {@link #ISSUER} and {@link #CLIENT_ID} are present.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public final class ClientRuntimeConfig {

    private ClientRuntimeConfig() {
        // constants holder — never instantiated
    }

    /** The common prefix for all client properties. */
    public static final String PREFIX = "sheriff.client";

    /**
     * The authorization server's issuer identifier URL. Property: {@code sheriff.client.issuer}.
     * Required to enable the client.
     */
    public static final String ISSUER = PREFIX + ".issuer";

    /**
     * The OAuth 2.0 {@code client_id}. Property: {@code sheriff.client.client-id}. Required to enable
     * the client.
     */
    public static final String CLIENT_ID = PREFIX + ".client-id";

    /**
     * The client secret for the shared-secret authentication methods. Property:
     * {@code sheriff.client.client-secret}. Absent for the key-based methods. Never logged.
     */
    public static final String CLIENT_SECRET = PREFIX + ".client-secret";

    /**
     * The client authentication method, as the RFC 8414 {@code token_endpoint_auth_methods_supported}
     * value (for example {@code client_secret_basic}). Property: {@code sheriff.client.auth-method}.
     * Defaults to {@code client_secret_basic}.
     */
    public static final String AUTH_METHOD = PREFIX + ".auth-method";

    /**
     * The OAuth 2.0 scopes to request, as a comma-separated list. Property:
     * {@code sheriff.client.scopes}. May be empty.
     */
    public static final String SCOPES = PREFIX + ".scopes";

    /**
     * The single exact {@code redirect_uri} for the interactive {@code authorization_code} flow.
     * Property: {@code sheriff.client.redirect-uri}. Absent for non-interactive clients.
     */
    public static final String REDIRECT_URI = PREFIX + ".redirect-uri";

    /**
     * Whether plaintext {@code http://} endpoints are permitted for discovery and back-channel calls.
     * Property: {@code sheriff.client.allow-insecure-http}. Defaults to {@code false}.
     */
    public static final String ALLOW_INSECURE_HTTP = PREFIX + ".allow-insecure-http";

    /**
     * Whether TLS hostname verification is enforced for this client's outbound calls. Property:
     * {@code sheriff.client.verify-hostname}. Defaults to {@code true}.
     * <p>
     * Client-wide — applies to every outbound discovery and back-channel call this client makes.
     * Setting it to {@code false} relaxes <strong>hostname matching only</strong>; certificate chain
     * trust, expiry, and algorithm constraints remain fully enforced. Never set it to {@code false}
     * in production. See {@link de.cuioss.sheriff.token.client.config.ClientConfiguration#isVerifyHostname()}
     * for the {@code SSLContext} mutual-exclusion constraint.
     *
     * @see de.cuioss.sheriff.token.client.config.ClientConfiguration#isVerifyHostname()
     * @see <a href=
     *      "https://github.com/cuioss/TokenSheriff/blob/main/doc/adr/0008-Adopt_the_upstream_cui-http_verifyHostname_knob_rather_than_a_local_trust_manager.adoc">ADR-0008
     *      - Adopt the upstream cui-http verifyHostname knob rather than a local trust manager</a>
     */
    public static final String VERIFY_HOSTNAME = PREFIX + ".verify-hostname";

    /**
     * The maximum size, in bytes, of the authorization server's discovery document. Property:
     * {@code sheriff.client.discovery-document-max-size}. Defaults to
     * {@link de.cuioss.sheriff.token.client.config.ClientConfiguration#DEFAULT_DISCOVERY_DOCUMENT_MAX_SIZE}.
     * Raise it only for an authorization server whose {@code .well-known/openid-configuration} exceeds
     * that ceiling.
     */
    public static final String DISCOVERY_DOCUMENT_MAX_SIZE = PREFIX + ".discovery-document-max-size";

    /**
     * Whether a refresh whose granted scope is <em>broader</em> than the requested scope is refused.
     * Property: {@code sheriff.client.strict-scope-reconciliation}. Defaults to {@code false}.
     * <p>
     * At the default a broadened grant is accepted, {@code WARN}-logged and surfaced on
     * {@code RotationResult}; enabling this refuses it with a {@code ClientProtocolException}. Enable
     * it only against an authorization server known not to canonicalise or expand scope sets — see
     * {@link de.cuioss.sheriff.token.client.config.ClientConfiguration} for the outage trade-off this
     * opt-in carries.
     */
    public static final String STRICT_SCOPE_RECONCILIATION = PREFIX + ".strict-scope-reconciliation";
}
