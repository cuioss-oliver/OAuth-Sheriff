/*
 * Copyright © 2022 CUI-OpenSource-Software (info@cuioss.de)
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
package de.cuioss.sheriff.token.client.internal;

import de.cuioss.http.client.handler.HttpHandler;
import de.cuioss.http.security.config.SecurityConfiguration;
import de.cuioss.http.security.core.HttpSecurityValidator;
import de.cuioss.http.security.exceptions.UrlSecurityException;
import de.cuioss.http.security.monitoring.SecurityEventCounter;
import de.cuioss.http.security.pipeline.PipelineFactory;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.tools.logging.CuiLogger;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Shared back-channel transport control for the OIDC/OAuth endpoint clients.
 * <p>
 * The five endpoint clients (token, PAR, userinfo, revocation, discovery) each issue their own
 * outbound {@code cui-http} calls to URLs the authorization server <em>advertised</em> in its
 * discovery document. Discovery data is only transport-authenticated — it is not fully trusted — so
 * an AS (or a mix-up attacker who controls the discovery response) could point a credential-bearing
 * back-channel {@code POST} at an unintended target. This helper centralises the egress control the
 * clients apply before each fetch, so the same defence is enforced uniformly rather than copied,
 * inconsistently, five times:
 * <ul>
 *   <li><strong>Egress / SSRF control (H9):</strong> the advertised endpoint URL is run through the
 *       existing {@code de.cuioss.http.security} URL-path validation pipeline before use, so a
 *       traversal / injection / encoding-evasion / malformed advertised path is rejected rather than
 *       fetched. The precise scope of this control — path-structure and scheme, not host-address
 *       reachability — is documented in the client transport specification.</li>
 *   <li><strong>Scheme / TLS control:</strong> a non-TLS ({@code http://}) endpoint is refused unless
 *       {@link ClientConfiguration#allowInsecureHttp} is set, via the {@link HttpHandler} builder's
 *       own TLS enforcement.</li>
 *   <li><strong>Per-client TLS trust:</strong> the {@link ClientConfiguration#getSslContext() configured
 *       SSLContext}, when present, is applied to every endpoint handler this helper produces — so all
 *       five endpoint clients sharing one {@code ClientConfiguration} trust the same authorization
 *       server, without a process-global {@code javax.net.ssl.trustStore} override. When absent, the
 *       cui-http / JVM default truststore is used.</li>
 *   <li><strong>Consistent transport typing (M9):</strong> a malformed or non-TLS endpoint surfaces as
 *       the declared {@link TransportException}, never a raw {@link IllegalArgumentException} leaking
 *       from {@code HttpHandler.build()}.</li>
 *   <li><strong>Client reuse (L16):</strong> a single {@link HttpClient} is built lazily and reused for
 *       every request issued through this helper instance, instead of a fresh client per request.</li>
 *   <li><strong>Configurable timeouts (L15):</strong> connect / read timeouts are read from
 *       {@link ClientConfiguration}, not hardcoded per client.</li>
 *   <li><strong>Bounded body reads (M7):</strong> {@link #bodyHandler()} enforces the payload ceiling
 *       during the read via {@link BoundedContentBodyHandler}. The ceiling's provenance travels with
 *       the failure: each construction site supplies a {@code boundOrigin} descriptor naming the knob
 *       that set the bound and whether it is settable, and the over-limit message reports it.</li>
 * </ul>
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public final class BackChannelHttp {

    private static final CuiLogger LOGGER = new CuiLogger(BackChannelHttp.class);

    /**
     * Bound origin for the back-channel clients (token, PAR, userinfo, revocation) that build their
     * own {@code ParserConfig} internally: their payload ceiling is deliberately fixed on that path
     * and is <em>not</em> reachable from {@link ClientConfiguration} nor from the
     * {@code sheriff.token.parser.max-payload-size} property, which feeds a different object graph.
     * The message must say so rather than let a reader chase a setting that has no effect here.
     * <p>
     * This is a shared descriptor, not a default: {@link #BackChannelHttp(ClientConfiguration, int, String)}
     * still requires the argument, so a new endpoint client cannot silently omit its origin.
     */
    public static final String FIXED_PARSER_CONFIG_ORIGIN =
            "ParserConfig.maxPayloadSize; fixed on this path, not settable via ClientConfiguration";

    private final ClientConfiguration configuration;
    private final HttpSecurityValidator egressValidator;
    private final int maxContentSize;
    private final String boundOrigin;
    private final ConcurrentMap<String, HttpClient> sharedClients = new ConcurrentHashMap<>();

    /**
     * @param configuration  the client configuration carrying the TLS policy and timeout knobs; must
     *                       not be {@code null}
     * @param maxContentSize the maximum response body size, in bytes, enforced during read
     * @param boundOrigin    the human-readable provenance of {@code maxContentSize} — the knob that set
     *                       it, and whether it is settable; reported in the over-limit failure message
     */
    public BackChannelHttp(ClientConfiguration configuration, int maxContentSize, String boundOrigin) {
        this.configuration = Objects.requireNonNull(configuration, "configuration must not be null");
        this.maxContentSize = maxContentSize;
        this.boundOrigin = Objects.requireNonNull(boundOrigin, "boundOrigin must not be null");
        this.egressValidator = PipelineFactory.createUrlPathPipeline(
                SecurityConfiguration.defaults(), new SecurityEventCounter());
    }

    /**
     * Applies the egress / SSRF and scheme controls to an advertised endpoint URL and returns a
     * per-endpoint {@link HttpHandler} configured with the client's timeout policy.
     *
     * @param endpointUrl    the absolute, discovery-advertised endpoint URL to fetch
     * @param failureContext a short, caller-safe prefix identifying the endpoint for exception messages
     *                       (for example {@code "token endpoint request failed"})
     * @return a configured {@link HttpHandler} for {@code endpointUrl}
     * @throws TransportException if the URL is malformed, fails the egress security validation, or is a
     *                            non-TLS endpoint while cleartext is not permitted
     */
    public HttpHandler validatedHandler(String endpointUrl, String failureContext) {
        Objects.requireNonNull(endpointUrl, "endpointUrl must not be null");
        applyEgressControl(endpointUrl, failureContext);
        try {
            HttpHandler.HttpHandlerBuilder builder = HttpHandler.builder()
                    .url(endpointUrl)
                    .connectionTimeoutSeconds(configuration.getConnectTimeoutSeconds())
                    .readTimeoutSeconds(configuration.getReadTimeoutSeconds())
                    .allowInsecureHttp(configuration.isAllowInsecureHttp());
            SSLContext sslContext = configuration.getSslContext();
            if (sslContext != null) {
                builder.sslContext(sslContext);
            }
            return builder.build();
        } catch (IllegalArgumentException e) {
            // M9: a non-TLS / malformed endpoint must surface as the declared transport failure, not a
            // raw IllegalArgumentException leaking from the handler builder.
            throw new TransportException(failureContext + ": " + e.getMessage(), e);
        }
    }

    private void applyEgressControl(String endpointUrl, String failureContext) {
        URI uri;
        try {
            uri = URI.create(endpointUrl);
        } catch (IllegalArgumentException e) {
            throw new TransportException(failureContext + ": malformed endpoint URL", e);
        }
        String path = uri.getRawPath();
        if (path == null || path.isEmpty()) {
            return;
        }
        try {
            egressValidator.validate(path);
        } catch (UrlSecurityException e) {
            LOGGER.debug(e, "Egress validation rejected advertised endpoint path: %s", e.getFailureType());
            throw new TransportException(failureContext
                    + ": endpoint URL failed egress security validation (" + e.getFailureType() + ")", e);
        }
    }

    /**
     * Returns the shared {@link HttpClient} for this helper instance, building it once (lazily,
     * thread-safely) per endpoint scheme and reusing it for every subsequent request to that scheme.
     * <p>
     * The client is keyed by scheme rather than being a single instance because
     * {@link HttpClient} bakes its TLS material in at construction: cui-http's {@code HttpHandler}
     * installs the {@link SSLContext} and the TLS 1.2/1.3 {@code SSLParameters} pinning only on its
     * HTTPS path. A single cached client seeded by whichever handler happened to be built first
     * would therefore let a cleartext endpoint — reachable only when
     * {@link ClientConfiguration#allowInsecureHttp} is set — seed a client carrying no trust
     * material, which a later {@code https://} endpoint would then silently reuse. That would drop
     * the configured per-client trust anchor and widen validation back to the JVM default CA set,
     * breaking the CLIENT-23 guarantee that the configured {@link SSLContext} applies to
     * <em>every</em> call. Keying by scheme keeps connection pooling while making that
     * cross-scheme bleed structurally impossible.
     *
     * @param handler an already-validated handler whose SSL context and connect timeout seed the client
     * @return the shared, reused {@link HttpClient} for this handler's scheme
     */
    public HttpClient sharedClient(HttpHandler handler) {
        Objects.requireNonNull(handler, "handler must not be null");
        String scheme = handler.getUri().getScheme();
        return sharedClients.computeIfAbsent(
                scheme == null ? "" : scheme.toLowerCase(Locale.ROOT),
                unusedKey -> handler.createHttpClient());
    }

    /**
     * @return a bounded body handler that enforces the configured payload ceiling during the read (M7)
     */
    public HttpResponse.BodyHandler<String> bodyHandler() {
        return BoundedContentBodyHandler.of(maxContentSize, boundOrigin);
    }
}
