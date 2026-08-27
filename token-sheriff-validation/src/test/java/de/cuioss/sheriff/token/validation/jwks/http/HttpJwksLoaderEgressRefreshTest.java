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
package de.cuioss.sheriff.token.validation.jwks.http;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.transport.EgressPolicy;
import de.cuioss.sheriff.token.commons.transport.HttpJwksLoaderConfig;
import de.cuioss.sheriff.token.validation.test.InMemoryJWKSFactory;
import de.cuioss.sheriff.token.validation.test.dispatcher.JwksResolveDispatcher;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import lombok.Getter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that {@link HttpJwksLoader} re-validates the SSRF egress guard on <em>every</em> background
 * refresh, not only once at initial adapter construction (C1 follow-up, finding 9edd1b).
 * <p>
 * The reused, cached {@link de.cuioss.http.client.adapter.HttpAdapter} means a DNS answer that rebinds
 * the JWKS host into an internal/metadata range after the first fetch would otherwise be trusted. These
 * tests drive the re-check deterministically with an injected {@link EgressPolicy.HostResolver} whose
 * answer flips from a public to a blocked address between the initial load and the refresh, so no real
 * DNS or timing is involved.
 */
@EnableTestLogger
@EnableMockWebServer
@DisplayName("HttpJwksLoader per-refresh SSRF egress re-validation")
class HttpJwksLoaderEgressRefreshTest {

    private static final String TEST_KID = InMemoryJWKSFactory.DEFAULT_KEY_ID;
    private static final String PUBLIC_IP = "93.184.216.34";
    private static final String METADATA_IP = "169.254.169.254";

    @Getter
    private final JwksResolveDispatcher moduleDispatcher = new JwksResolveDispatcher();

    private SecurityEventCounter securityEventCounter;

    @BeforeEach
    void setUp() {
        moduleDispatcher.setCallCounter(0);
        securityEventCounter = new SecurityEventCounter();
    }

    /**
     * A rebinding resolver: it answers {@link #PUBLIC_IP} until {@code rebound} is flipped, then
     * answers {@link #METADATA_IP}. The actual HTTP fetch still targets the real MockWebServer
     * endpoint — this resolver only feeds the egress gate, so flipping it models a DNS rebind of the
     * fetch host without moving the server.
     */
    private static EgressPolicy reboundPolicy(AtomicBoolean rebound) {
        EgressPolicy.HostResolver resolver = host -> {
            String ip = rebound.get() ? METADATA_IP : PUBLIC_IP;
            return new InetAddress[]{InetAddress.getByName(ip)};
        };
        return EgressPolicy.builder().resolver(resolver).build();
    }

    @Test
    @DisplayName("Should block the refresh fetch when the host rebinds into a metadata address after init")
    void shouldBlockRefreshWhenHostRebinds(URIBuilder uriBuilder) {
        moduleDispatcher.returnDefault();
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(0)
                .build();

        AtomicBoolean rebound = new AtomicBoolean(false);
        HttpJwksLoader loader = new HttpJwksLoader(config, reboundPolicy(rebound));
        loader.initJWKSLoader(securityEventCounter).join();

        assertTrue(loader.getKeyInfo(TEST_KID).isPresent(), "Initial load should succeed while the host is public");
        assertEquals(1, moduleDispatcher.getCallCounter(), "Initial load fetches exactly once");

        rebound.set(true);
        loader.performBackgroundRefresh();

        assertEquals(1, moduleDispatcher.getCallCounter(),
                "A rebound host must be rejected by the per-refresh egress re-check before any fetch");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "SSRF egress blocked");

        loader.close();
    }

    @Test
    @DisplayName("Should fetch on refresh when the host still resolves to a permitted address")
    void shouldFetchRefreshWhenHostStillPermitted(URIBuilder uriBuilder) {
        moduleDispatcher.returnDefault();
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder().allowInsecureHttp(true)
                .jwksUrl(jwksEndpoint)
                .issuerIdentifier("test-issuer")
                .refreshIntervalSeconds(0)
                .build();

        AtomicBoolean rebound = new AtomicBoolean(false);
        HttpJwksLoader loader = new HttpJwksLoader(config, reboundPolicy(rebound));
        loader.initJWKSLoader(securityEventCounter).join();

        assertTrue(loader.getKeyInfo(TEST_KID).isPresent(), "Initial load should succeed");
        assertEquals(1, moduleDispatcher.getCallCounter(), "Initial load fetches exactly once");

        loader.performBackgroundRefresh();

        assertEquals(2, moduleDispatcher.getCallCounter(),
                "A still-permitted host must let the refresh proceed to a second fetch");

        loader.close();
    }
}
