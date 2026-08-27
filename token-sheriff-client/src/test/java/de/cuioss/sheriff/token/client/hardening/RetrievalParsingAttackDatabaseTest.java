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
package de.cuioss.sheriff.token.client.hardening;

import de.cuioss.http.security.database.ApacheCVEAttackDatabase;
import de.cuioss.http.security.database.AttackTestCase;
import de.cuioss.http.security.database.ModSecurityCRSAttackDatabase;
import de.cuioss.http.security.database.OWASPTop10AttackDatabase;
import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.token.UserInfoClient;
import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import de.cuioss.test.mockwebserver.dispatcher.HttpMethodMapper;
import de.cuioss.test.mockwebserver.dispatcher.ModuleDispatcherElement;
import lombok.Getter;
import mockwebserver3.MockResponse;
import mockwebserver3.RecordedRequest;
import okhttp3.Headers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Hardening sweep — drives the full {@code http.security} attack corpora through the userinfo
 * <em>retrieval</em> parsing path and asserts it fails closed ({@code CLIENT-20}, {@code CLIENT-22}) —
 * deliverable 10.
 * <p>
 * Every adversarial userinfo response — injection, traversal, encoding-evasion, oversized — is
 * rejected by {@link UserInfoClient}: it never yields a trusted {@code UserInfoResponse}, but raises a
 * {@link TransportException}. Identity is never taken from an unvalidated response; the retrieval path
 * treats the body as untrusted until proven well-formed.
 */
@EnableTestLogger
@EnableGeneratorController
@EnableMockWebServer
@DisplayName("Retrieval-parsing fail-closed against http.security attack corpora")
class RetrievalParsingAttackDatabaseTest {

    @Getter
    private final AttackUserInfoDispatcher moduleDispatcher = new AttackUserInfoDispatcher();

    @ParameterizedTest
    @ArgumentsSource(OWASPTop10AttackDatabase.ArgumentsProvider.class)
    @DisplayName("Should reject an OWASP Top 10 attack payload served as a userinfo response body")
    void rejectsOwaspAttackBodies(AttackTestCase testCase, URIBuilder uriBuilder) {
        assertRetrievalFailsClosed(testCase.attackString(), uriBuilder);
    }

    @ParameterizedTest
    @ArgumentsSource(ApacheCVEAttackDatabase.ArgumentsProvider.class)
    @DisplayName("Should reject an Apache CVE attack payload served as a userinfo response body")
    void rejectsApacheCveAttackBodies(AttackTestCase testCase, URIBuilder uriBuilder) {
        assertRetrievalFailsClosed(testCase.attackString(), uriBuilder);
    }

    @ParameterizedTest
    @ArgumentsSource(ModSecurityCRSAttackDatabase.ArgumentsProvider.class)
    @DisplayName("Should reject a ModSecurity CRS attack payload served as a userinfo response body")
    void rejectsModSecurityAttackBodies(AttackTestCase testCase, URIBuilder uriBuilder) {
        assertRetrievalFailsClosed(testCase.attackString(), uriBuilder);
    }

    @Test
    @DisplayName("Should declare the back-channel bound fixed when rejecting an over-limit userinfo body")
    void shouldDeclareBackChannelBoundFixed(URIBuilder uriBuilder) {
        // The back-channel clients build their own ParserConfig, so their payload ceiling is NOT
        // reachable from ClientConfiguration nor from sheriff.token.parser.max-payload-size. The
        // failure must say so rather than send a reader chasing a property that has no effect here.
        moduleDispatcher.serve("{\"sub\": \"" + "x".repeat(9 * 1024) + "\"}");
        var client = new UserInfoClient(config());
        String userInfoEndpoint = uriBuilder.addPathSegment("userinfo").buildAsString();
        String accessToken = Generators.letterStrings(20, 40).next();

        var failure = assertThrows(TransportException.class,
                () -> client.fetchUserInfo(userInfoEndpoint, accessToken),
                "an over-limit userinfo response body must fail closed");

        assertAll("bound origin is named and declared fixed",
                () -> assertTrue(failure.getMessage().contains("ParserConfig.maxPayloadSize"),
                        "failure must name the originating knob, but was: " + failure.getMessage()),
                () -> assertTrue(
                        failure.getMessage().contains("fixed on this path, not settable via ClientConfiguration"),
                        "failure must declare the bound fixed on this path, but was: " + failure.getMessage()));
    }

    private void assertRetrievalFailsClosed(String attackBody, URIBuilder uriBuilder) {
        moduleDispatcher.serve(attackBody);
        var client = new UserInfoClient(config());
        String userInfoEndpoint = uriBuilder.addPathSegment("userinfo").buildAsString();
        String accessToken = Generators.letterStrings(20, 40).next();

        assertThrows(TransportException.class,
                () -> client.fetchUserInfo(userInfoEndpoint, accessToken),
                "an adversarial userinfo response body must never yield a trusted userinfo document");
    }

    private static ClientConfiguration config() {
        return ClientConfiguration.builder()
                .issuer("https://" + Generators.letterStrings(3, 10).next() + ".example.com")
                .clientId(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .allowInsecureHttp(true)
                .build();
    }

    /**
     * Serves a configurable body at the userinfo endpoint with HTTP 200, so the parser — not the HTTP
     * status — is what must reject the adversarial payload.
     */
    static final class AttackUserInfoDispatcher implements ModuleDispatcherElement {

        private String body = "";

        void serve(String responseBody) {
            this.body = responseBody;
        }

        @Override
        public String getBaseUrl() {
            return "/userinfo";
        }

        @Override
        public Set<HttpMethodMapper> supportedMethods() {
            return Set.of(HttpMethodMapper.GET);
        }

        @Override
        public Optional<MockResponse> handleGet(RecordedRequest request) {
            return Optional.of(new MockResponse(200, Headers.of("Content-Type", "application/json"), body));
        }
    }
}
