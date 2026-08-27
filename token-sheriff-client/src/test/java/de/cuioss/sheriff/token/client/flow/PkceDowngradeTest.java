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
package de.cuioss.sheriff.token.client.flow;

import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The PKCE downgrade defence ({@code CLIENT-2}): the interactive {@code authorization_code} flow is
 * refused fail-closed whenever the authorization server does not advertise PKCE {@code S256}, and the
 * {@code plain} transform is never offered.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("PKCE downgrade fail-closed defence")
class PkceDowngradeTest {

    private static final String REDIRECT_URI = "https://rp.example.com/callback";
    private static final String AUTH_ENDPOINT = "https://issuer.example.com/authorize";
    private static final String ISSUER = "https://issuer.example.com";

    private final AuthorizationRequestBuilder builder = new AuthorizationRequestBuilder();

    private static ClientConfiguration config() {
        return ClientConfiguration.builder()
                .issuer(ISSUER)
                .clientId(Generators.nonBlankStrings().next())
                .clientSecret(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .scope("openid")
                .redirectUri(REDIRECT_URI)
                .build();
    }

    private static ProviderMetadata metadata(List<String> codeChallengeMethods) {
        var metadata = new ProviderMetadata();
        metadata.issuer = ISSUER;
        metadata.authorizationEndpoint = AUTH_ENDPOINT;
        metadata.codeChallengeMethodsSupported = codeChallengeMethods;
        return metadata;
    }

    @Test
    @DisplayName("Should refuse the flow when the AS advertises no PKCE methods at all")
    void shouldRefuseWhenNoMethodsAdvertised() {
        var metadata = metadata(null);
        var context = FlowContext.create(REDIRECT_URI);
        var configuration = config();

        assertThrows(ClientProtocolException.class, () -> builder.build(configuration, metadata, context));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "does not advertise PKCE 'S256'");
    }

    @Test
    @DisplayName("Should refuse the flow when the AS advertises an empty method list")
    void shouldRefuseWhenEmptyMethodList() {
        var metadata = metadata(List.of());
        var context = FlowContext.create(REDIRECT_URI);
        var configuration = config();

        assertThrows(ClientProtocolException.class, () -> builder.build(configuration, metadata, context));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "does not advertise PKCE 'S256'");
    }

    @Test
    @DisplayName("Should refuse the flow when the AS advertises only the plain transform (downgrade attempt)")
    void shouldRefuseWhenOnlyPlainAdvertised() {
        var metadata = metadata(List.of("plain"));
        var context = FlowContext.create(REDIRECT_URI);
        var configuration = config();

        assertThrows(ClientProtocolException.class, () -> builder.build(configuration, metadata, context));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "does not advertise PKCE 'S256'");
    }

    @Test
    @DisplayName("Should proceed only when S256 is advertised, and never emit a plain method")
    void shouldProceedOnlyWithS256() {
        var metadata = metadata(List.of("S256", "plain"));
        var context = FlowContext.create(REDIRECT_URI);

        String url = builder.build(config(), metadata, context);

        assertTrue(url.contains("code_challenge_method=S256"),
                "the request always pins code_challenge_method=S256");
        assertTrue(url.contains("code_challenge="), "a code_challenge is always present");
    }

    @Test
    @DisplayName("Should never expose a plain PKCE transform on the challenge type")
    void shouldNeverExposePlainTransform() {
        var challenge = PkceChallenge.generate();

        assertEquals("S256", challenge.method(), "PkceChallenge only ever reports S256; plain is not implemented");
    }
}
