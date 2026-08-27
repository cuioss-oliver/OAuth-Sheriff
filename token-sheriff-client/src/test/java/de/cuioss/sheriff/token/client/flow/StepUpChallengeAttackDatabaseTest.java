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

import de.cuioss.http.security.database.AttackTestCase;
import de.cuioss.http.security.database.ModSecurityCRSAttackDatabase;
import de.cuioss.http.security.database.OWASPTop10AttackDatabase;
import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
import de.cuioss.sheriff.token.client.flow.StepUpChallengeParser.StepUpChallenge;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives the curated {@code http.security} attack corpora through the RFC 9470 step-up parsing and
 * initiation surface, asserting it fails closed: a forged {@code WWW-Authenticate} header never yields
 * an actionable challenge, and an attack payload smuggled as an {@code acr_values} value is safely
 * URL-encoded into a single parameter rather than injecting extra authorization-request parameters.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("Step-up surface fail-closed against http.security attack corpora")
class StepUpChallengeAttackDatabaseTest {

    private static final String REDIRECT_URI = "https://rp.example.com/callback";
    private static final String AUTH_ENDPOINT = "https://issuer.example.com/authorize";

    private final StepUpChallengeParser parser = new StepUpChallengeParser();
    private final StepUpHandler stepUpHandler = new StepUpHandler();

    private static ClientConfiguration config() {
        return ClientConfiguration.builder()
                .issuer("https://issuer.example.com")
                .clientId(Generators.nonBlankStrings().next())
                .clientSecret(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .scope("openid")
                .redirectUri(REDIRECT_URI)
                .build();
    }

    private static ProviderMetadata metadata() {
        var metadata = new ProviderMetadata();
        metadata.issuer = "https://issuer.example.com";
        metadata.authorizationEndpoint = AUTH_ENDPOINT;
        metadata.codeChallengeMethodsSupported = List.of("S256");
        return metadata;
    }

    @ParameterizedTest
    @ArgumentsSource(OWASPTop10AttackDatabase.ArgumentsProvider.class)
    @DisplayName("Should never derive a step-up challenge from an OWASP attack payload used as the raw header")
    void owaspForgedHeaderNeverYieldsChallenge(AttackTestCase testCase) {
        assertForgedHeaderRejected(testCase.attackString());
    }

    @ParameterizedTest
    @ArgumentsSource(ModSecurityCRSAttackDatabase.ArgumentsProvider.class)
    @DisplayName("Should never derive a step-up challenge from a ModSecurity attack payload used as the raw header")
    void modSecurityForgedHeaderNeverYieldsChallenge(AttackTestCase testCase) {
        assertForgedHeaderRejected(testCase.attackString());
    }

    @ParameterizedTest
    @ArgumentsSource(OWASPTop10AttackDatabase.ArgumentsProvider.class)
    @DisplayName("Should URL-encode an attack-payload acr_values into exactly one request parameter (TEST-10)")
    void injectedAcrValueIsSafelyEncoded(AttackTestCase testCase) {
        // Drive the raw attack payload straight into the acr_values the handler encodes — no silent
        // skip on a header that fails to parse; the encoding safety must hold for every payload.
        var challenge = new StepUpChallenge(testCase.attackString(), null);

        String url = stepUpHandler.initiate(config(), metadata(), challenge).authorizationUrl();

        assertEquals(1, countOccurrences(url, "acr_values="),
                "the attack payload must be encoded into exactly one acr_values parameter, never injecting a second");
        assertTrue(url.startsWith(AUTH_ENDPOINT + "?"),
                "the payload must not break the authorization endpoint prefix");
    }

    @Test
    @DisplayName("Should reject and log a challenge carrying a duplicate auth-param, sanitizing the key (RFC 9110 §11.2)")
    void shouldRejectDuplicateAuthParamFailClosed() {
        // A duplicate auth-param is malformed per RFC 9110 §11.2; the parser fails closed rather than
        // taking a last-wins value an attacker could inject, and the offending key is log-sanitized.
        String duplicated = "Bearer error=\"insufficient_user_authentication\", "
                + "acr_values=\"gold\", acr_values=\"silver\"";

        Optional<StepUpChallenge> challenge = parser.parse(duplicated);

        assertTrue(challenge.isEmpty(),
                "a challenge with a duplicate auth-param must be rejected fail-closed");
    }

    private void assertForgedHeaderRejected(String attackHeader) {
        Optional<StepUpChallenge> challenge = parser.parse(attackHeader);

        assertTrue(challenge.isEmpty(),
                "a raw attack payload is not an insufficient_user_authentication Bearer challenge");
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0;
        int index = haystack.indexOf(needle);
        while (index >= 0) {
            count++;
            index = haystack.indexOf(needle, index + needle.length());
        }
        return count;
    }
}
