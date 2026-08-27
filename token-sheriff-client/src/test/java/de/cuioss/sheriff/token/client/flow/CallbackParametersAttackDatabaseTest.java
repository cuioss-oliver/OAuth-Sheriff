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

import de.cuioss.http.security.database.ApacheCVEAttackDatabase;
import de.cuioss.http.security.database.AttackTestCase;
import de.cuioss.http.security.database.ModSecurityCRSAttackDatabase;
import de.cuioss.http.security.database.OWASPTop10AttackDatabase;
import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Drives the curated {@code http.security} attack corpora through the authorization-code callback
 * surface and asserts it fails closed: no adversarial {@code state} ever matches the flow context, so
 * an injected code is always rejected, and every attack payload is treated as inert data by
 * {@link CallbackParameters} rather than being trusted or executed.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("Callback surface fail-closed against http.security attack corpora")
class CallbackParametersAttackDatabaseTest {

    private static final String REDIRECT_URI = "https://rp.example.com/callback";

    private final CallbackHandler handler = new CallbackHandler();

    @ParameterizedTest
    @ArgumentsSource(OWASPTop10AttackDatabase.ArgumentsProvider.class)
    @DisplayName("Should reject an injected code whose state is an OWASP Top 10 attack payload")
    void rejectsOwaspAttackStates(AttackTestCase testCase) {
        assertRejectedAsForgedState(testCase.attackString());
    }

    @ParameterizedTest
    @ArgumentsSource(ApacheCVEAttackDatabase.ArgumentsProvider.class)
    @DisplayName("Should reject an injected code whose state is an Apache CVE attack payload")
    void rejectsApacheCveAttackStates(AttackTestCase testCase) {
        assertRejectedAsForgedState(testCase.attackString());
    }

    @ParameterizedTest
    @ArgumentsSource(ModSecurityCRSAttackDatabase.ArgumentsProvider.class)
    @DisplayName("Should reject an injected code whose state is a ModSecurity CRS attack payload")
    void rejectsModSecurityAttackStates(AttackTestCase testCase) {
        assertRejectedAsForgedState(testCase.attackString());
    }

    @ParameterizedTest
    @ArgumentsSource(OWASPTop10AttackDatabase.ArgumentsProvider.class)
    @DisplayName("Should reject an error callback whose error code is an attack payload")
    void rejectsAttackErrorCallbacks(AttackTestCase testCase) {
        var context = FlowContext.create(REDIRECT_URI);
        var parameters = new CallbackParameters(Generators.nonBlankStrings().next(),
                context.state(), testCase.attackString(), null, null);

        assertThrows(ClientProtocolException.class, () -> handler.handle(context, parameters),
                "an attack payload delivered as an error callback must be rejected");
    }

    @ParameterizedTest
    @ArgumentsSource(OWASPTop10AttackDatabase.ArgumentsProvider.class)
    @DisplayName("Should decode an attack payload through the real parse(rawQuery) path as inert data (TEST-8)")
    void treatsAttackPayloadAsInertData(AttackTestCase testCase) {
        String payload = testCase.attackString();
        String encoded = URLEncoder.encode(payload, StandardCharsets.UTF_8);
        String rawQuery = "code=" + encoded + "&state=" + encoded + "&iss=" + encoded;

        var parameters = CallbackParameters.parse(rawQuery);

        assertAll("inert payload URL-decoded verbatim on the real parse path",
                () -> assertEquals(payload, parameters.getCode().orElseThrow(),
                        "the code round-trips through URL-decoding as opaque data"),
                () -> assertEquals(payload, parameters.getIssuer().orElseThrow(),
                        "the iss round-trips through URL-decoding as opaque data"),
                () -> assertEquals(payload, parameters.state(),
                        "the state round-trips through URL-decoding as opaque data"));
    }

    @ParameterizedTest
    @ArgumentsSource(OWASPTop10AttackDatabase.ArgumentsProvider.class)
    @DisplayName("Should reject a smuggled duplicate state on the real parse path (RFC 9700 §4.7.3, TEST-8)")
    void rejectsSmuggledDuplicateState(AttackTestCase testCase) {
        String encoded = URLEncoder.encode(testCase.attackString(), StandardCharsets.UTF_8);
        String rawQuery = "state=" + encoded + "&state=" + encoded;

        assertThrows(IllegalArgumentException.class, () -> CallbackParameters.parse(rawQuery),
                "a smuggled second state must be rejected by parse, never silently last-wins");
    }

    private void assertRejectedAsForgedState(String attackState) {
        var context = FlowContext.create(REDIRECT_URI);
        var injected = new CallbackParameters(Generators.nonBlankStrings().next(), attackState, null, null, null);

        assertThrows(ClientProtocolException.class, () -> handler.handle(context, injected),
                "an attack-payload state can never match the flow context, so the code is rejected");
    }
}
