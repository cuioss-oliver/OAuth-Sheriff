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

import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Authorization-server mix-up defence ({@code CLIENT-8}, {@code T-MIXUP}): when a client trusts more
 * than one authorization server, an attacker AS cannot make the client redeem a code at the honest
 * AS. {@link IssValidator} rejects, before the code is ever exchanged, any callback whose RFC 9207
 * {@code iss} does not identify the AS the flow was started with.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("Authorization-server mix-up fail-closed defence")
class MixUpDefenseTest {

    private static final String HONEST_ISSUER = "https://honest.example.com/realms/main";
    private static final String ATTACKER_ISSUER = "https://attacker.example.com/realms/evil";

    private final IssValidator validator = new IssValidator();

    private static CallbackParameters callbackFrom(String issuer) {
        return new CallbackParameters(Generators.nonBlankStrings().next(),
                Generators.nonBlankStrings().next(), null, null, issuer);
    }

    @Test
    @DisplayName("Should reject a code stamped with the attacker AS iss while the flow started at the honest AS")
    void shouldRejectMixedUpIssuer() {
        var attackerCallback = callbackFrom(ATTACKER_ISSUER);

        assertThrows(ClientProtocolException.class,
                () -> validator.validate(HONEST_ISSUER, attackerCallback, false),
                "a callback from a different AS must be rejected before the code is redeemed");
    }

    @Test
    @DisplayName("Should accept a code stamped with the honest AS iss the flow was initiated with")
    void shouldAcceptHonestIssuer() {
        var honestCallback = callbackFrom(HONEST_ISSUER);

        assertDoesNotThrow(() -> validator.validate(HONEST_ISSUER, honestCallback, true),
                "the callback from the initiating AS is accepted");
    }

    @Test
    @DisplayName("Should treat a dropped iss as a mix-up signal when the AS is known to stamp it")
    void shouldRejectDroppedIssuerWhenRequired() {
        var strippedCallback = callbackFrom(null);

        assertThrows(ClientProtocolException.class,
                () -> validator.validate(HONEST_ISSUER, strippedCallback, true),
                "an attacker stripping the iss must not bypass the mix-up check when iss is required");
    }

    @RepeatedTest(20)
    @DisplayName("Should reject any randomly forged issuer that is not the initiating issuer")
    void shouldRejectRandomForgedIssuers() {
        var forgedCallback = callbackFrom("https://" + Generators.letterStrings(4, 12).next() + ".example.org");

        assertThrows(ClientProtocolException.class,
                () -> validator.validate(HONEST_ISSUER, forgedCallback, false),
                "no forged issuer may pass the mix-up check");
    }
}
