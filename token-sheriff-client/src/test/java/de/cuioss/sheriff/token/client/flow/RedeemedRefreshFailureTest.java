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
import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The pre-/post-redemption discriminator as a <em>type contract</em> rather than as an observed
 * behaviour of the wired flow (which {@code RefreshPostRedemptionQuarantineTest} pins end to end).
 * <p>
 * Two properties are load-bearing here and neither is visible from the wired tier. First, the carriers
 * must remain assignable to the exception types {@link RefreshFlow#refresh} has always documented, so
 * making the redemption state travel on the exception is not a breaking contract change for any
 * existing {@code catch}. Second, {@link RefreshFlow#redemptionOf(Throwable)} must classify a failure
 * that carries nothing as pre-redemption — the case where quarantining would destroy a working session
 * over a transient network fault.
 */
@EnableGeneratorController
@DisplayName("Post-redemption refusals carry their redemption state without changing the thrown type")
class RedeemedRefreshFailureTest {

    private static final SecurityEventCounter.EventType ANY_EVENT =
            SecurityEventCounter.EventType.INVALID_JWT_FORMAT;

    @Test
    @DisplayName("Should keep the validation carrier assignable to TokenValidationException, with its event type and message")
    void shouldPreserveTheValidationContract() {
        String message = Generators.letterStrings(5, 30).next();
        var refusal = new TokenValidationException(ANY_EVENT, message);
        RefreshRedemption redemption = RefreshRedemption.rotated(Generators.letterStrings(20, 40).next());

        var carrier = new RedeemedValidationRefusalException(refusal, redemption);

        assertAll("the narrower type is still the documented one",
                () -> assertInstanceOf(TokenValidationException.class, carrier),
                () -> assertEquals(ANY_EVENT, carrier.getEventType(),
                        "the EventCategory-driven RFC 9457 mapping must survive the wrap"),
                () -> assertEquals(message, carrier.getMessage()),
                () -> assertSame(refusal, carrier.getCause()),
                () -> assertSame(redemption, carrier.redemption()));
    }

    @Test
    @DisplayName("Should keep the scope carrier assignable to ClientProtocolException, with its message")
    void shouldPreserveTheScopeRefusalContract() {
        String message = Generators.letterStrings(5, 30).next();
        RefreshRedemption redemption = RefreshRedemption.notRotated();

        var carrier = new RedeemedScopeRefusalException(message, redemption);

        assertAll("the narrower type is still the documented one",
                () -> assertInstanceOf(ClientProtocolException.class, carrier),
                () -> assertEquals(message, carrier.getMessage()),
                () -> assertSame(redemption, carrier.redemption()));
    }

    @Test
    @DisplayName("Should reject a null redemption on either carrier rather than construct an unclassifiable failure")
    void shouldRejectNullRedemption() {
        var refusal = new TokenValidationException(ANY_EVENT, "refused");
        // Hoisted so each assertThrows body holds exactly the one construction under test (java:S5778).
        RefreshRedemption redemption = RefreshRedemption.notRotated();
        assertAll("a carrier without state would silently read as a pre-redemption failure",
                () -> assertThrows(NullPointerException.class,
                        () -> new RedeemedValidationRefusalException(refusal, null)),
                () -> assertThrows(NullPointerException.class,
                        () -> new RedeemedScopeRefusalException("refused", null)),
                () -> assertThrows(NullPointerException.class,
                        () -> new RedeemedValidationRefusalException(null, redemption)));
    }

    @Test
    @DisplayName("Should classify a carried refusal, an unparseable 2xx, and a pre-redemption failure distinctly")
    void shouldClassifyEveryFailureShape() {
        String successor = Generators.letterStrings(20, 40).next();

        Optional<RefreshRedemption> carried = RefreshFlow.redemptionOf(
                new RedeemedScopeRefusalException("refused", RefreshRedemption.rotated(successor)));
        Optional<RefreshRedemption> unparseable = RefreshFlow.redemptionOf(
                new RedeemedResponseException("Empty token endpoint response"));
        Optional<RefreshRedemption> preRedemption = RefreshFlow.redemptionOf(
                new TransportException("connection refused"));

        assertAll("the absence of a redemption is the discriminator that must not be collapsed",
                () -> assertEquals(successor, carried.orElseThrow().rotatedRefreshToken()),
                () -> assertTrue(unparseable.orElseThrow().presentedTokenBurned(),
                        "an unparseable 2xx fails closed on a presumed rotation"),
                () -> assertNull(unparseable.orElseThrow().rotatedRefreshToken(),
                        "with no successor invented to revoke"),
                () -> assertTrue(preRedemption.isEmpty(),
                        "a transient fault must not be mistaken for a burned credential"),
                () -> assertThrows(NullPointerException.class, () -> RefreshFlow.redemptionOf(null)));
    }

    @Test
    @DisplayName("Should not carry live token material across a serialization boundary, and stay fail-closed when it did not")
    void shouldNotSerializeTheSuccessor() throws IOException, ClassNotFoundException {
        String successor = Generators.letterStrings(20, 40).next();

        var scopeRefusal = new RedeemedScopeRefusalException("refused",
                RefreshRedemption.rotated(successor));
        var validationRefusal = new RedeemedValidationRefusalException(
                new TokenValidationException(ANY_EVENT, "refused"), RefreshRedemption.rotated(successor));

        byte[] scopeBytes = serialize(scopeRefusal);
        byte[] validationBytes = serialize(validationRefusal);
        var roundTrippedScope = (RedeemedScopeRefusalException) deserialize(scopeBytes);
        var roundTrippedValidation = (RedeemedValidationRefusalException) deserialize(validationBytes);

        assertAll("the successor is a usable credential and must not ride the throwable",
                () -> assertFalse(new String(scopeBytes, StandardCharsets.ISO_8859_1).contains(successor),
                        "the serialized scope refusal must not contain the rotated refresh token"),
                () -> assertFalse(new String(validationBytes, StandardCharsets.ISO_8859_1).contains(successor),
                        "the serialized validation refusal must not contain the rotated refresh token"),
                () -> assertTrue(roundTrippedScope.redemption().presentedTokenBurned(),
                        "a deserialized scope refusal still quarantines"),
                () -> assertNull(roundTrippedScope.redemption().rotatedRefreshToken(),
                        "but names no token to revoke"),
                () -> assertTrue(roundTrippedValidation.redemption().presentedTokenBurned(),
                        "a deserialized validation refusal still quarantines"),
                () -> assertNull(roundTrippedValidation.redemption().rotatedRefreshToken(),
                        "but names no token to revoke"));
    }

    private static byte[] serialize(Object value) throws IOException {
        var bytes = new ByteArrayOutputStream();
        try (var out = new ObjectOutputStream(bytes)) {
            out.writeObject(value);
        }
        return bytes.toByteArray();
    }

    private static Object deserialize(byte[] bytes) throws IOException, ClassNotFoundException {
        try (var in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            return in.readObject();
        }
    }
}
