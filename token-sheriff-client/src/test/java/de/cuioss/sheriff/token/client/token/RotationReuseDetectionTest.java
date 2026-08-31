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
package de.cuioss.sheriff.token.client.token;

import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Rotation and reuse-detection contract of the {@link RefreshTokenFamily} primitive, exercised in
 * isolation from any transport, store or lifecycle wiring.
 * <p>
 * A family advances its current token across a legitimate rotation, fails closed and revokes itself
 * when a superseded token is replayed against it, and rejects malformed or non-rotating inputs at
 * construction and on rotation. Because the primitive is what the wired path delegates its reuse
 * decision to, pinning it here keeps the decision testable without standing up a token endpoint.
 * <p>
 * The wired end-to-end contract built on top of this primitive — RFC 7009 revoke-on-reuse, the
 * single-flight collapse, and the OIDC Core §12.2 refreshed-ID-token consistency check — lives in
 * {@link RefreshAdversarialTest}, which drives the assembled lifecycle manager against a mock token
 * endpoint using the shared {@link RefreshTestSupport} fixture.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("RefreshTokenFamily rotation and reuse primitive")
class RotationReuseDetectionTest {

    @Test
    @DisplayName("Should advance the current token across a successful family rotation")
    void shouldAdvanceOnRotation() {
        String initial = Generators.letterStrings(20, 40).next();
        String next = Generators.letterStrings(20, 40).next();
        var family = new RefreshTokenFamily(initial);

        family.rotate(initial, next);

        assertAll("after rotation",
                () -> assertFalse(family.isRevoked(), "a valid rotation must not revoke the family"),
                () -> assertEquals(next, family.currentToken(), "the rotated token must become current"));
    }

    @Test
    @DisplayName("Should revoke the family and fail closed when a superseded token is replayed against it")
    void shouldRevokeFamilyOnReuse() {
        String initial = Generators.letterStrings(20, 40).next();
        String next = Generators.letterStrings(20, 40).next();
        String attackerNext = Generators.letterStrings(20, 40).next();
        var family = new RefreshTokenFamily(initial);
        family.rotate(initial, next);

        assertThrows(ClientProtocolException.class, () -> family.rotate(initial, attackerNext),
                "replaying the superseded token must fail closed");
        assertAll("post-reuse state",
                () -> assertTrue(family.isRevoked(), "reuse must revoke the family"),
                () -> assertThrows(ClientProtocolException.class, family::currentToken,
                        "a revoked family must not expose a current token"));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Refresh token reuse detected");
    }

    @Test
    @DisplayName("Should undo a tentative rotation so the presented token is current again")
    void shouldRevertRotationBackToPresentedToken() {
        String initial = Generators.letterStrings(20, 40).next();
        String next = Generators.letterStrings(20, 40).next();
        var family = new RefreshTokenFamily(initial);
        family.rotate(initial, next);

        family.revertRotation(initial, next);

        assertAll("after revert",
                () -> assertFalse(family.isRevoked(), "reverting a tentative rotation must not revoke the family"),
                () -> assertEquals(initial, family.currentToken(),
                        "the presented token must become current again"),
                () -> assertDoesNotThrow(() -> family.rotate(initial, next),
                        "the reverted token must be redeemable again, exactly as if the rotation never happened"));
    }

    @Test
    @DisplayName("Should ignore a revert once the family moved past the rotation it targets")
    void shouldIgnoreStaleRevert() {
        String initial = Generators.letterStrings(20, 40).next();
        String next = Generators.letterStrings(20, 40).next();
        String afterNext = Generators.letterStrings(20, 40).next();
        var family = new RefreshTokenFamily(initial);
        family.rotate(initial, next);
        family.rotate(next, afterNext);

        // A revert naming the now-superseded 'initial -> next' step must not claw the family back past
        // the legitimate 'next -> afterNext' rotation that has since happened.
        family.revertRotation(initial, next);

        assertEquals(afterNext, family.currentToken(),
                "a stale revert must not undo a later, unrelated rotation");
    }

    @Test
    @DisplayName("Should ignore a revert once the family has been revoked by reuse detection")
    void shouldIgnoreRevertOnRevokedFamily() {
        String initial = Generators.letterStrings(20, 40).next();
        String next = Generators.letterStrings(20, 40).next();
        String attackerNext = Generators.letterStrings(20, 40).next();
        var family = new RefreshTokenFamily(initial);
        family.rotate(initial, next);
        assertThrows(ClientProtocolException.class, () -> family.rotate(initial, attackerNext));

        family.revertRotation(initial, next);

        assertAll("revoked family stays revoked",
                () -> assertTrue(family.isRevoked(), "a revert must not un-revoke a family"),
                () -> assertThrows(ClientProtocolException.class, family::currentToken));
    }

    @Test
    @DisplayName("Should reject invalid tokens and non-rotating successors on the family primitive")
    void shouldRejectInvalidTokens() {
        var family = new RefreshTokenFamily(Generators.letterStrings(20, 40).next());
        var presented = Generators.letterStrings(20, 40).next();
        var freshFamily = new RefreshTokenFamily(presented);
        var rotationSuccessor = Generators.letterStrings(20, 40).next();
        assertAll("token validation",
                () -> assertThrows(NullPointerException.class, () -> new RefreshTokenFamily(null)),
                () -> assertThrows(IllegalArgumentException.class, () -> new RefreshTokenFamily("  ")),
                () -> assertThrows(NullPointerException.class,
                        () -> family.rotate(null, rotationSuccessor)),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> freshFamily.rotate(presented, presented)));
    }
}
