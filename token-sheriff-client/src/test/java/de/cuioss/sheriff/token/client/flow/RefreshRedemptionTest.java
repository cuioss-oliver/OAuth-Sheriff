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

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnableGeneratorController
@DisplayName("RefreshRedemption tri-state redemption signal")
class RefreshRedemptionTest {

    @Test
    @DisplayName("Should report a rotating server as burned and carry the revocable successor")
    void shouldReportRotationAsBurned() {
        String successor = Generators.letterStrings(20, 40).next();

        RefreshRedemption redemption = RefreshRedemption.rotated(successor);

        assertAll("rotated",
                () -> assertEquals(successor, redemption.rotatedRefreshToken(),
                        "the successor must be carried so the quarantine can revoke it"),
                () -> assertTrue(redemption.rotationKnown(), "a parsed response makes rotation known"),
                () -> assertTrue(redemption.presentedTokenBurned(),
                        "a rotated presented token is dead at the authorization server"));
    }

    @Test
    @DisplayName("Should report a non-rotating server as not burned, so the session survives a refusal")
    void shouldReportNoRotationAsSurviving() {
        RefreshRedemption redemption = RefreshRedemption.notRotated();

        assertAll("not rotated",
                () -> assertNull(redemption.rotatedRefreshToken(), "there is no successor to carry"),
                () -> assertTrue(redemption.rotationKnown(), "a parsed response makes rotation known"),
                () -> assertFalse(redemption.presentedTokenBurned(),
                        "a presented token the server reused is still valid and must not be quarantined"));
    }

    @Test
    @DisplayName("Should fail closed on an unrecoverable rotation decision while carrying no successor")
    void shouldFailClosedWhenRotationIsUnknown() {
        RefreshRedemption redemption = RefreshRedemption.rotationUnknown();

        assertAll("rotation unknown",
                () -> assertFalse(redemption.rotationKnown(),
                        "an unparseable response leaves rotation undetermined"),
                () -> assertTrue(redemption.presentedTokenBurned(),
                        "an undetermined rotation must be presumed burned, not presumed safe"),
                () -> assertNull(redemption.rotatedRefreshToken(),
                        "no successor may be invented for a response that never yielded one"));
    }

    @Test
    @DisplayName("Should reject a null or blank successor rather than record an unusable revocation target")
    void shouldRejectUnusableSuccessor() {
        assertAll("successor validation",
                () -> assertThrows(NullPointerException.class, () -> RefreshRedemption.rotated(null)),
                () -> assertThrows(IllegalArgumentException.class, () -> RefreshRedemption.rotated("   ")));
    }

    @Test
    @DisplayName("Should redact the successor token from toString while keeping its presence visible")
    void shouldRedactSuccessorInToString() {
        String successor = Generators.letterStrings(20, 40).next();

        assertAll("redaction",
                () -> assertFalse(RefreshRedemption.rotated(successor).toString().contains(successor),
                        "a stray toString must never leak a usable credential"),
                () -> assertTrue(RefreshRedemption.rotated(successor).toString().contains("<redacted>"),
                        "the successor's presence must still be visible for diagnosis"),
                () -> assertTrue(RefreshRedemption.rotationUnknown().toString().contains("null"),
                        "an absent successor must render as absent, not as redacted material"));
    }
}
