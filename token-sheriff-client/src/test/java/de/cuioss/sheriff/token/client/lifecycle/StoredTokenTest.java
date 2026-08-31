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
package de.cuioss.sheriff.token.client.lifecycle;

import de.cuioss.sheriff.token.client.dpop.ConstraintBinding;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Value-object level tests for {@link StoredToken}: construction guards, the {@link
 * StoredToken#isExpired(Instant)} freshness predicate the refresh scheduler drives, and the
 * carry-forward rules {@link StoredToken#refreshed} applies to the refresh and ID tokens.
 */
@EnableGeneratorController
@DisplayName("StoredToken value object")
class StoredTokenTest {

    private static String token() {
        return Generators.letterStrings(20, 40).next();
    }

    private static StoredToken bearerToken(Instant expiresAt) {
        return new StoredToken(token(), token(), token(), null, expiresAt, null);
    }

    @Nested
    @DisplayName("Construction guards")
    class ConstructionGuards {

        @Test
        @DisplayName("Should reject a blank access token so an unusable bundle can never be stored")
        void shouldRejectBlankAccessToken() {
            assertAll("blank access tokens",
                    () -> assertThrows(IllegalArgumentException.class,
                            () -> new StoredToken("", null, null, null, null, null),
                            "an empty access token is not a usable credential"),
                    () -> assertThrows(IllegalArgumentException.class,
                            () -> new StoredToken("   ", null, null, null, null, null),
                            "a whitespace-only access token is not a usable credential"));
        }

        @Test
        @DisplayName("Should reject a null access token via the separate requireNonNull guard")
        void shouldRejectNullAccessToken() {
            // Distinct from the blank cases above: the compact constructor guards null with
            // Objects.requireNonNull (NullPointerException) before the isBlank check that raises
            // IllegalArgumentException, so the two contracts need separate coverage.
            assertThrows(NullPointerException.class,
                    () -> new StoredToken(null, null, null, null, null, null),
                    "a null access token is not a usable credential");
        }
    }

    @Nested
    @DisplayName("Expiry predicate")
    class ExpiryPredicate {

        @Test
        @DisplayName("Should never report expiry when the access-token expiry is unknown")
        void shouldNeverExpireWithoutExpiry() {
            var stored = bearerToken(null);

            assertFalse(stored.isExpired(Instant.now()),
                    "a bundle with an unknown expiry must not be treated as expired");
        }

        @Test
        @DisplayName("Should report the token still valid strictly before its expiry instant")
        void shouldNotBeExpiredBeforeExpiry() {
            var expiresAt = Instant.now().plus(Duration.ofMinutes(5));
            var stored = bearerToken(expiresAt);

            assertFalse(stored.isExpired(expiresAt.minusSeconds(1)),
                    "the token is still valid up to, but not including, its expiry instant");
        }

        @Test
        @DisplayName("Should report the token expired at and after its expiry instant (inclusive boundary)")
        void shouldBeExpiredAtAndAfterExpiry() {
            var expiresAt = Instant.now().plus(Duration.ofMinutes(5));
            var stored = bearerToken(expiresAt);

            assertAll("inclusive expiry boundary",
                    () -> assertTrue(stored.isExpired(expiresAt),
                            "the expiry instant itself already counts as expired"),
                    () -> assertTrue(stored.isExpired(expiresAt.plusSeconds(1)),
                            "any instant after the expiry counts as expired"));
        }
    }

    @Nested
    @DisplayName("Refresh carry-forward")
    class RefreshCarryForward {

        @Test
        @DisplayName("Should keep the current refresh and ID token when the AS returned neither on refresh")
        void shouldKeepCurrentRefreshAndIdToken() {
            var stored = bearerToken(Instant.now());
            var newAccessToken = token();

            var refreshed = stored.refreshed(newAccessToken, null, null, null, null);

            assertAll("carry-forward on an omitting refresh",
                    () -> assertEquals(newAccessToken, refreshed.accessToken(),
                            "the refreshed access token replaces the previous one"),
                    () -> assertEquals(stored.refreshToken(), refreshed.refreshToken(),
                            "an omitted refresh token keeps the stored one"),
                    () -> assertEquals(stored.idToken(), refreshed.idToken(),
                            "an omitted ID token keeps the stored one (OIDC Core §12.2)"),
                    () -> assertNull(refreshed.expiresAt(),
                            "an unknown refreshed expiry is recorded as unknown"));
        }

        @Test
        @DisplayName("Should adopt the refreshed refresh and ID token when the AS returned both")
        void shouldAdoptReturnedRefreshAndIdToken() {
            var stored = bearerToken(Instant.now());
            var newRefreshToken = token();
            var newIdToken = token();

            var refreshed = stored.refreshed(token(), newRefreshToken, null, null, null, newIdToken);

            assertAll("adoption of returned material",
                    () -> assertEquals(newRefreshToken, refreshed.refreshToken(),
                            "a returned refresh token replaces the stored one (rotation)"),
                    () -> assertEquals(newIdToken, refreshed.idToken(),
                            "a returned ID token replaces the stored one"));
        }

        @Test
        @DisplayName("Should refuse to refresh a sender-constrained bundle onto a plain bearer token (CLIENT-18)")
        void shouldRefuseDowngradeToBearer() {
            var binding = ConstraintBinding.dpop(token());
            var constrained = new StoredToken(token(), token(), token(), binding, Instant.now(), null);
            var newAccessToken = token();

            var exception = assertThrows(IllegalStateException.class,
                    () -> constrained.refreshed(newAccessToken, null, null, null, null),
                    "a sender-constrained bundle must not silently degrade to a bearer token");

            assertTrue(exception.getMessage().contains("cnf"),
                    "the failure must name the stale cnf binding it refused to preserve");
        }

        @Test
        @DisplayName("Should refuse to refresh a sender-constrained bundle onto a differently bound token")
        void shouldRefuseRebindingToAnotherKey() {
            var binding = ConstraintBinding.dpop(token());
            var otherBinding = ConstraintBinding.dpop(token());
            var constrained = new StoredToken(token(), token(), token(), binding, Instant.now(), null);
            var newAccessToken = token();

            assertThrows(IllegalStateException.class,
                    () -> constrained.refreshed(newAccessToken, null, null, otherBinding, null),
                    "a re-binding to a different key must fail closed");
        }

        @Test
        @DisplayName("Should carry the sender constraint forward when the refreshed token confirms the same key")
        void shouldCarryConstraintForwardOnMatchingBinding() {
            var binding = ConstraintBinding.dpop(token());
            var constrained = new StoredToken(token(), token(), token(), binding, Instant.now(), null);

            var refreshed = constrained.refreshed(token(), null, null, binding, null);

            assertEquals(binding, refreshed.constraintBinding(),
                    "a refreshed token confirming the same key keeps the sender constraint");
        }
    }
}
