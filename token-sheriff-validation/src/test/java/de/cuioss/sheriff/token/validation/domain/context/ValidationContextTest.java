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
package de.cuioss.sheriff.token.validation.domain.context;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link ValidationContext}.
 *
 * @author Oliver Wolff
 */
@DisplayName("ValidationContext")
class ValidationContextTest {

    private static final int CLOCK_SKEW = 60;
    private static final OffsetDateTime FIXED_TIME = OffsetDateTime.parse("2026-03-24T12:00:00Z");

    @Nested
    @DisplayName("Constructors")
    class Constructors {

        @Test
        @DisplayName("Two-arg production constructor should set clockSkew and null maxTokenAge")
        void productionConstructor() {
            var ctx = new ValidationContext(CLOCK_SKEW, null);
            assertEquals(CLOCK_SKEW, ctx.getClockSkewSeconds());
            assertNull(ctx.getMaxTokenAgeSeconds());
            assertNotNull(ctx.getCurrentTime());
        }

        @Test
        @DisplayName("Two-arg constructor with time should set clockSkew and null maxTokenAge")
        void twoArgWithTimeConstructor() {
            var ctx = new ValidationContext(FIXED_TIME, CLOCK_SKEW, null);
            assertEquals(FIXED_TIME, ctx.getCurrentTime());
            assertEquals(CLOCK_SKEW, ctx.getClockSkewSeconds());
            assertNull(ctx.getMaxTokenAgeSeconds());
        }

        @Test
        @DisplayName("Two-arg constructor with maxTokenAge should capture current time")
        void twoArgWithMaxAgeConstructor() {
            var ctx = new ValidationContext(CLOCK_SKEW, 300);
            assertEquals(CLOCK_SKEW, ctx.getClockSkewSeconds());
            assertEquals(300, ctx.getMaxTokenAgeSeconds());
            assertNotNull(ctx.getCurrentTime());
        }

        @Test
        @DisplayName("Two-arg constructor with null maxTokenAge should disable token age validation")
        void twoArgWithNullMaxAge() {
            var ctx = new ValidationContext(CLOCK_SKEW, null);
            assertNull(ctx.getMaxTokenAgeSeconds());
            assertFalse(ctx.isTokenAgeValidationEnabled());
        }

        @Test
        @DisplayName("Three-arg constructor should set all fields")
        void threeArgConstructor() {
            var ctx = new ValidationContext(FIXED_TIME, CLOCK_SKEW, 300);
            assertEquals(FIXED_TIME, ctx.getCurrentTime());
            assertEquals(CLOCK_SKEW, ctx.getClockSkewSeconds());
            assertEquals(300, ctx.getMaxTokenAgeSeconds());
        }

        @Test
        @DisplayName("Three-arg constructor with null maxTokenAge should disable token age validation")
        void threeArgWithNullMaxAge() {
            var ctx = new ValidationContext(FIXED_TIME, CLOCK_SKEW, null);
            assertNull(ctx.getMaxTokenAgeSeconds());
            assertFalse(ctx.isTokenAgeValidationEnabled());
        }

        @Test
        @DisplayName("Two-arg constructor should reject negative clockSkewSeconds")
        void twoArgShouldRejectNegativeClockSkew() {
            var exception = assertThrows(IllegalArgumentException.class,
                    () -> new ValidationContext(-1, null));
            assertTrue(exception.getMessage().contains("clockSkewSeconds must not be negative"));
        }

        @Test
        @DisplayName("Three-arg constructor should reject negative clockSkewSeconds")
        void threeArgShouldRejectNegativeClockSkew() {
            var exception = assertThrows(IllegalArgumentException.class,
                    () -> new ValidationContext(FIXED_TIME, -5, null));
            assertTrue(exception.getMessage().contains("clockSkewSeconds must not be negative"));
        }

        @Test
        @DisplayName("Both constructors should accept zero clockSkewSeconds")
        void shouldAcceptZeroClockSkew() {
            assertDoesNotThrow(() -> new ValidationContext(0, null));
            assertDoesNotThrow(() -> new ValidationContext(FIXED_TIME, 0, null));
        }
    }

    @Nested
    @DisplayName("isTokenAgeValidationEnabled")
    class IsTokenAgeValidationEnabled {

        @Test
        @DisplayName("Should return true when maxTokenAgeSeconds is set")
        void shouldReturnTrueWhenEnabled() {
            var ctx = new ValidationContext(FIXED_TIME, CLOCK_SKEW, 300);
            assertTrue(ctx.isTokenAgeValidationEnabled());
        }

        @Test
        @DisplayName("Should return false when maxTokenAgeSeconds is null")
        void shouldReturnFalseWhenDisabled() {
            var ctx = new ValidationContext(FIXED_TIME, CLOCK_SKEW, null);
            assertFalse(ctx.isTokenAgeValidationEnabled());
        }
    }

    @Nested
    @DisplayName("isExpired")
    class IsExpired {

        @Test
        @DisplayName("Should return true for clearly expired token")
        void shouldReturnTrueForExpiredToken() {
            var ctx = new ValidationContext(FIXED_TIME, CLOCK_SKEW, null);
            var expiration = FIXED_TIME.minusHours(1);
            assertTrue(ctx.isExpired(expiration));
        }

        @Test
        @DisplayName("Should return false for non-expired token")
        void shouldReturnFalseForNonExpiredToken() {
            var ctx = new ValidationContext(FIXED_TIME, CLOCK_SKEW, null);
            var expiration = FIXED_TIME.plusHours(1);
            assertFalse(ctx.isExpired(expiration));
        }

        @Test
        @DisplayName("Should tolerate clock skew - token expired less than skew seconds ago")
        void shouldTolerateClockSkew() {
            var ctx = new ValidationContext(FIXED_TIME, CLOCK_SKEW, null);
            // Token expired 30 seconds ago, but clock skew is 60s, so still valid
            var expiration = FIXED_TIME.minusSeconds(30);
            assertFalse(ctx.isExpired(expiration));
        }

        @Test
        @DisplayName("Should expire when beyond clock skew tolerance")
        void shouldExpireBeyondClockSkew() {
            var ctx = new ValidationContext(FIXED_TIME, CLOCK_SKEW, null);
            // Token expired 61 seconds ago, clock skew is 60s -> expired
            var expiration = FIXED_TIME.minusSeconds(61);
            assertTrue(ctx.isExpired(expiration));
        }

        @Test
        @DisplayName("Should not expire at exact clock skew boundary")
        void shouldNotExpireAtExactBoundary() {
            var ctx = new ValidationContext(FIXED_TIME, CLOCK_SKEW, null);
            // Token expired exactly 60 seconds ago, clock skew is 60s
            // expiration + clockSkew == currentTime -> isBefore returns false
            var expiration = FIXED_TIME.minusSeconds(60);
            assertFalse(ctx.isExpired(expiration));
        }

        @Test
        @DisplayName("Should apply zero clock skew correctly")
        void shouldApplyZeroClockSkew() {
            var ctx = new ValidationContext(FIXED_TIME, 0, null);
            // Token expired 1 second ago with no clock skew -> expired
            var expiration = FIXED_TIME.minusSeconds(1);
            assertTrue(ctx.isExpired(expiration));
        }
    }

    @Nested
    @DisplayName("isTokenTooOld")
    class IsTokenTooOld {

        @Test
        @DisplayName("Should return false for young token")
        void shouldReturnFalseForYoungToken() {
            var ctx = new ValidationContext(FIXED_TIME, CLOCK_SKEW, 300);
            // Issued 100 seconds ago, max age 300 + 60 skew = 360
            var issuedAt = FIXED_TIME.minusSeconds(100);
            assertFalse(ctx.isTokenTooOld(issuedAt));
        }

        @Test
        @DisplayName("Should return true for too old token")
        void shouldReturnTrueForTooOldToken() {
            var ctx = new ValidationContext(FIXED_TIME, CLOCK_SKEW, 300);
            // Issued 400 seconds ago, max age 300 + 60 skew = 360 -> too old
            var issuedAt = FIXED_TIME.minusSeconds(400);
            assertTrue(ctx.isTokenTooOld(issuedAt));
        }

        @Test
        @DisplayName("Should return false at exact boundary")
        void shouldReturnFalseAtExactBoundary() {
            var ctx = new ValidationContext(FIXED_TIME, CLOCK_SKEW, 300);
            // Issued exactly 360 seconds ago, max age + skew = 360 -> not too old (<=)
            var issuedAt = FIXED_TIME.minusSeconds(360);
            assertFalse(ctx.isTokenTooOld(issuedAt));
        }

        @Test
        @DisplayName("Should return true just past boundary")
        void shouldReturnTrueJustPastBoundary() {
            var ctx = new ValidationContext(FIXED_TIME, CLOCK_SKEW, 300);
            // Issued 361 seconds ago, max age + skew = 360 -> too old
            var issuedAt = FIXED_TIME.minusSeconds(361);
            assertTrue(ctx.isTokenTooOld(issuedAt));
        }

        @Test
        @DisplayName("Should throw IllegalStateException when token age validation is disabled")
        void shouldThrowWhenDisabled() {
            var ctx = new ValidationContext(FIXED_TIME, CLOCK_SKEW, null);
            var issuedAt = FIXED_TIME.minusSeconds(100);
            assertThrows(IllegalStateException.class, () -> ctx.isTokenTooOld(issuedAt));
        }

        @Test
        @DisplayName("Should account for clock skew in token age calculation")
        void shouldAccountForClockSkewInAge() {
            var ctx = new ValidationContext(FIXED_TIME, 0, 300);
            // With zero clock skew, 301 seconds -> too old
            var issuedAt = FIXED_TIME.minusSeconds(301);
            assertTrue(ctx.isTokenTooOld(issuedAt));

            // With zero clock skew, 300 seconds -> not too old
            var issuedAt2 = FIXED_TIME.minusSeconds(300);
            assertFalse(ctx.isTokenTooOld(issuedAt2));
        }
    }
}
