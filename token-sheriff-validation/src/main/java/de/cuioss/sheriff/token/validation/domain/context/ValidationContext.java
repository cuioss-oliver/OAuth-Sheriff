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

import lombok.Getter;

import java.time.Duration;
import java.time.OffsetDateTime;

/**
 * Context object that carries validation state and cached values throughout the JWT validation pipeline.
 * <p>
 * This class eliminates synchronous time operations by caching the current time at the start of validation
 * and reusing it throughout the pipeline. This approach significantly improves performance under concurrent
 * load by avoiding multiple OffsetDateTime.now() system calls that can cause extreme latency variance.
 * <p>
 * The ValidationContext can be extended in the future to carry additional pipeline state, configuration,
 * or optimization data as needed.
 * <p>
 * <strong>Performance Impact:</strong>
 * <ul>
 *   <li>Eliminates 3+ OffsetDateTime.now() calls per token validation</li>
 *   <li>Reduces 4,813x P50-to-P99 latency variance caused by system call contention</li>
 *   <li>Consistent timing behavior under high concurrency (200+ threads)</li>
 * </ul>
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public class ValidationContext {

    /**
     * Cached current time captured at the start of validation pipeline.
     * This timestamp is used consistently throughout all validation steps to avoid
     * multiple OffsetDateTime.now() system calls.
     */
    @Getter
    private final OffsetDateTime currentTime;

    /**
     * Clock skew tolerance in seconds for time-based validations.
     * Applied to both expiration (exp) and not-before (nbf) claim validation
     * to account for time differences between token issuer and validator.
     */
    @Getter
    private final int clockSkewSeconds;

    /**
     * Maximum token age in seconds, or {@code null} if token age validation is disabled.
     * When set, tokens where {@code now - iat > maxTokenAgeSeconds + clockSkewSeconds}
     * are rejected, even if not yet expired.
     *
     * @see <a href="https://download.eclipse.org/microprofile/microprofile-jwt-auth-2.1/microprofile-jwt-auth-spec-2.1.html">MP-JWT 2.1 - mp.jwt.verify.token.age</a>
     */
    @Getter
    private final Integer maxTokenAgeSeconds;

    /**
     * Creates a new ValidationContext, capturing the current time via {@link OffsetDateTime#now()}.
     * <p>
     * Convenience constructor for callers that do not already hold a timestamp. Prefer the
     * three-argument constructor when a consistent timestamp is already available (as the
     * validation pipelines do), so that all steps of an operation share the same time.
     *
     * @param clockSkewSeconds the clock skew tolerance in seconds
     * @param maxTokenAgeSeconds the maximum token age in seconds, or null to disable
     */
    public ValidationContext(int clockSkewSeconds, Integer maxTokenAgeSeconds) {
        if (clockSkewSeconds < 0) {
            throw new IllegalArgumentException("clockSkewSeconds must not be negative: " + clockSkewSeconds);
        }
        this.currentTime = OffsetDateTime.now();
        this.clockSkewSeconds = clockSkewSeconds;
        this.maxTokenAgeSeconds = maxTokenAgeSeconds;
    }

    /**
     * Creates a new ValidationContext with an explicitly provided current time.
     * <p>
     * This is the primary constructor used by the validation pipelines: they capture the
     * current time once at the start of validation and pass it in, so cache checks and all
     * validation steps operate on a single consistent timestamp. It is equally useful in
     * tests to validate against a fixed point in time.
     *
     * @param currentTime the current time to use for validation
     * @param clockSkewSeconds the clock skew tolerance in seconds
     * @param maxTokenAgeSeconds the maximum token age in seconds, or null to disable
     */
    public ValidationContext(OffsetDateTime currentTime, int clockSkewSeconds, Integer maxTokenAgeSeconds) {
        if (clockSkewSeconds < 0) {
            throw new IllegalArgumentException("clockSkewSeconds must not be negative: " + clockSkewSeconds);
        }
        this.currentTime = currentTime;
        this.clockSkewSeconds = clockSkewSeconds;
        this.maxTokenAgeSeconds = maxTokenAgeSeconds;
    }


    /**
     * Gets the current time plus the clock skew tolerance.
     * Used for not-before validation to allow for time differences between systems.
     *
     * @return current time plus clock skew seconds
     */
    public OffsetDateTime getCurrentTimeWithClockSkew() {
        return currentTime.plusSeconds(clockSkewSeconds);
    }

    /**
     * Checks if a given expiration time represents an expired token.
     * <p>
     * Applies clock skew tolerance: a token is considered expired only if its expiration time
     * plus the clock skew tolerance is before the current time. This accommodates clock drift
     * between the token issuer and the validator in distributed systems.
     *
     * @param expirationTime the token's expiration time
     * @return true if the token is expired (even accounting for clock skew), false otherwise
     */
    public boolean isExpired(OffsetDateTime expirationTime) {
        return isExpired(expirationTime, clockSkewSeconds, currentTime);
    }

    /**
     * Shared expiry predicate: checks whether an expiration time (extended by the clock skew
     * tolerance) lies before the given reference time.
     * <p>
     * Centralizes the expiry semantics used by both the validation pipeline and the access
     * token cache, ensuring both apply clock skew identically.
     *
     * @param expirationTime the token's expiration time
     * @param clockSkewSeconds the clock skew tolerance in seconds
     * @param now the reference time to check against
     * @return true if the token is expired (even accounting for clock skew), false otherwise
     */
    public static boolean isExpired(OffsetDateTime expirationTime, int clockSkewSeconds, OffsetDateTime now) {
        return expirationTime.plusSeconds(clockSkewSeconds).isBefore(now);
    }

    /**
     * Checks if a not-before time is invalid (too far in the future).
     *
     * @param notBeforeTime the token's not-before time
     * @return true if the not-before time is invalid, false otherwise
     */
    public boolean isNotBeforeInvalid(OffsetDateTime notBeforeTime) {
        return notBeforeTime.isAfter(getCurrentTimeWithClockSkew());
    }

    /**
     * Checks if token age validation is enabled.
     *
     * @return true if maxTokenAgeSeconds is configured
     */
    public boolean isTokenAgeValidationEnabled() {
        return maxTokenAgeSeconds != null;
    }

    /**
     * Checks if a token is too old based on its issued-at time.
     * <p>
     * A token is considered too old when {@code now - issuedAt > maxTokenAgeSeconds + clockSkewSeconds}.
     *
     * @param issuedAt the token's issued-at time
     * @return true if the token is too old, false otherwise
     * @throws IllegalStateException if token age validation is not enabled
     */
    public boolean isTokenTooOld(OffsetDateTime issuedAt) {
        if (maxTokenAgeSeconds == null) {
            throw new IllegalStateException("Token age validation is not enabled");
        }
        long ageSeconds = Duration.between(issuedAt, currentTime).getSeconds();
        return ageSeconds > (long) maxTokenAgeSeconds + clockSkewSeconds;
    }
}