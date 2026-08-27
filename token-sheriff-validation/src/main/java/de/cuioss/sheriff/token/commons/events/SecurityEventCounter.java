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
package de.cuioss.sheriff.token.commons.events;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * Provides counters for relevant security events in the JWT Token handling module.
 * <p>
 * This class is designed to be thread-safe and highly concurrent, allowing for
 * accurate counting of security events in multi-threaded environments.
 * <p>
 * The event-type naming/numbering follows the same scheme as the global
 * {@code JWTValidationLogMessages} registry for easy correlation between logs and metrics.
 * That correlation is maintained by convention and documented in {@code doc/LogMessages.adoc};
 * it is intentionally <em>not</em> a compile-time type link, because this counter lives in the
 * {@code commons.events} base layer, which must not depend on the {@code validation} packages
 * (the ArchUnit boundary — see {@code doc/commons/architecture.adoc}).
 * <p>
 * Security events that are tracked include:
 * <ul>
 *   <li>Token format issues - empty tokens, size violations, decoding failures</li>
 *   <li>Missing claims - required fields not present in tokens</li>
 *   <li>Validation failures - expired tokens, audience mismatches</li>
 *   <li>Signature issues - validation failures, missing keys</li>
 *   <li>Algorithm issues - unsupported or insecure algorithms</li>
 *   <li>JWKS issues - endpoint failures, parsing errors</li>
 *   <li>Successful operations - token creations</li>
 * </ul>
 * <p>
 * This implementation is structured to simplify later integration with micrometer
 * but does not create any dependency on it.
 * <p>
 * For more details on the security monitoring aspects, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/security-reference.adoc">Security Specification</a>
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public class SecurityEventCounter {

    /**
     * Enum defining all security event types that can be counted.
     * <p>
     * Each event type carries an {@link EventCategory} (or {@code null} for successful
     * operations). The identifiers follow the same numbering scheme as the global log-message
     * registry; see the class-level note on why that link is by convention rather than a type
     * reference.
     */
    public enum EventType {
        // Token format issues
        TOKEN_EMPTY(EventCategory.INVALID_STRUCTURE),
        TOKEN_SIZE_EXCEEDED(EventCategory.INVALID_STRUCTURE),
        FAILED_TO_DECODE_JWT(EventCategory.INVALID_STRUCTURE),
        INVALID_JWT_FORMAT(EventCategory.INVALID_STRUCTURE),
        DECODED_PART_SIZE_EXCEEDED(EventCategory.INVALID_STRUCTURE),
        JSON_STRUCTURE_BOUNDS_EXCEEDED(EventCategory.INVALID_STRUCTURE),

        // Missing claims
        MISSING_CLAIM(EventCategory.SEMANTIC_ISSUES),
        MISSING_RECOMMENDED_ELEMENT(EventCategory.SEMANTIC_ISSUES),

        // Validation failures
        TOKEN_EXPIRED(EventCategory.SEMANTIC_ISSUES),
        TOKEN_AGE_EXCEEDED(EventCategory.SEMANTIC_ISSUES),
        TOKEN_NBF_FUTURE(EventCategory.SEMANTIC_ISSUES),
        AUDIENCE_MISMATCH(EventCategory.SEMANTIC_ISSUES),
        ACCESS_TOKEN_AUDIENCE_MISSING(EventCategory.SEMANTIC_ISSUES),
        AZP_MISMATCH(EventCategory.SEMANTIC_ISSUES),
        NO_ISSUER_CONFIG(EventCategory.SEMANTIC_ISSUES),
        ISSUER_MISMATCH(EventCategory.SEMANTIC_ISSUES),
        TOKEN_TYPE_MISMATCH(EventCategory.SEMANTIC_ISSUES),

        // DPoP validation issues (RFC 9449)
        DPOP_PROOF_MISSING(EventCategory.SEMANTIC_ISSUES),
        DPOP_PROOF_INVALID(EventCategory.INVALID_STRUCTURE),
        DPOP_PROOF_EXPIRED(EventCategory.SEMANTIC_ISSUES),
        DPOP_THUMBPRINT_MISMATCH(EventCategory.INVALID_SIGNATURE),
        DPOP_REPLAY_DETECTED(EventCategory.SEMANTIC_ISSUES),
        DPOP_ATH_MISMATCH(EventCategory.SEMANTIC_ISSUES),
        DPOP_CNF_MISSING(EventCategory.SEMANTIC_ISSUES),
        DPOP_HTU_MISMATCH(EventCategory.SEMANTIC_ISSUES),
        DPOP_HTM_MISMATCH(EventCategory.SEMANTIC_ISSUES),

        // Custom validation rule issues
        CUSTOM_RULE_REJECTED(EventCategory.SEMANTIC_ISSUES),

        // JWE decryption issues (RFC 7516)
        JWE_DECRYPTION_FAILED(EventCategory.INVALID_STRUCTURE),
        JWE_UNSUPPORTED_ALGORITHM(EventCategory.INVALID_STRUCTURE),
        JWE_DECRYPTION_NOT_CONFIGURED(EventCategory.INVALID_STRUCTURE),
        JWE_DECRYPTION_KEY_NOT_FOUND(EventCategory.INVALID_STRUCTURE),

        // Signature issues
        SIGNATURE_VALIDATION_FAILED(EventCategory.INVALID_SIGNATURE),
        KEY_NOT_FOUND(EventCategory.INVALID_SIGNATURE),

        // Algorithm issues
        UNSUPPORTED_ALGORITHM(EventCategory.INVALID_SIGNATURE),

        // JWKS issues
        JWKS_JSON_PARSE_FAILED(EventCategory.INVALID_SIGNATURE),
        DUPLICATE_JWKS_KID(EventCategory.INVALID_STRUCTURE),

        // Design Decision: success events use a null category per CUI logging standards.
        // Only INVALID_* semantic failures need a category. Success events are metric
        // counters only, tracked at DEBUG level.
        ACCESS_TOKEN_CREATED(null),
        ID_TOKEN_CREATED(null),
        REFRESH_TOKEN_CREATED(null),
        ACCESS_TOKEN_CACHE_HIT(null);

        private final EventCategory category;

        EventType(EventCategory category) {
            this.category = category;
        }

        /**
         * @return the event category for this event type, or null for successful operations
         */
        public EventCategory getCategory() {
            return category;
        }

    }

    private final ConcurrentHashMap<EventType, AtomicLong> counters = new ConcurrentHashMap<>();

    /**
     * Increments the counter for the specified event type.
     * <p>
     * If the counter doesn't exist yet, it will be created.
     *
     * @param eventType the type of security event to count
     * @return the new count value
     */
    public long increment(EventType eventType) {
        return counters.computeIfAbsent(eventType, k -> new AtomicLong(0)).incrementAndGet();
    }

    /**
     * Gets the current count for the specified event type.
     *
     * @param eventType the type of security event
     * @return the current count, or 0 if the event has never been counted
     */
    public long getCount(EventType eventType) {
        AtomicLong counter = counters.get(eventType);
        return counter != null ? counter.get() : 0;
    }

    /**
     * Gets a snapshot of all current counter values.
     *
     * @return an unmodifiable map of event types to their current counts
     */
    public Map<EventType, Long> getCounters() {
        return counters.entrySet().stream()
                .collect(Collectors.toUnmodifiableMap(
                        Map.Entry::getKey,
                        entry -> entry.getValue().get()));
    }

    /**
     * Resets all counters to zero.
     */
    public void reset() {
        counters.clear();
    }

}
