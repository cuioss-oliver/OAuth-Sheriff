/*
 * Copyright © 2022 CUI-OpenSource-Software (info@cuioss.de)
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
package de.cuioss.sheriff.token.quarkus.metrics;

import de.cuioss.sheriff.token.commons.events.EventCategory;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.metrics.MetricIdentifier;
import de.cuioss.sheriff.token.quarkus.config.JwtPropertyKeys;
import de.cuioss.sheriff.token.quarkus.observability.ObservedValidatorResolver;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.tools.logging.CuiLogger;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Tags;
import io.quarkus.arc.Unremovable;
import io.quarkus.scheduler.Scheduled;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jspecify.annotations.Nullable;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static de.cuioss.sheriff.token.quarkus.TokenSheriffQuarkusLogMessages.INFO;
import static de.cuioss.sheriff.token.quarkus.TokenSheriffQuarkusLogMessages.WARN;

/**
 * Collects JWT validation metrics from {@link SecurityEventCounter} and exposes them as Micrometer metrics.
 * <p>
 * This collector registers metrics for security events:
 * <ul>
 *   <li>Security Event Counters - from {@link SecurityEventCounter}</li>
 * </ul>
 * <p>
 * All metrics follow Micrometer naming conventions and include appropriate tags
 * for filtering:
 * <ul>
 *   <li>sheriff.token.validation.errors - Counter for validation errors by type</li>
 *   <li>sheriff.token.validation.success - Counter for successful operations by type</li>
 * </ul>
 * <p>
 * Security event metrics include tags:
 * <ul>
 *   <li>event_type - The type of security event</li>
 *   <li>result - The validation result (success or failure)</li>
 *   <li>category - The category of event (structure, signature, semantic) - only for failures</li>
 * </ul>
 *
 * @since 1.0
 */
@ApplicationScoped
@Unremovable
public class JwtMetricsCollector {

    private static final CuiLogger LOGGER = new CuiLogger(JwtMetricsCollector.class);

    private static final String TAG_EVENT_TYPE = "event_type";
    private static final String TAG_RESULT = "result";
    private static final String TAG_CATEGORY = "category";

    private static final String RESULT_FAILURE = "failure";
    private static final String RESULT_SUCCESS = "success";

    private final MeterRegistry registry;
    private final ObservedValidatorResolver resolver;

    // Caching of counters to avoid lookups
    private final Map<String, Counter> counters = new ConcurrentHashMap<>();

    // Track last known counts to calculate deltas
    private final Map<SecurityEventCounter.EventType, Long> lastKnownCounts = new ConcurrentHashMap<>();

    // The validator whose counter the current baselines belong to; deltas are re-baselined when it changes
    private @Nullable TokenValidator baselinedValidator;

    /**
     * Creates a new JwtMetricsCollector with the given MeterRegistry and validator resolver.
     *
     * @param registry the Micrometer registry
     * @param resolver resolves the validator whose security events are exported
     */
    @Inject
    public JwtMetricsCollector(MeterRegistry registry,
            ObservedValidatorResolver resolver) {
        this.registry = registry;
        this.resolver = resolver;
    }

    /**
     * Initializes all metrics after dependency injection is complete.
     * This method is guaranteed to run before any business method can be called.
     */
    @PostConstruct
    void initialize() {
        LOGGER.info(INFO.INITIALIZING_JWT_METRICS_COLLECTOR);

        // Register counters for all event types
        registerEventCounters();

        // Baselines start at zero (implicit via getOrDefault) so that events recorded
        // before initialization are exported as deltas by the initial update below

        LOGGER.info(INFO.JWT_METRICS_COLLECTOR_INITIALIZED, counters.size());

        // Force initial update to ensure metrics are visible immediately
        updateCounters();
    }

    /**
     * Registers counters for all security event types.
     * Creates both success and failure counters as appropriate.
     */
    private void registerEventCounters() {
        // For each event type, create appropriate counters
        for (SecurityEventCounter.EventType eventType : SecurityEventCounter.EventType.values()) {
            EventCategory category = eventType.getCategory();

            if (category == null) {
                // Success events (no category) - register as success metrics
                Tags tags = Tags.of(
                        Tag.of(TAG_EVENT_TYPE, eventType.name()),
                        Tag.of(TAG_RESULT, RESULT_SUCCESS)
                );

                Counter counter = Counter.builder(MetricIdentifier.VALIDATION.SUCCESS)
                        .tags(tags)
                        .description("Number of successful JWT operations by type")
                        .baseUnit("operations")
                        .register(registry);

                counters.put(eventType.name(), counter);
                LOGGER.debug("Registered success counter for event type %s", eventType.name());
            } else {
                // Failure events (with category) - register as error metrics
                Tags tags = Tags.of(
                        Tag.of(TAG_EVENT_TYPE, eventType.name()),
                        Tag.of(TAG_RESULT, RESULT_FAILURE),
                        Tag.of(TAG_CATEGORY, category.name())
                );

                Counter counter = Counter.builder(MetricIdentifier.VALIDATION.ERRORS)
                        .tags(tags)
                        .description("Number of JWT validation errors by type")
                        .baseUnit("errors")
                        .register(registry);

                counters.put(eventType.name(), counter);
                LOGGER.debug("Registered error counter for event type %s", eventType.name());
            }
        }
    }


    /**
     * Updates all counters from the current state.
     * This method is called periodically to ensure metrics are up to date.
     * <p>
     * The interval can be configured via the property: sheriff.token.metrics.collection.interval
     * Default: 10s (production), can be set to 2s for faster integration testing.
     */
    @Scheduled(every = "${" + JwtPropertyKeys.METRICS_COLLECTION_INTERVAL + ":10s}")
    public void updateCounters() {
        updateSecurityEventCounters();
    }

    /**
     * Updates security event counters from the observed validator's SecurityEventCounter state.
     * <p>
     * Goes idle without throwing when no validator is observable, and re-baselines the deltas when
     * the observed validator changes so two validators' histories are never mixed.
     * </p>
     */
    private void updateSecurityEventCounters() {
        TokenValidator validator = resolver.observedValidator().orElse(null);
        if (validator == null) {
            return;
        }
        if (validator != baselinedValidator) {
            lastKnownCounts.clear();
            baselinedValidator = validator;
        }
        SecurityEventCounter securityEventCounter = validator.getSecurityEventCounter();

        // Get current counts for all event types
        Map<SecurityEventCounter.EventType, Long> currentCounts = securityEventCounter.getCounters();

        // Debug: Log current state for success events
        for (SecurityEventCounter.EventType eventType : SecurityEventCounter.EventType.values()) {
            if (eventType.getCategory() == null) {
                long count = securityEventCounter.getCount(eventType);
                if (count > 0) {
                    LOGGER.debug("Success event %s has count %s", eventType.name(), count);
                }
            }
        }

        // Update counters based on current counts. Iterate the union of current and
        // baseline keys: after an external reset, event types disappear from the
        // current counts and would otherwise keep a stale baseline.
        Set<SecurityEventCounter.EventType> eventTypes = new HashSet<>(currentCounts.keySet());
        eventTypes.addAll(lastKnownCounts.keySet());

        for (SecurityEventCounter.EventType eventType : eventTypes) {
            long currentCount = currentCounts.getOrDefault(eventType, 0L);

            // Get the last known count for this event type
            long lastCount = lastKnownCounts.getOrDefault(eventType, 0L);

            // Calculate the delta
            long delta = currentCount - lastCount;

            // Only update if there's a change
            if (delta > 0) {
                // Get the counter for this event type
                Counter counter = counters.get(eventType.name());
                if (counter != null) {
                    // Increment the counter by the delta
                    counter.increment(delta);
                    LOGGER.debug("Updated counter for event type %s by %s (total: %s)", eventType.name(), delta, counter.count());
                } else {
                    LOGGER.warn(WARN.NO_MICROMETER_COUNTER_FOUND, eventType.name(), delta);
                }

                // Update the last known count
                lastKnownCounts.put(eventType, currentCount);
            } else if (delta < 0) {
                // The underlying counter was reset externally — re-baseline to the current
                // count so subsequent events are exported correctly instead of being ignored
                LOGGER.debug("Detected external reset for event type %s (delta %s), re-baselining to %s",
                        eventType.name(), delta, currentCount);
                lastKnownCounts.put(eventType, currentCount);
            }
        }
    }

}
