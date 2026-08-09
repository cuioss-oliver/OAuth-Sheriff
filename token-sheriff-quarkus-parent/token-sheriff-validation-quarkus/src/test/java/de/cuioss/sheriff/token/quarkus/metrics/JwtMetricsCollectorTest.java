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

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter.EventType;
import de.cuioss.sheriff.token.commons.metrics.MetricIdentifier;
import de.cuioss.sheriff.token.quarkus.config.JwtTestProfile;
import de.cuioss.sheriff.token.quarkus.observability.ObservedValidatorResolver;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link JwtMetricsCollector}.
 * <p>
 * This test class verifies that the metrics collector properly initializes and registers
 * metrics for all security event types. It also tests that the collector correctly updates
 * metrics when security events occur.
 * <p>
 * The tests cover:
 * <ul>
 *   <li>Initialization of metrics for all event types</li>
 *   <li>Recording and updating metrics for security events</li>
 * </ul>
 */
@QuarkusTest
@TestProfile(JwtTestProfile.class)
@EnableTestLogger
class JwtMetricsCollectorTest {

    @Inject
    TokenValidator tokenValidator;

    @Inject
    MeterRegistry registry;

    @Inject
    JwtMetricsCollector metricsCollector;

    @Test
    @DisplayName("Should initialize metrics for all event types")
    void shouldInitializeMetrics() {
        // Ensure collector is properly initialized
        assertNotNull(metricsCollector);

        // Logging verification is handled in separate unit test

        // Get counters from registry - both error and success counters
        Collection<Counter> errorCounters = registry.find(MetricIdentifier.VALIDATION.ERRORS).counters();
        Collection<Counter> successCounters = registry.find(MetricIdentifier.VALIDATION.SUCCESS).counters();

        // Verify counters exist for all event types
        assertFalse(errorCounters.isEmpty(), "Should have registered error counters");
        assertFalse(successCounters.isEmpty(), "Should have registered success counters");

        // Verify all event types have corresponding counters
        for (EventType eventType : SecurityEventCounter.EventType.values()) {
            if (eventType.getCategory() == null) {
                // Success events should be in success counters
                boolean hasCounter = successCounters.stream()
                        .anyMatch(counter -> Objects.equals(counter.getId().getTag("event_type"), eventType.name()));
                assertTrue(hasCounter, "Should have success counter for event type: " + eventType.name());
            } else {
                // Error events should be in error counters
                boolean hasCounter = errorCounters.stream()
                        .anyMatch(counter -> Objects.equals(counter.getId().getTag("event_type"), eventType.name()));
                assertTrue(hasCounter, "Should have error counter for event type: " + eventType.name());
            }
        }
    }

    @Test
    @DisplayName("Should record metrics for security events")
    void shouldHaveMetricsForSecurityEvents() {
        // Get the security event counter from the token validator
        SecurityEventCounter counter = tokenValidator.getSecurityEventCounter();
        assertNotNull(counter);

        // Record some events
        EventType testEventType = EventType.SIGNATURE_VALIDATION_FAILED;
        counter.increment(testEventType);
        counter.increment(testEventType);

        // Manually update counters (instead of waiting for scheduled update)
        metricsCollector.updateCounters();

        // Verify the metric exists with the correct tags
        boolean hasMetric = !registry.find(MetricIdentifier.VALIDATION.ERRORS)
                .tag("event_type", testEventType.name())
                .tag("result", "failure")
                .tag("category", "INVALID_SIGNATURE")
                .counters().isEmpty();

        assertTrue(hasMetric, "Should have metric for the event type");
    }


    @Test
    @DisplayName("Should re-baseline on external counter reset instead of losing events")
    void shouldRebaselineOnExternalCounterReset() {
        // Use a locally constructed collector with a SimpleMeterRegistry so counter
        // values can be asserted deterministically (the injected registry is a
        // composite and the scheduled update would interfere with delta assertions)
        SecurityEventCounter securityEventCounter = new SecurityEventCounter();
        SimpleMeterRegistry localRegistry = new SimpleMeterRegistry();
        JwtMetricsCollector localCollector = new JwtMetricsCollector(localRegistry, observing(securityEventCounter));
        localCollector.initialize();

        // Record some events and export them
        EventType testEventType = EventType.SIGNATURE_VALIDATION_FAILED;
        securityEventCounter.increment(testEventType);
        securityEventCounter.increment(testEventType);
        localCollector.updateCounters();

        Counter metricCounter = localRegistry.find(MetricIdentifier.VALIDATION.ERRORS)
                .tag("event_type", testEventType.name())
                .counter();
        assertNotNull(metricCounter, "Counter should exist");
        assertEquals(2.0, metricCounter.count(), "Both events should be exported");

        // External reset of the underlying monitor (inlined equivalent of the removed clear())
        securityEventCounter.reset();
        assertEquals(0, securityEventCounter.getCount(testEventType), "Security event counter should be reset");

        // Negative delta must not decrement the Micrometer counter, only reset the baseline
        localCollector.updateCounters();
        assertEquals(2.0, metricCounter.count(),
                "External reset must not change the cumulative Micrometer counter");

        // New events after the reset must be exported with the re-baselined delta
        securityEventCounter.increment(testEventType);
        localCollector.updateCounters();
        assertEquals(3.0, metricCounter.count(),
                "Only the single new event should be exported after the external reset");
    }

    @Test
    @DisplayName("Should export events recorded before initialization")
    void shouldExportEventsRecordedBeforeInitialization() {
        // Events counted before the collector initializes must not be dropped
        SecurityEventCounter preInitCounter = new SecurityEventCounter();
        EventType testEventType = EventType.SIGNATURE_VALIDATION_FAILED;
        preInitCounter.increment(testEventType);
        preInitCounter.increment(testEventType);

        SimpleMeterRegistry localRegistry = new SimpleMeterRegistry();
        JwtMetricsCollector localCollector = new JwtMetricsCollector(localRegistry, observing(preInitCounter));
        localCollector.initialize();

        Counter metricCounter = localRegistry.find(MetricIdentifier.VALIDATION.ERRORS)
                .tag("event_type", testEventType.name())
                .counter();
        assertNotNull(metricCounter, "Counter should exist");
        assertEquals(2.0, metricCounter.count(),
                "Pre-initialization events must be exported as deltas, not silently dropped");
    }

    @Test
    @DisplayName("Should go idle without throwing when no validator is observable")
    void shouldBeSilentNoOpWhenNothingObservable() {
        SimpleMeterRegistry localRegistry = new SimpleMeterRegistry();
        JwtMetricsCollector localCollector = new JwtMetricsCollector(localRegistry,
                new ObservedValidatorResolver(ObservedValidatorResolver.Outcome.NOT_CONFIGURED,
                        null, List.of(), null));

        assertDoesNotThrow(localCollector::initialize,
                "Initialization must register counters without touching a validator");
        assertDoesNotThrow(localCollector::updateCounters,
                "A scheduled tick must go idle instead of throwing when nothing is observable");

        Counter metricCounter = localRegistry.find(MetricIdentifier.VALIDATION.ERRORS)
                .tag("event_type", EventType.SIGNATURE_VALIDATION_FAILED.name())
                .counter();
        assertNotNull(metricCounter, "Counters are registered regardless of the resolution outcome");
        assertEquals(0.0, metricCounter.count(), "No event may be exported when nothing is observable");
    }

    @Test
    @DisplayName("Should re-baseline when the observed validator changes between ticks")
    void shouldRebaselineWhenObservedValidatorChanges() {
        EventType testEventType = EventType.SIGNATURE_VALIDATION_FAILED;
        SecurityEventCounter firstCounter = new SecurityEventCounter();
        firstCounter.increment(testEventType);

        SimpleMeterRegistry localRegistry = new SimpleMeterRegistry();
        SwitchableResolver resolver = new SwitchableResolver(observing(firstCounter));
        JwtMetricsCollector localCollector = new JwtMetricsCollector(localRegistry, resolver);
        localCollector.initialize();

        Counter metricCounter = localRegistry.find(MetricIdentifier.VALIDATION.ERRORS)
                .tag("event_type", testEventType.name())
                .counter();
        assertNotNull(metricCounter, "Counter should exist");
        assertEquals(1.0, metricCounter.count(), "The first validator's single event should be exported");

        // A different validator carrying a lower count must not be read against the old baseline
        SecurityEventCounter secondCounter = new SecurityEventCounter();
        secondCounter.increment(testEventType);
        resolver.switchTo(observing(secondCounter));
        localCollector.updateCounters();

        assertEquals(2.0, metricCounter.count(),
                "The new validator's event must be exported against a fresh baseline");
    }

    /**
     * A resolver whose delegate can be swapped, standing in for a validator that changes between
     * scheduled ticks.
     */
    private static final class SwitchableResolver extends ObservedValidatorResolver {

        private ObservedValidatorResolver delegate;

        SwitchableResolver(ObservedValidatorResolver delegate) {
            super(Outcome.NOT_CONFIGURED, null, List.of(), null);
            this.delegate = delegate;
        }

        void switchTo(ObservedValidatorResolver next) {
            this.delegate = next;
        }

        @Override
        public Outcome outcome() {
            return delegate.outcome();
        }

        @Override
        public Optional<TokenValidator> observedValidator() {
            return delegate.observedValidator();
        }
    }

    /**
     * Pins a resolver to a validator exposing the supplied security event counter.
     */
    private static ObservedValidatorResolver observing(SecurityEventCounter counter) {
        TokenValidator validator = createNiceMock(TokenValidator.class);
        expect(validator.getSecurityEventCounter()).andStubReturn(counter);
        replay(validator);
        return new ObservedValidatorResolver(ObservedValidatorResolver.Outcome.PROPERTY_CONFIGURED,
                validator, List.of(), null);
    }
}
