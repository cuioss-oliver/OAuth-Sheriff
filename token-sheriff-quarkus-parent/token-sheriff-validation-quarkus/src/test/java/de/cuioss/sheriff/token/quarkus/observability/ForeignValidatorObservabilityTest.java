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
package de.cuioss.sheriff.token.quarkus.observability;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.quarkus.health.JwksEndpointHealthCheck;
import de.cuioss.sheriff.token.quarkus.health.TokenValidatorHealthCheck;
import de.cuioss.sheriff.token.quarkus.metrics.JwtMetricsCollector;
import de.cuioss.sheriff.token.quarkus.runtime.TokenSheriffDevUIRuntimeService;
import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.ClaimControlParameter;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Alternative;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;
import jakarta.inject.Qualifier;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Liveness;
import org.eclipse.microprofile.health.Readiness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Container-level regression test for the embedder scenario reported in issue #641: the
 * {@code sheriff.token.issuers.*} namespace is empty and the application supplies its own
 * differently-qualified {@link TokenValidator}.
 * <p>
 * Before the fix every observability bean injected {@code TokenValidatorProducer}'s by-products,
 * which forced that producer's {@code @PostConstruct init()} to run and throw
 * {@code IllegalStateException("No issuer configurations found in properties")} — liveness and
 * readiness reported {@code DOWN}, the scheduled metrics collector threw on every tick, and every
 * DevUI JSON-RPC call threw.
 * <p>
 * The assertions here run against the container's own wiring rather than hand-constructed beans, so
 * they exercise the real injection points. The resolver reporting
 * {@link ObservedValidatorResolver.Outcome#EXTERNAL_VALIDATOR} is the structural evidence that the
 * extension's own producer was never instantiated: had it been, the resolution would have failed
 * with that {@code IllegalStateException} instead of degrading honestly.
 */
@QuarkusTest
@TestProfile(ForeignValidatorObservabilityTest.ForeignValidatorProfile.class)
@EnableTestLogger
@DisplayName("Foreign TokenValidator observability")
class ForeignValidatorObservabilityTest {

    /**
     * Mirrors an embedder's own qualifier (e.g. API Sheriff's {@code @GatewayValidator}).
     */
    @Qualifier
    @Retention(RetentionPolicy.RUNTIME)
    public @interface GatewayValidator {
    }

    /**
     * Test-only producer of a differently-qualified {@link TokenValidator}. It carries no
     * {@code @Priority}: a prioritized alternative is enabled GLOBALLY, which would leak this second
     * validator bean into every other test's application. Enabling it solely through
     * {@link ForeignValidatorProfile#getEnabledAlternatives()} keeps it scoped to this profile.
     */
    @Alternative
    @ApplicationScoped
    public static class ForeignValidatorProducer {

        @Produces
        @ApplicationScoped
        @GatewayValidator
        TokenValidator gatewayValidator() {
            TestTokenHolder tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN,
                    ClaimControlParameter.defaultForTokenType(TokenType.ACCESS_TOKEN));
            return TokenValidator.builder()
                    .parserConfig(ParserConfig.builder().build())
                    .issuerConfig(tokenHolder.getIssuerConfig())
                    .build();
        }
    }

    /**
     * Supplies no {@code sheriff.token.issuers.*} property at all and enables the foreign producer.
     */
    public static class ForeignValidatorProfile implements QuarkusTestProfile {

        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of();
        }

        @Override
        public Set<Class<?>> getEnabledAlternatives() {
            return Set.of(ForeignValidatorProducer.class);
        }
    }

    @Inject
    ObservedValidatorResolver resolver;

    @Inject
    @GatewayValidator
    TokenValidator foreignValidator;

    @Inject
    @Liveness
    TokenValidatorHealthCheck livenessCheck;

    @Inject
    @Readiness
    JwksEndpointHealthCheck readinessCheck;

    @Inject
    JwtMetricsCollector metricsCollector;

    @Inject
    TokenSheriffDevUIRuntimeService devUiService;

    @Test
    @DisplayName("resolves the foreign validator without instantiating the extension's producer")
    void resolvesForeignValidator() {
        assertAll("foreign validator resolution",
                () -> assertEquals(ObservedValidatorResolver.Outcome.EXTERNAL_VALIDATOR, resolver.outcome(),
                        "An empty namespace plus one foreign validator must resolve to EXTERNAL_VALIDATOR"),
                () -> assertSame(foreignValidator, resolver.observedValidator().orElseThrow(),
                        "The foreign validator must be the observation target"),
                () -> assertTrue(resolver.observedIssuerConfigs().isEmpty(),
                        "A foreign validator exposes no issuer configurations"),
                () -> assertTrue(resolver.observedParserConfig().isEmpty(),
                        "A foreign validator exposes no parser configuration"));
    }

    @Test
    @DisplayName("liveness reports UP with the external-validator marker instead of DOWN")
    void livenessReportsUp() {
        HealthCheckResponse response = livenessCheck.call();

        assertAll("liveness",
                () -> assertEquals(HealthCheckResponse.Status.UP, response.getStatus(),
                        "Liveness must not report DOWN for an embedder-supplied validator"),
                () -> assertEquals("observing external validator",
                        response.getData().orElseThrow().get("status"),
                        "status must name the external-validator outcome"));
    }

    @Test
    @DisplayName("readiness reports UP with zero checked endpoints instead of DOWN")
    void readinessReportsUp() {
        HealthCheckResponse response = readinessCheck.call();

        Map<String, Object> data = response.getData().orElseThrow();
        assertAll("readiness",
                () -> assertEquals(HealthCheckResponse.Status.UP, response.getStatus(),
                        "Readiness must not hold the application out of the load balancer"),
                () -> assertEquals(0, ((Number) data.get("checkedEndpoints")).intValue(),
                        "A foreign validator exposes no JWKS endpoints to probe"),
                () -> assertEquals("EXTERNAL_VALIDATOR", data.get("readiness"),
                        "readiness must name the external-validator outcome"));
    }

    @Test
    @DisplayName("the scheduled metrics tick runs without throwing when an external validator is in use")
    void metricsTickDoesNotThrow() {
        assertDoesNotThrow(metricsCollector::updateCounters,
                "The scheduled tick threw on every interval before the fix");
    }

    @Test
    @DisplayName("the collector's counter source is the foreign validator's SecurityEventCounter")
    void collectorObservesForeignCounters() {
        // The collector reads getSecurityEventCounter() off the resolver's observed validator, so
        // establishing that this container's resolution points at the foreign validator's own counter
        // is what proves the collector exports the validator in use. The Micrometer delta/export
        // mechanics on top of that counter are asserted deterministically in JwtMetricsCollectorTest
        // against a local SimpleMeterRegistry — the injected registry is a composite with no child
        // registry in this module's test scope, so its counters are permanent no-ops.
        SecurityEventCounter observedCounter = resolver.observedValidator().orElseThrow()
                .getSecurityEventCounter();
        SecurityEventCounter.EventType eventType = SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED;
        long before = observedCounter.getCount(eventType);

        foreignValidator.getSecurityEventCounter().increment(eventType);

        assertAll("observed counter",
                () -> assertSame(foreignValidator.getSecurityEventCounter(), observedCounter,
                        "The collector must read the foreign validator's own SecurityEventCounter"),
                () -> assertEquals(before + 1, observedCounter.getCount(eventType),
                        "An event recorded on the foreign validator must be visible to the collector"));
    }

    @Test
    @DisplayName("every DevUI JSON-RPC method returns the external-validator view state without throwing")
    void devUiReportsExternalValidatorViewState() {
        Map<String, Object> validationStatus = assertDoesNotThrow(devUiService::getValidationStatus);
        Map<String, Object> jwksStatus = assertDoesNotThrow(devUiService::getJwksStatus);
        Map<String, Object> configuration = assertDoesNotThrow(devUiService::getConfiguration);
        Map<String, Object> health = assertDoesNotThrow(devUiService::getHealthInfo);
        Map<String, Object> validation = assertDoesNotThrow(() -> devUiService.validateToken("not-a-jwt"));

        @SuppressWarnings("unchecked")
        Map<String, Object> parser = (Map<String, Object>) configuration.get("parser");
        @SuppressWarnings("unchecked")
        Map<String, Object> httpJwksLoader = (Map<String, Object>) configuration.get("httpJwksLoader");

        assertAll("DevUI view state",
                () -> assertEquals("ACTIVE", validationStatus.get("status"),
                        "A foreign validator is still an active validator"),
                () -> assertEquals("EXTERNAL_VALIDATOR", jwksStatus.get("status"),
                        "JWKS status must name the external-validator outcome"),
                () -> assertEquals("unavailable (external validator)", parser.get("status"),
                        "The parser section must carry the unavailability marker"),
                () -> assertEquals("unavailable (external validator)", httpJwksLoader.get("sizeLimit"),
                        "sizeLimit is the symmetric peer and carries the same marker"),
                () -> assertEquals("UP", health.get("healthStatus"),
                        "Health stays UP while a validator is observable"),
                () -> assertEquals(false, validation.get("valid"),
                        "A malformed token is rejected rather than throwing"));
    }
}
