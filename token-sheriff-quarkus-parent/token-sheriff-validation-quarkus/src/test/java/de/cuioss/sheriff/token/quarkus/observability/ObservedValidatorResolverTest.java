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
package de.cuioss.sheriff.token.quarkus.observability;

import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.quarkus.config.JwtPropertyKeys;
import de.cuioss.sheriff.token.quarkus.producer.TokenValidatorProducer;
import de.cuioss.sheriff.token.quarkus.test.TestConfig;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import jakarta.enterprise.inject.Instance;
import jakarta.enterprise.inject.spi.Bean;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static de.cuioss.test.juli.LogAsserts.assertLogMessagePresentContaining;
import static org.easymock.EasyMock.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link ObservedValidatorResolver}, covering all four resolution branches without a
 * CDI container.
 */
@DisplayName("ObservedValidatorResolver")
@EnableTestLogger
class ObservedValidatorResolverTest {

    private static final String TEST_ISSUER = "test";

    /** Stand-in bean classes for embedder-supplied validators. */
    private static final class ForeignValidatorAlpha {
    }

    private static final class ForeignValidatorBeta {
    }

    @Nested
    @DisplayName("Populated issuer namespace")
    class PropertyConfigured {

        @Test
        @DisplayName("should observe the extension's own produced validator, issuer configs and parser config")
        void shouldObserveProducedValidator() {
            TokenValidator produced = createNiceMock(TokenValidator.class);
            RecordingHandle producerHandle = new RecordingHandle(TokenValidatorProducer.class, produced);
            List<IssuerConfig> producedIssuerConfigs = new ArrayList<>();
            ParserConfig producedParserConfig = ParserConfig.builder().build();
            ObservedValidatorResolver resolver = new ObservedValidatorResolver(
                    configWithEnabledIssuer(),
                    validatorInstance(producerHandle),
                    valueInstance(producedIssuerConfigs),
                    valueInstance(producedParserConfig));

            assertAll("property-configured resolution",
                    () -> assertEquals(ObservedValidatorResolver.Outcome.PROPERTY_CONFIGURED, resolver.outcome(),
                            "Populated namespace must resolve to PROPERTY_CONFIGURED"),
                    () -> assertSame(produced, resolver.observedValidator().orElseThrow(),
                            "Observed validator must be the produced one"),
                    () -> assertSame(producedIssuerConfigs, resolver.observedIssuerConfigs(),
                            "Observed issuer configs must be the produced list"),
                    () -> assertSame(producedParserConfig, resolver.observedParserConfig().orElseThrow(),
                            "Observed parser config must be the produced one"));
        }
    }

    @Nested
    @DisplayName("Empty issuer namespace")
    class EmptyNamespace {

        @Test
        @DisplayName("should observe the single foreign validator without instantiating the extension's producer")
        void shouldObserveSingleForeignValidator() {
            TokenValidator foreign = createNiceMock(TokenValidator.class);
            RecordingHandle producerHandle = new RecordingHandle(TokenValidatorProducer.class,
                    createNiceMock(TokenValidator.class));
            RecordingHandle foreignHandle = new RecordingHandle(ForeignValidatorAlpha.class, foreign);
            ObservedValidatorResolver resolver = resolverOver(producerHandle, foreignHandle);

            assertAll("external-validator resolution",
                    () -> assertEquals(ObservedValidatorResolver.Outcome.EXTERNAL_VALIDATOR, resolver.outcome(),
                            "A single foreign validator must resolve to EXTERNAL_VALIDATOR"),
                    () -> assertSame(foreign, resolver.observedValidator().orElseThrow(),
                            "Observed validator must be the foreign one"),
                    () -> assertTrue(resolver.observedIssuerConfigs().isEmpty(),
                            "A foreign validator exposes no issuer configurations"),
                    () -> assertTrue(resolver.observedParserConfig().isEmpty(),
                            "A foreign validator exposes no parser configuration"),
                    () -> assertTrue(foreignHandle.wasGetInvoked(),
                            "Positive control: the foreign handle must be resolved"),
                    () -> assertFalse(producerHandle.wasGetInvoked(),
                            "Negative control: the TokenValidatorProducer handle must never be get()-ed"));
        }

        @Test
        @DisplayName("should report NOT_CONFIGURED and warn when several foreign validators exist")
        void shouldRefuseToGuessBetweenForeignValidators() {
            RecordingHandle producerHandle = new RecordingHandle(TokenValidatorProducer.class,
                    createNiceMock(TokenValidator.class));
            RecordingHandle alpha = new RecordingHandle(ForeignValidatorAlpha.class,
                    createNiceMock(TokenValidator.class));
            RecordingHandle beta = new RecordingHandle(ForeignValidatorBeta.class,
                    createNiceMock(TokenValidator.class));
            ObservedValidatorResolver resolver = resolverOver(producerHandle, alpha, beta);

            ObservedValidatorResolver.Outcome outcome = resolver.outcome();

            assertAll("ambiguous resolution",
                    () -> assertEquals(ObservedValidatorResolver.Outcome.NOT_CONFIGURED, outcome,
                            "Ambiguous foreign validators must resolve to NOT_CONFIGURED"),
                    () -> assertTrue(resolver.observedValidator().isEmpty(),
                            "No validator may be observed when the choice is ambiguous"),
                    () -> assertFalse(producerHandle.wasGetInvoked(),
                            "Negative control: the TokenValidatorProducer handle must never be get()-ed"),
                    () -> assertFalse(alpha.wasGetInvoked(),
                            "No candidate may be instantiated when the choice is ambiguous"),
                    () -> assertFalse(beta.wasGetInvoked(),
                            "No candidate may be instantiated when the choice is ambiguous"));
            assertLogMessagePresentContaining(TestLogLevel.WARN, ForeignValidatorAlpha.class.getName());
            assertLogMessagePresentContaining(TestLogLevel.WARN, ForeignValidatorBeta.class.getName());
        }

        @Test
        @DisplayName("should warn about an ambiguity that only appears after an earlier zero-candidate probe")
        void shouldWarnOnAmbiguityAfterEarlierNotConfiguredProbe() {
            List<Instance.Handle<TokenValidator>> handles = new ArrayList<>();
            handles.add(new RecordingHandle(TokenValidatorProducer.class, createNiceMock(TokenValidator.class)));
            ObservedValidatorResolver resolver = new ObservedValidatorResolver(
                    new TestConfig(Map.of()),
                    validatorInstance(handles),
                    valueInstance(new ArrayList<>()),
                    valueInstance(ParserConfig.builder().build()));

            assertEquals(ObservedValidatorResolver.Outcome.NOT_CONFIGURED, resolver.outcome(),
                    "Nothing is observable on the first probe");
            handles.add(new RecordingHandle(ForeignValidatorAlpha.class, createNiceMock(TokenValidator.class)));
            handles.add(new RecordingHandle(ForeignValidatorBeta.class, createNiceMock(TokenValidator.class)));

            assertEquals(ObservedValidatorResolver.Outcome.NOT_CONFIGURED, resolver.outcome(),
                    "Ambiguous foreign validators must still resolve to NOT_CONFIGURED");
            // The outcome never transitioned, so an outcome-gated warning would stay silent here
            assertLogMessagePresentContaining(TestLogLevel.WARN, ForeignValidatorAlpha.class.getName());
            assertLogMessagePresentContaining(TestLogLevel.WARN, ForeignValidatorBeta.class.getName());
        }

        @Test
        @DisplayName("should report NOT_CONFIGURED when no validator exists at all")
        void shouldReportNotConfiguredWithoutAnyValidator() {
            RecordingHandle producerHandle = new RecordingHandle(TokenValidatorProducer.class,
                    createNiceMock(TokenValidator.class));
            ObservedValidatorResolver resolver = resolverOver(producerHandle);

            assertAll("unconfigured resolution",
                    () -> assertEquals(ObservedValidatorResolver.Outcome.NOT_CONFIGURED, resolver.outcome(),
                            "An empty namespace with no foreign validator must resolve to NOT_CONFIGURED"),
                    () -> assertTrue(resolver.observedValidator().isEmpty(),
                            "No validator may be observed"),
                    () -> assertTrue(resolver.observedIssuerConfigs().isEmpty(),
                            "No issuer configuration may be observed"),
                    () -> assertTrue(resolver.observedParserConfig().isEmpty(),
                            "No parser configuration may be observed"),
                    () -> assertFalse(producerHandle.wasGetInvoked(),
                            "Negative control: the TokenValidatorProducer handle must never be get()-ed"));
        }

        @Test
        @DisplayName("should pick up a validator that only becomes available after the first probe")
        void shouldReResolveWhileNotConfigured() {
            TokenValidator lateArrival = createNiceMock(TokenValidator.class);
            List<Instance.Handle<TokenValidator>> handles = new ArrayList<>();
            handles.add(new RecordingHandle(TokenValidatorProducer.class, createNiceMock(TokenValidator.class)));
            ObservedValidatorResolver resolver = new ObservedValidatorResolver(
                    new TestConfig(Map.of()),
                    validatorInstance(handles),
                    valueInstance(new ArrayList<>()),
                    valueInstance(ParserConfig.builder().build()));

            assertEquals(ObservedValidatorResolver.Outcome.NOT_CONFIGURED, resolver.outcome(),
                    "Nothing is observable on the first probe");
            handles.add(new RecordingHandle(ForeignValidatorAlpha.class, lateArrival));

            assertAll("late-arriving validator",
                    () -> assertEquals(ObservedValidatorResolver.Outcome.EXTERNAL_VALIDATOR, resolver.outcome(),
                            "NOT_CONFIGURED must be re-resolved so a later validator is picked up"),
                    () -> assertSame(lateArrival, resolver.observedValidator().orElseThrow(),
                            "The late-arriving validator must become the observation target"));
        }
    }

    @Nested
    @DisplayName("Pinned resolution")
    class PinnedResolution {

        @Test
        @DisplayName("should report the pinned outcome without consulting CDI")
        void shouldReportPinnedOutcome() {
            TokenValidator validator = createNiceMock(TokenValidator.class);
            ObservedValidatorResolver resolver = new ObservedValidatorResolver(
                    ObservedValidatorResolver.Outcome.EXTERNAL_VALIDATOR, validator, List.of(), null);

            assertAll("pinned resolution",
                    () -> assertEquals(ObservedValidatorResolver.Outcome.EXTERNAL_VALIDATOR, resolver.outcome(),
                            "Pinned outcome must be reported verbatim"),
                    () -> assertSame(validator, resolver.observedValidator().orElseThrow(),
                            "Pinned validator must be reported verbatim"),
                    () -> assertTrue(resolver.observedIssuerConfigs().isEmpty(),
                            "Pinned issuer configs must be reported verbatim"),
                    () -> assertTrue(resolver.observedParserConfig().isEmpty(),
                            "Pinned parser config must be reported verbatim"));
        }

        @Test
        @DisplayName("should keep reporting NOT_CONFIGURED when pinned to it")
        void shouldNotReResolvePinnedNotConfigured() {
            ObservedValidatorResolver resolver = new ObservedValidatorResolver(
                    ObservedValidatorResolver.Outcome.NOT_CONFIGURED, null, List.of(), null);

            assertEquals(ObservedValidatorResolver.Outcome.NOT_CONFIGURED, resolver.outcome(),
                    "A pinned NOT_CONFIGURED must never trigger a CDI lookup");
            assertTrue(resolver.observedValidator().isEmpty(), "No validator may be observed");
        }
    }

    private static ObservedValidatorResolver resolverOver(RecordingHandle... handles) {
        return new ObservedValidatorResolver(
                new TestConfig(Map.of()),
                validatorInstance(List.of(handles)),
                valueInstance(new ArrayList<>()),
                valueInstance(ParserConfig.builder().build()));
    }

    private static Config configWithEnabledIssuer() {
        return new TestConfig(Map.of(
                JwtPropertyKeys.ISSUERS.ENABLED.formatted(TEST_ISSUER), "true",
                JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(TEST_ISSUER), "https://example.com"));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Instance<TokenValidator> validatorInstance(List<? extends Instance.Handle<TokenValidator>> handles) {
        Instance<TokenValidator> instance = createNiceMock(Instance.class);
        // The raw cast side-steps the wildcard capture on Instance#handles(); the recorded call is unaffected
        expect((Iterable) instance.handles()).andStubReturn(handles);
        replay(instance);
        return instance;
    }

    private static Instance<TokenValidator> validatorInstance(RecordingHandle handle) {
        return validatorInstance(List.of(handle));
    }

    @SuppressWarnings("unchecked")
    private static <T> Instance<T> valueInstance(T value) {
        Instance<T> instance = createNiceMock(Instance.class);
        expect(instance.get()).andStubReturn(value);
        replay(instance);
        return instance;
    }

    /**
     * A {@link Instance.Handle} test double that records whether {@link #get()} was ever invoked, so
     * the "the producer handle is never instantiated" invariant can be asserted directly.
     */
    private static final class RecordingHandle implements Instance.Handle<TokenValidator> {

        private final Bean<TokenValidator> bean;
        private final TokenValidator value;
        private boolean getInvoked;

        RecordingHandle(Class<?> beanClass, TokenValidator value) {
            this.bean = beanOf(beanClass);
            this.value = value;
        }

        @Override
        public TokenValidator get() {
            getInvoked = true;
            return value;
        }

        @Override
        public Bean<TokenValidator> getBean() {
            return bean;
        }

        @Override
        public void destroy() {
            // no-op: the double owns no contextual instance
        }

        @Override
        public void close() {
            // no-op: the double owns no contextual instance
        }

        boolean wasGetInvoked() {
            return getInvoked;
        }

        @SuppressWarnings({"unchecked", "rawtypes"})
        private static Bean<TokenValidator> beanOf(Class<?> beanClass) {
            Bean<TokenValidator> bean = createNiceMock(Bean.class);
            // The raw cast side-steps the wildcard capture on Bean#getBeanClass()
            expect((Class) bean.getBeanClass()).andStubReturn(beanClass);
            replay(bean);
            return bean;
        }
    }
}
