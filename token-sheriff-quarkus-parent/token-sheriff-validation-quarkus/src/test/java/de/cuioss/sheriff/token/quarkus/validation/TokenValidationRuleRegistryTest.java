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
package de.cuioss.sheriff.token.quarkus.validation;

import de.cuioss.sheriff.token.validation.pipeline.validator.TokenValidationRule;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import jakarta.enterprise.inject.Instance;
import jakarta.enterprise.util.TypeLiteral;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Iterator;
import java.util.List;
import java.util.stream.Stream;

import static de.cuioss.sheriff.token.quarkus.TokenSheriffQuarkusLogMessages.INFO;
import static de.cuioss.test.juli.LogAsserts.assertLogMessagePresent;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link TokenValidationRuleRegistry}.
 */
@DisplayName("TokenValidationRuleRegistry")
@EnableTestLogger
class TokenValidationRuleRegistryTest {

    private static final TokenValidationRule DUMMY_RULE = (token, context) -> {
        // no-op rule
    };

    @Test
    @DisplayName("should initialize with no rules")
    void shouldInitializeWithNoRules() {
        var registry = createRegistry(List.of());
        registry.init();

        assertTrue(registry.getValidationRules().isEmpty(), "Should have no registered rules");
        assertLogMessagePresent(TestLogLevel.INFO, INFO.NO_CUSTOM_VALIDATION_RULES_DISCOVERED.format());
    }

    @Test
    @DisplayName("should register single enabled rule")
    void shouldRegisterSingleEnabledRule() {
        var rule = createDiscoverableRule(DUMMY_RULE, true, 1000);
        var registry = createRegistry(List.of(rule));
        registry.init();

        assertEquals(1, registry.getValidationRules().size());
        assertSame(DUMMY_RULE, registry.getValidationRules().getFirst());
    }

    @Test
    @DisplayName("should filter out disabled rules")
    void shouldFilterOutDisabledRules() {
        TokenValidationRule enabledRule = (token, context) -> {
        };
        var enabled = createDiscoverableRule(enabledRule, true, 1000);
        var disabled = createDiscoverableRule(DUMMY_RULE, false, 1000);
        var registry = createRegistry(List.of(enabled, disabled));
        registry.init();

        assertEquals(1, registry.getValidationRules().size());
        assertSame(enabledRule, registry.getValidationRules().getFirst());
    }

    @Test
    @DisplayName("should sort rules by priority (lower first)")
    void shouldSortRulesByPriority() {
        TokenValidationRule highPriority = (token, context) -> {
        };
        TokenValidationRule lowPriority = (token, context) -> {
        };
        TokenValidationRule mediumPriority = (token, context) -> {
        };

        // Add in non-sorted order
        var rule1 = createDiscoverableRule(lowPriority, true, 2000);
        var rule2 = createDiscoverableRule(highPriority, true, 100);
        var rule3 = createDiscoverableRule(mediumPriority, true, 1000);
        var registry = createRegistry(List.of(rule1, rule2, rule3));
        registry.init();

        assertEquals(3, registry.getValidationRules().size());
        assertSame(highPriority, registry.getValidationRules().getFirst(), "Lowest priority value should be first");
        assertSame(mediumPriority, registry.getValidationRules().get(1));
        assertSame(lowPriority, registry.getValidationRules().get(2), "Highest priority value should be last");
    }

    @Test
    @DisplayName("should return unmodifiable list")
    void shouldReturnUnmodifiableList() {
        var rule = createDiscoverableRule(DUMMY_RULE, true, 1000);
        var registry = createRegistry(List.of(rule));
        registry.init();

        var rules = registry.getValidationRules();
        assertThrows(UnsupportedOperationException.class,
                () -> rules.add(DUMMY_RULE));
    }

    @Test
    @DisplayName("should log initialized message with rule count")
    void shouldLogInitializedMessage() {
        var rule = createDiscoverableRule(DUMMY_RULE, true, 1000);
        var registry = createRegistry(List.of(rule));
        registry.init();

        assertLogMessagePresent(TestLogLevel.INFO,
                INFO.VALIDATION_RULE_REGISTRY_INITIALIZED.format("1"));
    }

    @Test
    @DisplayName("should register multiple rules")
    void shouldRegisterMultipleRules() {
        TokenValidationRule rule1 = (token, context) -> {
        };
        TokenValidationRule rule2 = (token, context) -> {
        };
        var discoverable1 = createDiscoverableRule(rule1, true, 1000);
        var discoverable2 = createDiscoverableRule(rule2, true, 1000);
        var registry = createRegistry(List.of(discoverable1, discoverable2));
        registry.init();

        assertEquals(2, registry.getValidationRules().size());
    }

    private static TokenValidationRuleRegistry createRegistry(List<DiscoverableTokenValidationRule> rules) {
        return new TokenValidationRuleRegistry(new TestInstance(rules));
    }

    private static DiscoverableTokenValidationRule createDiscoverableRule(
            TokenValidationRule rule, boolean enabled, int priority) {
        return new DiscoverableTokenValidationRule() {
            @Override
            public TokenValidationRule getRule() {
                return rule;
            }

            @Override
            public boolean isEnabled() {
                return enabled;
            }

            @Override
            public int getPriority() {
                return priority;
            }
        };
    }

    /**
     * Minimal test implementation of {@link Instance} for unit testing without CDI.
     */
    private record TestInstance(List<DiscoverableTokenValidationRule> rules)
            implements Instance<DiscoverableTokenValidationRule> {

        @Override
        public Iterator<DiscoverableTokenValidationRule> iterator() {
            return rules.iterator();
        }

        @Override
        public Instance<DiscoverableTokenValidationRule> select(java.lang.annotation.Annotation... qualifiers) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <U extends DiscoverableTokenValidationRule> Instance<U> select(
                Class<U> subtype, java.lang.annotation.Annotation... qualifiers) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <U extends DiscoverableTokenValidationRule> Instance<U> select(
                TypeLiteral<U> subtype, java.lang.annotation.Annotation... qualifiers) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isUnsatisfied() {
            return rules.isEmpty();
        }

        @Override
        public boolean isAmbiguous() {
            return false;
        }

        @Override
        public void destroy(DiscoverableTokenValidationRule instance) {
            // no-op
        }

        @Override
        public Handle<DiscoverableTokenValidationRule> getHandle() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Iterable<? extends Handle<DiscoverableTokenValidationRule>> handles() {
            throw new UnsupportedOperationException();
        }

        @Override
        public DiscoverableTokenValidationRule get() {
            return rules.getFirst();
        }

        @Override
        public Stream<DiscoverableTokenValidationRule> stream() {
            return rules.stream();
        }

        @Override
        public boolean isResolvable() {
            return rules.size() == 1;
        }
    }
}
