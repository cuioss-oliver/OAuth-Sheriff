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
import de.cuioss.tools.logging.CuiLogger;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import static de.cuioss.sheriff.token.quarkus.TokenSheriffQuarkusLogMessages.INFO;

/**
 * CDI registry for {@link DiscoverableTokenValidationRule} beans.
 * <p>
 * This registry collects all CDI-discovered {@link DiscoverableTokenValidationRule} beans,
 * filters out disabled rules, sorts by priority, and provides the ordered list
 * of {@link TokenValidationRule} instances for the validation pipeline.
 * </p>
 *
 * @since 1.0
 * @see DiscoverableTokenValidationRule
 */
@ApplicationScoped
public class TokenValidationRuleRegistry {

    private static final CuiLogger LOGGER = new CuiLogger(TokenValidationRuleRegistry.class);

    private final Instance<DiscoverableTokenValidationRule> discoveredRules;
    private List<TokenValidationRule> registeredRules;

    /**
     * Creates a new TokenValidationRuleRegistry with CDI-discovered rules.
     *
     * @param discoveredRules the CDI-managed instances of {@link DiscoverableTokenValidationRule}
     */
    public TokenValidationRuleRegistry(Instance<DiscoverableTokenValidationRule> discoveredRules) {
        this.discoveredRules = discoveredRules;
    }

    /**
     * Initializes the registry by collecting all enabled rules and sorting by priority.
     */
    @PostConstruct
    void init() {
        registeredRules = Collections.unmodifiableList(
                discoveredRules.stream()
                        .filter(rule -> {
                            if (rule.isEnabled()) {
                                return true;
                            }
                            LOGGER.debug("Skipping disabled token validation rule: %s",
                                    rule.getClass().getSimpleName());
                            return false;
                        })
                        .sorted(Comparator.comparingInt(DiscoverableTokenValidationRule::getPriority))
                        .map(DiscoverableTokenValidationRule::getRule)
                        .toList());

        if (registeredRules.isEmpty()) {
            LOGGER.info(INFO.NO_CUSTOM_VALIDATION_RULES_DISCOVERED);
        } else {
            LOGGER.info(INFO.VALIDATION_RULE_REGISTRY_INITIALIZED, registeredRules.size());
        }
    }

    /**
     * Returns the ordered list of registered validation rules.
     * <p>
     * Rules are sorted by priority (lower value first) and the list is unmodifiable.
     * </p>
     *
     * @return an unmodifiable list of registered validation rules
     */
    public List<TokenValidationRule> getValidationRules() {
        return registeredRules;
    }
}
