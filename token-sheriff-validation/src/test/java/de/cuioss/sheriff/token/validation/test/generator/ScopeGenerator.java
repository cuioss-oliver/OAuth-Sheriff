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
package de.cuioss.sheriff.token.validation.test.generator;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.tools.string.MoreStrings;
import de.cuioss.tools.string.Splitter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Generator for OAuth/OIDC scopes.
 * Generates a string with space-separated scopes, where "openid" is always included.
 */
public class ScopeGenerator implements TypedGenerator<String> {

    private static final String OPENID_SCOPE = "openid";
    private static final List<String> COMMON_SCOPES = List.of(
            "email", "profile", "offline_access", "address", "phone", "groups", "roles", "custom_scope1", "user/read"
    );

    private final int minAdditionalScopes;
    private final int maxAdditionalScopes;

    /**
     * Constructor with default min and max additional scopes (0-3).
     */
    public ScopeGenerator() {
        this(0, 3);
    }

    /**
     * Constructor with custom min and max additional scopes.
     *
     * @param minAdditionalScopes minimum number of additional scopes (besides "openid")
     * @param maxAdditionalScopes maximum number of additional scopes (besides "openid")
     */
    public ScopeGenerator(int minAdditionalScopes, int maxAdditionalScopes) {
        if (minAdditionalScopes < 0) {
            throw new IllegalArgumentException("minAdditionalScopes must be >= 0");
        }
        if (maxAdditionalScopes < minAdditionalScopes) {
            throw new IllegalArgumentException("maxAdditionalScopes must be >= minAdditionalScopes");
        }
        this.minAdditionalScopes = minAdditionalScopes;
        this.maxAdditionalScopes = maxAdditionalScopes;
    }

    @Override
    public String next() {
        List<String> scopes = new ArrayList<>();
        // Always include "openid"
        scopes.add(OPENID_SCOPE);

        // Add random number of additional scopes
        int additionalScopesCount = Generators.integers(minAdditionalScopes, maxAdditionalScopes).next();
        if (additionalScopesCount > 0) {
            // Shuffle and take a subset of common scopes
            List<String> shuffledScopes = new ArrayList<>(COMMON_SCOPES);
            Collections.shuffle(shuffledScopes);
            int count = Math.min(additionalScopesCount, shuffledScopes.size());
            scopes.addAll(shuffledScopes.subList(0, count));

            // If we need more scopes than the common ones, generate random ones
            if (additionalScopesCount > count) {
                for (int i = 0; i < additionalScopesCount - count; i++) {
                    scopes.add(Generators.letterStrings(3, 10).next());
                }
            }
        }

        // Join scopes with spaces
        return String.join(" ", scopes);
    }

    /**
     * Splits a string of scopes into a collection of individual scopes.
     *
     * @param scopes the string containing space-separated scopes
     * @return a collection of individual scopes
     */
    public static Collection<String> splitScopes(String scopes) {
        return Splitter.on(' ').splitToList(MoreStrings.nullToEmpty(scopes));
    }
}