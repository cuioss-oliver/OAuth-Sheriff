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

import java.util.*;

/**
 * Generator for OAuth/OIDC groups.
 * Generates a Set of group strings.
 */
public class GroupGenerator implements TypedGenerator<Set<String>> {

    private static final List<String> COMMON_GROUPS = List.of(
            "employees", "contractors", "admins", "developers", "testers", "managers",
            "support", "sales", "marketing", "finance", "hr", "it"
    );

    private final int minGroups;
    private final int maxGroups;

    /**
     * Constructor with default min and max groups (1-3).
     */
    public GroupGenerator() {
        this(1, 3);
    }

    /**
     * Constructor with custom min and max groups.
     *
     * @param minGroups minimum number of groups
     * @param maxGroups maximum number of groups
     */
    public GroupGenerator(int minGroups, int maxGroups) {
        if (minGroups < 0) {
            throw new IllegalArgumentException("minGroups must be >= 0");
        }
        if (maxGroups < minGroups) {
            throw new IllegalArgumentException("maxGroups must be >= minGroups");
        }
        this.minGroups = minGroups;
        this.maxGroups = maxGroups;
    }

    @Override
    public Set<String> next() {
        Set<String> groups = new HashSet<>();

        // Determine how many groups to generate
        int groupCount = Generators.integers(minGroups, maxGroups).next();
        if (groupCount == 0) {
            return groups;
        }

        // Shuffle and take a subset of common groups
        List<String> shuffledGroups = new ArrayList<>(COMMON_GROUPS);
        Collections.shuffle(shuffledGroups);
        int count = Math.min(groupCount, shuffledGroups.size());
        groups.addAll(shuffledGroups.subList(0, count));

        // If we need more groups than the common ones, generate random ones
        if (groupCount > count) {
            for (int i = 0; i < groupCount - count; i++) {
                groups.add(Generators.letterStrings(3, 10).next());
            }
        }

        return groups;
    }
}