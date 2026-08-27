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
 * Generator for OAuth/OIDC roles.
 * Generates a Set of role strings.
 */
public class RoleGenerator implements TypedGenerator<Set<String>> {

    private static final List<String> COMMON_ROLES = List.of(
            "reader", "writer", "admin", "user", "manager", "editor", "viewer", "gambler"
    );

    private final int minRoles;
    private final int maxRoles;

    /**
     * Constructor with default min and max roles (1-3).
     */
    public RoleGenerator() {
        this(1, 3);
    }

    /**
     * Constructor with custom min and max roles.
     *
     * @param minRoles minimum number of roles
     * @param maxRoles maximum number of roles
     */
    public RoleGenerator(int minRoles, int maxRoles) {
        if (minRoles < 0) {
            throw new IllegalArgumentException("minRoles must be >= 0");
        }
        if (maxRoles < minRoles) {
            throw new IllegalArgumentException("maxRoles must be >= minRoles");
        }
        this.minRoles = minRoles;
        this.maxRoles = maxRoles;
    }

    @Override
    public Set<String> next() {
        Set<String> roles = new HashSet<>();

        // Determine how many roles to generate
        int roleCount = Generators.integers(minRoles, maxRoles).next();
        if (roleCount == 0) {
            return roles;
        }

        // Shuffle and take a subset of common roles
        List<String> shuffledRoles = new ArrayList<>(COMMON_ROLES);
        Collections.shuffle(shuffledRoles);
        int count = Math.min(roleCount, shuffledRoles.size());
        roles.addAll(shuffledRoles.subList(0, count));

        // If we need more roles than the common ones, generate random ones
        if (roleCount > count) {
            for (int i = 0; i < roleCount - count; i++) {
                roles.add(Generators.letterStrings(3, 10).next());
            }
        }

        return roles;
    }
}