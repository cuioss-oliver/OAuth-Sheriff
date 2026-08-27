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
package de.cuioss.sheriff.token.integration;

import de.cuioss.sheriff.token.integration.TestRealm.Capability;
import de.cuioss.tools.logging.CuiLogger;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;

/**
 * Shared provider sources for parameterized integration tests.
 * <p>
 * <b>Adding a new IDP</b> requires exactly one change here: add a
 * {@link ProviderRegistration} entry to {@link #PROVIDER_REGISTRY}.
 * Everything else (capability filtering, INFO logging for skipped providers,
 * test parameterization) follows automatically.
 * <p>
 * Maven profiles control IDP availability via system properties passed to
 * the failsafe-forked JVM (e.g. {@code -Ddex.enabled=true}).
 */
public final class TestProviders {

    private static final CuiLogger LOGGER = new CuiLogger(TestProviders.class);

    /**
     * Registry of all IDPs. Each entry maps a system-property gate to a
     * {@link TestRealm} factory. Providers whose system property is absent
     * or {@code false} are not included in the provider list.
     * <p>
     * A {@code null} system property means "always enabled" (e.g. Keycloak).
     */
    private static final List<ProviderRegistration> PROVIDER_REGISTRY = List.of(
            // Keycloak — always available
            new ProviderRegistration(null, TestRealm::createIntegrationRealm),
            new ProviderRegistration(null, TestRealm::createBenchmarkRealm),
            // Dex — only when multi-idp-tests profile is active
            new ProviderRegistration("dex.enabled", TestRealm::createDexProvider),
            // Zitadel — only when multi-idp-tests profile is active
            new ProviderRegistration("zitadel.enabled", TestRealm::createZitadelProvider)
    );

    private TestProviders() {
        // utility class
    }

    /**
     * All available OIDC providers based on active system properties.
     * Providers whose gate property is absent or false are excluded.
     * <p>
     * If a provider is enabled but unreachable, {@code obtainValidToken()} will
     * fail loudly (no silent skip, no {@code @EnabledIf}).
     */
    public static Stream<TestRealm> allProviders() {
        var providers = new ArrayList<TestRealm>();
        for (var reg : PROVIDER_REGISTRY) {
            if (reg.isEnabled()) {
                providers.add(reg.factory.get());
            }
        }
        return providers.stream();
    }

    /**
     * Returns providers that support <em>all</em> of the given capabilities.
     * Providers missing any required capability are skipped with an INFO log.
     *
     * @param required capabilities the test needs
     * @return stream of matching providers (may be empty)
     */
    public static Stream<TestRealm> withCapabilities(Capability... required) {
        Set<Capability> requiredSet = Set.of(required);
        List<TestRealm> all = allProviders().toList();
        List<TestRealm> matching = new ArrayList<>();

        for (TestRealm realm : all) {
            if (realm.hasAllCapabilities(required)) {
                matching.add(realm);
            } else {
                LOGGER.info("Skipping %s — missing capabilities: %s (has: %s)",
                        realm, requiredSet, realm.getCapabilities());
            }
        }
        return matching.stream();
    }

    // === Convenience method sources (referenced by @MethodSource in specs) ===

    /**
     * Providers that support bearer auth with roles, groups, and custom scopes.
     */
    public static Stream<TestRealm> bearerAuthProviders() {
        return withCapabilities(Capability.ROLES, Capability.GROUPS, Capability.CUSTOM_SCOPES);
    }

    /**
     * Providers that support the {@code offline_access} scope for refresh tokens.
     */
    public static Stream<TestRealm> offlineAccessProviders() {
        return withCapabilities(Capability.OFFLINE_ACCESS);
    }

    /**
     * Providers whose access tokens are JWTs (not opaque).
     */
    public static Stream<TestRealm> jwtAccessTokenProviders() {
        return withCapabilities(Capability.JWT_ACCESS_TOKENS);
    }

    /**
     * Providers that support role claims in bearer tokens.
     * Includes Keycloak and Zitadel but not Dex (no roles support).
     */
    public static Stream<TestRealm> rolesProviders() {
        return withCapabilities(Capability.ROLES, Capability.JWT_ACCESS_TOKENS);
    }

    /**
     * Providers that support group claims in bearer tokens.
     * Includes Keycloak, Dex, and Zitadel.
     */
    public static Stream<TestRealm> groupsProviders() {
        return withCapabilities(Capability.GROUPS, Capability.ROLES, Capability.JWT_ACCESS_TOKENS);
    }

    /**
     * Providers that support custom scopes (e.g. "read") in bearer tokens.
     * Only Keycloak — Dex rejects unknown scopes, Zitadel only accepts URN scopes.
     */
    public static Stream<TestRealm> customScopesProviders() {
        return withCapabilities(Capability.CUSTOM_SCOPES, Capability.JWT_ACCESS_TOKENS);
    }

    /**
     * Associates a system-property gate with a {@link TestRealm} factory.
     *
     * @param systemProperty system property that must be {@code true} to enable
     *                       this provider, or {@code null} for always-enabled
     * @param factory        creates the {@link TestRealm} instance
     */
    private record ProviderRegistration(String systemProperty, Supplier<TestRealm> factory) {
        boolean isEnabled() {
            return systemProperty == null || Boolean.getBoolean(systemProperty);
        }
    }
}
