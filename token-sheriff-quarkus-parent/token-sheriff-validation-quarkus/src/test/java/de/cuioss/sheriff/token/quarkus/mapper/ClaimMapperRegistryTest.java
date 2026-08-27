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
package de.cuioss.sheriff.token.quarkus.mapper;

import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.claim.mapper.ClaimMapper;
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
 * Tests for {@link ClaimMapperRegistry}.
 */
@DisplayName("ClaimMapperRegistry")
@EnableTestLogger
class ClaimMapperRegistryTest {

    private static final ClaimMapper DUMMY_MAPPER =
            (mapRepresentation, claimName) -> ClaimValue.forList("dummy", List.of());

    @Test
    @DisplayName("should initialize with no mappers")
    void shouldInitializeWithNoMappers() {
        var registry = createRegistry(List.of());
        registry.init();

        assertTrue(registry.getRegisteredClaimNames().isEmpty(), "Should have no registered claim names");
        assertTrue(registry.getMapper("roles").isEmpty(), "Should return empty for unregistered claim");
        assertLogMessagePresent(TestLogLevel.INFO, INFO.NO_CUSTOM_CLAIM_MAPPERS_DISCOVERED.format());
    }

    @Test
    @DisplayName("should register single enabled mapper")
    void shouldRegisterSingleEnabledMapper() {
        var mapper = createDiscoverableMapper("roles", DUMMY_MAPPER, true);
        var registry = createRegistry(List.of(mapper));
        registry.init();

        assertEquals(1, registry.getRegisteredClaimNames().size());
        assertTrue(registry.getRegisteredClaimNames().contains("roles"));
        assertTrue(registry.getMapper("roles").isPresent());
        assertSame(DUMMY_MAPPER, registry.getMapper("roles").get());
    }

    @Test
    @DisplayName("should register multiple mappers for different claims")
    void shouldRegisterMultipleMappersForDifferentClaims() {
        ClaimMapper rolesMapper = (mapRepresentation, claimName) ->
                ClaimValue.forList("roles", List.of());
        ClaimMapper groupsMapper = (mapRepresentation, claimName) ->
                ClaimValue.forList("groups", List.of());

        var mapper1 = createDiscoverableMapper("roles", rolesMapper, true);
        var mapper2 = createDiscoverableMapper("groups", groupsMapper, true);
        var registry = createRegistry(List.of(mapper1, mapper2));
        registry.init();

        assertEquals(2, registry.getRegisteredClaimNames().size());
        assertTrue(registry.getRegisteredClaimNames().contains("roles"));
        assertTrue(registry.getRegisteredClaimNames().contains("groups"));
        assertSame(rolesMapper, registry.getMapper("roles").get());
        assertSame(groupsMapper, registry.getMapper("groups").get());
    }

    @Test
    @DisplayName("should fail fast on duplicate claim names")
    void shouldFailFastOnDuplicateClaimNames() {
        var mapper1 = createDiscoverableMapper("roles", DUMMY_MAPPER, true);
        var mapper2 = createDiscoverableMapper("roles", DUMMY_MAPPER, true);
        var registry = createRegistry(List.of(mapper1, mapper2));

        var exception = assertThrows(IllegalStateException.class, registry::init);
        assertTrue(exception.getMessage().contains("Duplicate claim mapper registration"),
                "Should indicate duplicate registration");
        assertTrue(exception.getMessage().contains("roles"),
                "Should mention the duplicate claim name");
    }

    @Test
    @DisplayName("should filter out disabled mappers")
    void shouldFilterOutDisabledMappers() {
        var enabledMapper = createDiscoverableMapper("roles", DUMMY_MAPPER, true);
        var disabledMapper = createDiscoverableMapper("groups", DUMMY_MAPPER, false);
        var registry = createRegistry(List.of(enabledMapper, disabledMapper));
        registry.init();

        assertEquals(1, registry.getRegisteredClaimNames().size());
        assertTrue(registry.getRegisteredClaimNames().contains("roles"));
        assertTrue(registry.getMapper("groups").isEmpty(),
                "Disabled mapper should not be registered");
    }

    @Test
    @DisplayName("should allow same claim name when one mapper is disabled")
    void shouldAllowSameClaimNameWhenOneDisabled() {
        var disabledMapper = createDiscoverableMapper("roles", DUMMY_MAPPER, false);
        var enabledMapper = createDiscoverableMapper("roles", DUMMY_MAPPER, true);
        var registry = createRegistry(List.of(disabledMapper, enabledMapper));
        registry.init();

        assertEquals(1, registry.getRegisteredClaimNames().size());
        assertTrue(registry.getMapper("roles").isPresent());
    }

    @Test
    @DisplayName("should return unmodifiable set of claim names")
    void shouldReturnUnmodifiableSetOfClaimNames() {
        var mapper = createDiscoverableMapper("roles", DUMMY_MAPPER, true);
        var registry = createRegistry(List.of(mapper));
        registry.init();

        var claimNames = registry.getRegisteredClaimNames();
        assertThrows(UnsupportedOperationException.class,
                () -> claimNames.add("extra"));
    }

    @Test
    @DisplayName("should log initialized message with mapper count")
    void shouldLogInitializedMessage() {
        var mapper = createDiscoverableMapper("roles", DUMMY_MAPPER, true);
        var registry = createRegistry(List.of(mapper));
        registry.init();

        assertLogMessagePresent(TestLogLevel.INFO,
                INFO.CLAIM_MAPPER_REGISTRY_INITIALIZED.format("1", "roles"));
    }

    private static ClaimMapperRegistry createRegistry(List<DiscoverableClaimMapper> mappers) {
        return new ClaimMapperRegistry(new TestInstance(mappers));
    }

    private static DiscoverableClaimMapper createDiscoverableMapper(String claimName, ClaimMapper mapper, boolean enabled) {
        return new DiscoverableClaimMapper() {
            @Override
            public String getClaimName() {
                return claimName;
            }

            @Override
            public ClaimMapper getMapper() {
                return mapper;
            }

            @Override
            public boolean isEnabled() {
                return enabled;
            }
        };
    }

    /**
     * Minimal test implementation of {@link Instance} for unit testing without CDI.
     */
    private record TestInstance(List<DiscoverableClaimMapper> mappers) implements Instance<DiscoverableClaimMapper> {

        @Override
        public Iterator<DiscoverableClaimMapper> iterator() {
            return mappers.iterator();
        }

        @Override
        public Instance<DiscoverableClaimMapper> select(java.lang.annotation.Annotation... qualifiers) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <U extends DiscoverableClaimMapper> Instance<U> select(Class<U> subtype, java.lang.annotation.Annotation... qualifiers) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <U extends DiscoverableClaimMapper> Instance<U> select(TypeLiteral<U> subtype, java.lang.annotation.Annotation... qualifiers) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isUnsatisfied() {
            return mappers.isEmpty();
        }

        @Override
        public boolean isAmbiguous() {
            return false;
        }

        @Override
        public void destroy(DiscoverableClaimMapper instance) {
            // no-op
        }

        @Override
        public Handle<DiscoverableClaimMapper> getHandle() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Iterable<? extends Handle<DiscoverableClaimMapper>> handles() {
            throw new UnsupportedOperationException();
        }

        @Override
        public DiscoverableClaimMapper get() {
            return mappers.getFirst();
        }

        @Override
        public Stream<DiscoverableClaimMapper> stream() {
            return mappers.stream();
        }

        @Override
        public boolean isResolvable() {
            return mappers.size() == 1;
        }
    }
}
