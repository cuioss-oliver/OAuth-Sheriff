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
package de.cuioss.sheriff.token.quarkus.mapper.keycloak;

import de.cuioss.sheriff.token.quarkus.config.JwtPropertyKeys;
import de.cuioss.sheriff.token.quarkus.test.TestConfig;
import de.cuioss.sheriff.token.validation.domain.claim.mapper.KeycloakDefaultRolesMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link KeycloakRolesMapperBean}.
 */
@DisplayName("KeycloakRolesMapperBean")
class KeycloakRolesMapperBeanTest {

    @Test
    @DisplayName("should be disabled by default")
    void shouldBeDisabledByDefault() {
        var config = new TestConfig(Map.of());
        var bean = new KeycloakRolesMapperBean(config);

        assertFalse(bean.isEnabled(), "Should be disabled by default");
    }

    @Test
    @DisplayName("should be enabled when property is true")
    void shouldBeEnabledWhenPropertyIsTrue() {
        var config = new TestConfig(Map.of(
                JwtPropertyKeys.KEYCLOAK.DEFAULT_ROLES_MAPPER_ENABLED, "true"
        ));
        var bean = new KeycloakRolesMapperBean(config);

        assertTrue(bean.isEnabled(), "Should be enabled when property is true");
    }

    @Test
    @DisplayName("should be disabled when property is false")
    void shouldBeDisabledWhenPropertyIsFalse() {
        var config = new TestConfig(Map.of(
                JwtPropertyKeys.KEYCLOAK.DEFAULT_ROLES_MAPPER_ENABLED, "false"
        ));
        var bean = new KeycloakRolesMapperBean(config);

        assertFalse(bean.isEnabled(), "Should be disabled when property is false");
    }

    @Test
    @DisplayName("should return correct claim name")
    void shouldReturnCorrectClaimName() {
        var config = new TestConfig(Map.of());
        var bean = new KeycloakRolesMapperBean(config);

        assertEquals("roles", bean.getClaimName());
    }

    @Test
    @DisplayName("should return KeycloakDefaultRolesMapper instance")
    void shouldReturnCorrectMapperDelegate() {
        var config = new TestConfig(Map.of());
        var bean = new KeycloakRolesMapperBean(config);

        assertInstanceOf(KeycloakDefaultRolesMapper.class, bean.getMapper(),
                "Should delegate to KeycloakDefaultRolesMapper");
    }
}
