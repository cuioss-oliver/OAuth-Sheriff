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
package de.cuioss.sheriff.token.validation;

import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValueType;
import de.cuioss.sheriff.token.validation.domain.claim.mapper.ClaimMapper;
import de.cuioss.sheriff.token.validation.domain.claim.mapper.JsonCollectionMapper;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.test.InMemoryJWKSFactory;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.ClaimControlParameter;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@EnableGeneratorController
@DisplayName("Tests Custom ClaimMapper functionality")
class CustomClaimMapperTest {

    private static final String ROLE_CLAIM = "role";
    private static final List<String> ROLES = List.of("admin", "user", "manager");

    private TokenValidator tokenValidator;
    private String tokenWithRoles;
    private String jwksContent;

    @BeforeEach
    void setUp() {
        jwksContent = InMemoryJWKSFactory.createDefaultJwks();

        ClaimMapper roleMapper = new JsonCollectionMapper();

        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuerIdentifier(TestTokenHolder.TEST_ISSUER)
                .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                .expectedClientId(TestTokenHolder.TEST_CLIENT_ID)
                .jwksContent(jwksContent)
                .claimMapper(ROLE_CLAIM, roleMapper)
                .build();

        tokenValidator = TokenValidator.builder().issuerConfig(issuerConfig).build();

        var claimControl = ClaimControlParameter.builder().build();
        var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, claimControl);

        tokenHolder.withClaim(ClaimName.AUDIENCE.getName(), ClaimValue.forList(TestTokenHolder.TEST_AUDIENCE, List.of(TestTokenHolder.TEST_AUDIENCE)));
        tokenHolder.withClaim(ClaimName.ISSUER.getName(), ClaimValue.forPlainString(TestTokenHolder.TEST_ISSUER));
        tokenHolder.withClaim(ClaimName.AUTHORIZED_PARTY.getName(), ClaimValue.forPlainString(TestTokenHolder.TEST_CLIENT_ID));
        tokenHolder.withClaim(ROLE_CLAIM, ClaimValue.forList(String.join(",", ROLES), ROLES));
        tokenHolder.withClaim(ClaimName.SCOPE.getName(), ClaimValue.forList("openid profile email",
                List.of("openid", "profile", "email")));

        tokenWithRoles = tokenHolder.getRawToken();
    }

    @Test
    @DisplayName("Use custom claim mapper for role claim")
    void shouldUseCustomClaimMapperForRoleClaim() {
        AccessTokenContent tokenContent = tokenValidator.createAccessToken(AccessTokenRequest.of(tokenWithRoles));
        ClaimValue roleClaim = tokenContent.getClaims().get(ROLE_CLAIM);

        assertNotNull(roleClaim, "Role claim should not be null");
        assertEquals(ClaimValueType.STRING_LIST, roleClaim.getType(), "Role claim should be a STRING_LIST");
        assertEquals(ROLES.size(), roleClaim.getAsList().size(), "Role claim should have the correct number of roles");
        assertTrue(roleClaim.getAsList().containsAll(ROLES), "Role claim should contain all the roles");
    }

    @Test
    @DisplayName("Use default mapper when no custom mapper is configured")
    void shouldUseDefaultMapperWhenNoCustomMapperIsConfigured() {
        IssuerConfig issuerConfigWithoutCustomMapper = IssuerConfig.builder()
                .issuerIdentifier(TestTokenHolder.TEST_ISSUER)
                .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                .expectedClientId(TestTokenHolder.TEST_CLIENT_ID)
                .jwksContent(jwksContent)
                .build();

        TokenValidator factoryWithoutCustomMapper = TokenValidator.builder()
                .issuerConfig(issuerConfigWithoutCustomMapper)
                .build();

        AccessTokenContent tokenContent = factoryWithoutCustomMapper.createAccessToken(AccessTokenRequest.of(tokenWithRoles));
        ClaimValue roleClaim = tokenContent.getClaims().get(ROLE_CLAIM);

        assertNotNull(roleClaim, "Role claim should not be null");
        assertNotEquals(ClaimValueType.STRING_LIST, roleClaim.getType(), "Role claim should not be a STRING_LIST with default mapper");
    }
}
