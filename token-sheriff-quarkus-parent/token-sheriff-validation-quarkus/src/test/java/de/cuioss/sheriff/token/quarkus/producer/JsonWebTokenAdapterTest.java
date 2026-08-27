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
package de.cuioss.sheriff.token.quarkus.producer;

import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.domain.token.TokenContent;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Principal;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link JsonWebTokenAdapter}.
 *
 * @author Oliver Wolff
 */
@DisplayName("JsonWebTokenAdapter")
class JsonWebTokenAdapterTest {

    @Test
    @DisplayName("should implement JsonWebToken and Principal")
    void shouldImplementJsonWebTokenAndPrincipal() {
        var adapter = createAdapter(createClaims());
        assertInstanceOf(JsonWebToken.class, adapter);
        assertInstanceOf(Principal.class, adapter);
    }

    @Test
    @DisplayName("getName should return UPN when present")
    void getNameShouldReturnUpnWhenPresent() {
        var claims = createClaims();
        claims.put("upn", ClaimValue.forPlainString("user@example.com"));
        claims.put("preferred_username", ClaimValue.forPlainString("jdoe"));
        assertEquals("user@example.com", createAdapter(claims).getName());
    }

    @Test
    @DisplayName("getName should fallback to preferred_username when UPN is absent")
    void getNameShouldFallbackToPreferredUsername() {
        var claims = createClaims();
        claims.put("preferred_username", ClaimValue.forPlainString("jdoe"));
        assertEquals("jdoe", createAdapter(claims).getName());
    }

    @Test
    @DisplayName("getName should fallback to sub when UPN and preferred_username are absent")
    void getNameShouldFallbackToSub() {
        assertEquals("test-subject", createAdapter(createClaims()).getName());
    }

    @Test
    @DisplayName("getName should return null when no principal claims are present")
    void getNameShouldReturnNullWhenNoPrincipalClaims() {
        var claims = createClaims();
        claims.remove("sub");
        assertNull(createAdapter(claims).getName());
    }

    @Test
    @DisplayName("getSubject should return nullable String per JsonWebToken contract")
    void getSubjectShouldReturnNullableString() {
        assertEquals("test-subject", createAdapter(createClaims()).getSubject());

        var claims = createClaims();
        claims.remove("sub");
        assertNull(createAdapter(claims).getSubject());
    }

    @Test
    @DisplayName("getIssuer should return issuer")
    void getIssuerShouldReturnIssuer() {
        assertEquals("test-issuer", createAdapter(createClaims()).getIssuer());
    }

    @Test
    @DisplayName("getRawToken should delegate")
    void getRawTokenShouldDelegate() {
        assertEquals("raw-token", createAdapter(createClaims()).getRawToken());
    }

    @Test
    @DisplayName("getExpirationTime should return epoch seconds")
    void getExpirationTimeShouldReturnEpochSeconds() {
        var adapter = createAdapter(createClaims());
        long epochSeconds = adapter.getExpirationTime();
        assertTrue(epochSeconds > 0);
    }

    @Test
    @DisplayName("getIssuedAtTime should return epoch seconds")
    void getIssuedAtTimeShouldReturnEpochSeconds() {
        var adapter = createAdapter(createClaims());
        long epochSeconds = adapter.getIssuedAtTime();
        assertTrue(epochSeconds > 0);
    }

    @Test
    @DisplayName("getAudience should return Set")
    void getAudienceShouldReturnSet() {
        var claims = createClaims();
        claims.put("aud", ClaimValue.forList("aud-value", List.of("client-a", "client-b")));
        var audience = createAdapter(claims).getAudience();
        assertEquals(2, audience.size());
        assertTrue(audience.contains("client-a"));
        assertTrue(audience.contains("client-b"));
    }

    @Test
    @DisplayName("getAudience should return empty set when absent")
    void getAudienceShouldReturnEmptySetWhenAbsent() {
        assertTrue(createAdapter(createClaims()).getAudience().isEmpty());
    }

    @Test
    @DisplayName("getGroups should return Set")
    void getGroupsShouldReturnSet() {
        var claims = createClaims();
        claims.put("groups", ClaimValue.forList("groups-value", List.of("admin", "users")));
        var groups = createAdapter(claims).getGroups();
        assertEquals(2, groups.size());
        assertTrue(groups.contains("admin"));
    }

    @Test
    @DisplayName("getTokenID should return jti claim")
    void getTokenIDShouldReturnJtiClaim() {
        var claims = createClaims();
        claims.put("jti", ClaimValue.forPlainString("token-123"));
        assertEquals("token-123", createAdapter(claims).getTokenID());
    }

    @Test
    @DisplayName("getTokenID should return null when absent")
    void getTokenIDShouldReturnNullWhenAbsent() {
        assertNull(createAdapter(createClaims()).getTokenID());
    }

    @Test
    @DisplayName("getClaimNames should return all claim keys")
    void getClaimNamesShouldReturnAllClaimKeys() {
        var names = createAdapter(createClaims()).getClaimNames();
        assertTrue(names.contains("iss"));
        assertTrue(names.contains("sub"));
    }

    @Test
    @DisplayName("containsClaim should check presence")
    void containsClaimShouldCheckPresence() {
        var adapter = createAdapter(createClaims());
        assertTrue(adapter.containsClaim("iss"));
        assertFalse(adapter.containsClaim("nonexistent"));
    }

    @Test
    @DisplayName("getClaim should return typed values")
    void getClaimShouldReturnTypedValues() {
        var claims = createClaims();
        claims.put("groups", ClaimValue.forList("groups-value", List.of("admin")));
        claims.put("jti", ClaimValue.forPlainString("id-123"));
        var adapter = createAdapter(claims);

        // String claim
        String issuer = adapter.getClaim("iss");
        assertEquals("test-issuer", issuer);

        // DateTime claim returns epoch seconds (Long)
        Long exp = adapter.getClaim("exp");
        assertNotNull(exp);
        assertTrue(exp > 0);

        // List claim returns Set
        Set<String> groups = adapter.getClaim("groups");
        assertTrue(groups.contains("admin"));
    }

    @Test
    @DisplayName("getClaim should return null for absent claims")
    void getClaimShouldReturnNullForAbsentClaims() {
        assertNull(createAdapter(createClaims()).getClaim("nonexistent"));
    }

    @Test
    @DisplayName("getClaim should return original string for unknown claim names")
    void getClaimShouldReturnStringForUnknownClaims() {
        var claims = createClaims();
        claims.put("custom_claim", ClaimValue.forPlainString("custom-value"));
        assertEquals("custom-value", createAdapter(claims).<String>getClaim("custom_claim"));
    }

    // Helper methods

    private Map<String, ClaimValue> createClaims() {
        var claims = new HashMap<String, ClaimValue>();
        claims.put("iss", ClaimValue.forPlainString("test-issuer"));
        claims.put("sub", ClaimValue.forPlainString("test-subject"));
        claims.put("exp", ClaimValue.forDateTime("exp-value", OffsetDateTime.now().plusHours(1)));
        claims.put("iat", ClaimValue.forDateTime("iat-value", OffsetDateTime.now().minusMinutes(5)));
        return claims;
    }

    private JsonWebTokenAdapter createAdapter(Map<String, ClaimValue> claims) {
        return new JsonWebTokenAdapter(createTokenContent(claims));
    }

    private TokenContent createTokenContent(Map<String, ClaimValue> claims) {
        return new AccessTokenContent(claims, "raw-token");
    }
}
