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
package de.cuioss.sheriff.token.validation.domain.token;

import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit test for {@link MinimalTokenContent} interface.
 * <p>
 * Tests the interface contract using concrete implementations.
 *
 * @author Oliver Wolff
 */
@EnableGeneratorController
class MinimalTokenContentTest {

    @Test
    @DisplayName("Should provide raw token access")
    void shouldProvideRawTokenAccess() {
        MinimalTokenContent content = new UnvalidatedRefreshToken("test-token", Map.of());

        assertEquals("test-token", content.getRawToken());
    }

    @Test
    @DisplayName("Should provide token type access")
    void shouldProvideTokenTypeAccess() {
        MinimalTokenContent refreshToken = new UnvalidatedRefreshToken("token3", Map.of());
        assertEquals(TokenType.REFRESH_TOKEN, refreshToken.getTokenType());
    }

    @Test
    @DisplayName("Should handle null raw token")
    void shouldHandleNullRawToken() {
        MinimalTokenContent content = new UnvalidatedRefreshToken(null, Map.of());

        assertNull(content.getRawToken());
        assertEquals(TokenType.REFRESH_TOKEN, content.getTokenType());
    }

    @Test
    @DisplayName("Should handle empty raw token")
    void shouldHandleEmptyRawToken() {
        MinimalTokenContent content = new UnvalidatedRefreshToken("", Map.of());

        assertEquals("", content.getRawToken());
        assertEquals(TokenType.REFRESH_TOKEN, content.getTokenType());
    }

    @Test
    @DisplayName("Should handle long raw token")
    void shouldHandleLongRawToken() {
        String longToken = """
                eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5LWlkIn0\
                .eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoidGVzdC11c2VyIiwiYXVkIjoiY2xpZW50LWlkIiwi\
                ZXhwIjoxNjQwOTk1MjAwLCJpYXQiOjE2NDA5OTE2MDBdfQ\
                .signature-part-here""";

        MinimalTokenContent content = new UnvalidatedRefreshToken(longToken, Map.of());

        assertEquals(longToken, content.getRawToken());
        assertEquals(TokenType.REFRESH_TOKEN, content.getTokenType());
    }

    @Test
    @DisplayName("Should be serializable")
    void shouldBeSerializable() throws Exception {
        UnvalidatedRefreshToken original = new UnvalidatedRefreshToken("test-token", Map.of());

        // Serialize
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(original);
        oos.close();

        // Deserialize
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        UnvalidatedRefreshToken deserialized = (UnvalidatedRefreshToken) ois.readObject();
        ois.close();

        // Verify
        assertEquals(original.getRawToken(), deserialized.getRawToken());
        assertEquals(original.getTokenType(), deserialized.getTokenType());
    }

    @Test
    @DisplayName("Should maintain consistency across calls")
    void shouldMaintainConsistencyAcrossCalls() {
        MinimalTokenContent content = new UnvalidatedRefreshToken("consistent-token", Map.of());

        // Multiple calls should return the same values
        assertEquals("consistent-token", content.getRawToken());
        assertEquals("consistent-token", content.getRawToken());
        assertEquals("consistent-token", content.getRawToken());

        assertEquals(TokenType.REFRESH_TOKEN, content.getTokenType());
        assertEquals(TokenType.REFRESH_TOKEN, content.getTokenType());
        assertEquals(TokenType.REFRESH_TOKEN, content.getTokenType());
    }

    @Test
    @DisplayName("Should support different token implementations")
    void shouldSupportDifferentTokenImplementations() {
        // Test that different permitted implementations of the sealed interface work correctly
        MinimalTokenContent refreshToken = new UnvalidatedRefreshToken("refresh-token", Map.of());
        Map<String, ClaimValue> claims = Map.of("sub", ClaimValue.forPlainString("user"));
        MinimalTokenContent accessToken = new AccessTokenContent(claims, "access-token");

        assertNotNull(refreshToken.getRawToken());
        assertNotNull(refreshToken.getTokenType());
        assertNotNull(accessToken.getRawToken());
        assertNotNull(accessToken.getTokenType());

        assertNotEquals(refreshToken.getRawToken(), accessToken.getRawToken());
        assertNotEquals(refreshToken.getTokenType(), accessToken.getTokenType());
    }
}
