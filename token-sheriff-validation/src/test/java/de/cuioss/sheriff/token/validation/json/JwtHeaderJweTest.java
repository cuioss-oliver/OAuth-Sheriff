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
package de.cuioss.sheriff.token.validation.json;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("JwtHeader JWE Fields Tests")
class JwtHeaderJweTest {

    @Test
    @DisplayName("isJwe should return true when enc is present")
    void isJweShouldReturnTrueWhenEncPresent() {
        var header = new JwtHeader("RSA-OAEP", null, null, null, null,
                "A256GCM", null, null, null, null);
        assertTrue(header.isJwe());
    }

    @Test
    @DisplayName("isJwe should return false when enc is null")
    void isJweShouldReturnFalseWhenEncNull() {
        var header = new JwtHeader("RS256", null, null, null, null,
                null, null, null, null, null);
        assertFalse(header.isJwe());
    }

    @Test
    @DisplayName("isJwe should return false when enc is blank")
    void isJweShouldReturnFalseWhenEncBlank() {
        var header = new JwtHeader("RS256", null, null, null, null,
                "  ", null, null, null, null);
        assertFalse(header.isJwe());
    }

    @Test
    @DisplayName("getEnc should return Optional with value when present")
    void getEncShouldReturnValue() {
        var header = new JwtHeader("RSA-OAEP", null, null, null, null,
                "A256GCM", null, null, null, null);
        assertTrue(header.getEnc().isPresent());
        assertEquals("A256GCM", header.getEnc().get());
    }

    @Test
    @DisplayName("getEnc should return empty Optional when null")
    void getEncShouldReturnEmptyWhenNull() {
        var header = new JwtHeader("RS256", null, null, null, null,
                null, null, null, null, null);
        assertTrue(header.getEnc().isEmpty());
    }

    @Test
    @DisplayName("getEnc should return empty Optional when blank")
    void getEncShouldReturnEmptyWhenBlank() {
        var header = new JwtHeader("RS256", null, null, null, null,
                "", null, null, null, null);
        assertTrue(header.getEnc().isEmpty());
    }

    @Test
    @DisplayName("getZip should return value when present")
    void getZipShouldReturnValue() {
        var header = new JwtHeader("RSA-OAEP", null, null, null, null,
                "A256GCM", "DEF", null, null, null);
        assertTrue(header.getZip().isPresent());
        assertEquals("DEF", header.getZip().get());
    }

    @Test
    @DisplayName("getZip should return empty when null")
    void getZipShouldReturnEmptyWhenNull() {
        var header = new JwtHeader("RSA-OAEP", null, null, null, null,
                "A256GCM", null, null, null, null);
        assertTrue(header.getZip().isEmpty());
    }

    @Test
    @DisplayName("getEpk should return value when present")
    void getEpkShouldReturnValue() {
        String epk = "{\"kty\":\"EC\",\"crv\":\"P-256\"}";
        var header = new JwtHeader("ECDH-ES", null, null, null, null,
                "A128GCM", null, epk, null, null);
        assertTrue(header.getEpk().isPresent());
        assertEquals(epk, header.getEpk().get());
    }

    @Test
    @DisplayName("getApu should return value when present")
    void getApuShouldReturnValue() {
        var header = new JwtHeader("ECDH-ES", null, null, null, null,
                "A128GCM", null, null, "dGVzdA", null);
        assertTrue(header.getApu().isPresent());
        assertEquals("dGVzdA", header.getApu().get());
    }

    @Test
    @DisplayName("getApv should return value when present")
    void getApvShouldReturnValue() {
        var header = new JwtHeader("ECDH-ES", null, null, null, null,
                "A128GCM", null, null, null, "dGVzdA");
        assertTrue(header.getApv().isPresent());
        assertEquals("dGVzdA", header.getApv().get());
    }

    @Test
    @DisplayName("getApu and getApv should return empty when null")
    void getApuApvShouldReturnEmptyWhenNull() {
        var header = new JwtHeader("ECDH-ES", null, null, null, null,
                "A128GCM", null, null, null, null);
        assertTrue(header.getApu().isEmpty());
        assertTrue(header.getApv().isEmpty());
    }
}
