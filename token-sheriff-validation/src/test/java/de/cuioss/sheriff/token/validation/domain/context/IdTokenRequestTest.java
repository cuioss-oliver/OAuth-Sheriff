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
package de.cuioss.sheriff.token.validation.domain.context;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("IdTokenRequest")
class IdTokenRequestTest {

    private static final String TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature";

    @Test
    @DisplayName("should create request with token string and empty headers via factory")
    void shouldCreateWithFactory() {
        var request = IdTokenRequest.of(TOKEN);
        assertEquals(TOKEN, request.tokenString());
        assertTrue(request.httpHeaders().isEmpty());
    }

    @Test
    @DisplayName("should create request with token string and headers")
    void shouldCreateWithHeaders() {
        Map<String, List<String>> headers = Map.of("content-type", List.of("application/json"));
        var request = new IdTokenRequest(TOKEN, headers);
        assertEquals(TOKEN, request.tokenString());
        assertEquals(1, request.httpHeaders().size());
    }

    @Test
    @DisplayName("should reject null token string")
    void shouldRejectNullTokenString() {
        assertThrows(NullPointerException.class, () -> IdTokenRequest.of(null));
    }

    @Test
    @DisplayName("should reject null headers")
    void shouldRejectNullHeaders() {
        assertThrows(NullPointerException.class, () -> new IdTokenRequest(TOKEN, null));
    }

    @Test
    @DisplayName("should defensively copy headers")
    void shouldDefensivelyCopyHeaders() {
        Map<String, List<String>> mutableHeaders = new HashMap<>();
        mutableHeaders.put("authorization", new ArrayList<>(List.of("Bearer token")));

        var request = new IdTokenRequest(TOKEN, mutableHeaders);
        mutableHeaders.put("x-new-header", List.of("value"));

        assertFalse(request.httpHeaders().containsKey("x-new-header"));
    }

    @Test
    @DisplayName("should return immutable headers")
    void shouldReturnImmutableHeaders() {
        var request = new IdTokenRequest(TOKEN, Map.of("key", List.of("value")));
        var headers = request.httpHeaders();
        var newValue = List.of("val");
        assertThrows(UnsupportedOperationException.class,
                () -> headers.put("new", newValue));
    }

    @Test
    @DisplayName("should implement TokenValidationRequest sealed interface")
    void shouldImplementSealedInterface() {
        TokenValidationRequest request = IdTokenRequest.of(TOKEN);
        assertInstanceOf(IdTokenRequest.class, request);
        assertEquals(TOKEN, request.tokenString());
    }

    @Test
    @DisplayName("should support record equality")
    void shouldSupportEquality() {
        var request1 = IdTokenRequest.of(TOKEN);
        var request2 = IdTokenRequest.of(TOKEN);
        assertEquals(request1, request2);
        assertEquals(request1.hashCode(), request2.hashCode());
    }
}
