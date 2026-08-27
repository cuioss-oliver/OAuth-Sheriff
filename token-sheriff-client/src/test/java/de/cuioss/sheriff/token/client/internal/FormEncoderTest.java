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
package de.cuioss.sheriff.token.client.internal;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@EnableGeneratorController
@DisplayName("FormEncoder produces application/x-www-form-urlencoded bodies")
class FormEncoderTest {

    private static final String KEY_STATE = "state";
    private static final String VALUE_PREFIX = KEY_STATE + "=";

    @Test
    @DisplayName("Should return an empty string for an empty parameter map")
    void shouldEncodeEmptyMap() {
        assertEquals("", FormEncoder.encode(Map.of()),
                "an empty parameter map encodes to an empty body");
    }

    @Test
    @DisplayName("Should encode a single parameter as key=value")
    void shouldEncodeSingleParameter() {
        String encoded = FormEncoder.encode(Map.of("grant_type", "authorization_code"));

        assertEquals("grant_type=authorization_code", encoded,
                "a token-safe single parameter is emitted verbatim as key=value");
    }

    @Test
    @DisplayName("Should percent-encode reserved characters so a value cannot inject extra parameters")
    void shouldPercentEncodeReservedChars() {
        String value = "a&b=c d";

        String encoded = FormEncoder.encode(Map.of(KEY_STATE, value));

        String valuePart = encoded.substring(VALUE_PREFIX.length());
        assertAll("reserved characters neutralized",
                () -> assertFalse(valuePart.contains("&"),
                        "an embedded & must be percent-encoded, never left raw to inject a second parameter"),
                () -> assertFalse(valuePart.contains("="),
                        "an embedded = must be percent-encoded, never left raw"),
                () -> assertEquals(value, URLDecoder.decode(valuePart, StandardCharsets.UTF_8),
                        "the value round-trips exactly through URL-decoding"));
    }

    @Test
    @DisplayName("Should join multiple parameters with & and round-trip each value")
    void shouldRoundTripMultipleParameters() {
        String code = Generators.letterStrings(3, 12).next();
        String state = Generators.letterStrings(3, 12).next();
        Map<String, String> params = new HashMap<>();
        params.put("code", code);
        params.put(KEY_STATE, state);

        String encoded = FormEncoder.encode(params);

        Map<String, String> decoded = decode(encoded);
        assertAll("each parameter round-trips",
                () -> assertEquals(2, decoded.size(), "both parameters are emitted"),
                () -> assertEquals(code, decoded.get("code"), "the code round-trips"),
                () -> assertEquals(state, decoded.get(KEY_STATE), "the state round-trips"));
    }

    private static Map<String, String> decode(String encoded) {
        Map<String, String> out = new HashMap<>();
        for (String pair : encoded.split("&")) {
            int eq = pair.indexOf('=');
            out.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return out;
    }
}
