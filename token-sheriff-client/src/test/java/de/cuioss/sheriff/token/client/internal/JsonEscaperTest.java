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

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@EnableGeneratorController
@DisplayName("JsonEscaper escapes JSON string members per RFC 8259 §7")
class JsonEscaperTest {

    /** A single backslash, built without a source escape so the pipeline cannot mangle it. */
    private static final String BACKSLASH = String.valueOf((char) 92);

    /** A double-quote character. */
    private static final String QUOTE = String.valueOf((char) 34);

    @Test
    @DisplayName("Should pass a printable value through unchanged")
    void shouldPassPrintableThrough() {
        String value = Generators.letterStrings(5, 30).next();

        assertEquals(value, JsonEscaper.escape(value),
                "a value with no structural or control characters must be returned verbatim");
    }

    @Test
    @DisplayName("Should escape a quote so it cannot break out of the JSON string")
    void shouldEscapeQuote() {
        String escaped = JsonEscaper.escape("a" + QUOTE + "b");

        assertEquals("a" + BACKSLASH + QUOTE + "b", escaped,
                "an embedded quote is prefixed with a backslash");
    }

    @Test
    @DisplayName("Should escape a backslash")
    void shouldEscapeBackslash() {
        String escaped = JsonEscaper.escape("a" + BACKSLASH + "b");

        assertEquals("a" + BACKSLASH + BACKSLASH + "b", escaped,
                "an embedded backslash is doubled");
    }

    @Test
    @DisplayName("Should escape the RFC 8259 named control characters")
    void shouldEscapeNamedControlChars() {
        assertAll("named escapes",
                () -> assertEquals(BACKSLASH + "b", JsonEscaper.escape(Character.toString(8)), "backspace"),
                () -> assertEquals(BACKSLASH + "f", JsonEscaper.escape(Character.toString(12)), "form feed"),
                () -> assertEquals(BACKSLASH + "n", JsonEscaper.escape(Character.toString(10)), "line feed"),
                () -> assertEquals(BACKSLASH + "r", JsonEscaper.escape(Character.toString(13)), "carriage return"),
                () -> assertEquals(BACKSLASH + "t", JsonEscaper.escape(Character.toString(9)), "tab"));
    }

    @Test
    @DisplayName("Should escape other ASCII control characters as unicode escapes")
    void shouldEscapeOtherControlChars() {
        assertAll("unicode escapes",
                () -> assertEquals(BACKSLASH + "u0000", JsonEscaper.escape(Character.toString(0)), "NUL"),
                () -> assertEquals(BACKSLASH + "u001f", JsonEscaper.escape(Character.toString(31)), "unit separator"));
    }

    @Test
    @DisplayName("Should neutralize every quote so a hostile value cannot break out of a JSON string")
    void shouldNeutralizeStructuralQuotes() {
        String hostile = QUOTE + ",here" + QUOTE + "admin" + QUOTE + ":true";

        String escaped = JsonEscaper.escape(hostile);

        assertFalse(escaped.replace(BACKSLASH + QUOTE, "").contains(QUOTE),
                "every quote in the escaped value must be backslash-escaped, leaving no bare structural quote");
    }
}
