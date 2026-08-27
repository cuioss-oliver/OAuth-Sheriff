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

/**
 * Escapes a string for embedding in a hand-rolled JSON string literal, per
 * <a href="https://www.rfc-editor.org/rfc/rfc8259#section-7">RFC 8259 §7</a>.
 * <p>
 * The {@code private_key_jwt} client assertion ({@code auth.PrivateKeyJwtAuth}) and the DPoP proof
 * JWT ({@code dpop.DpopProofGenerator}) build their header/payload JSON by hand rather than through a
 * general-purpose JSON library, so every string member (including values sourced from the
 * authorization server's own discovery metadata — the token endpoint URL used as the DPoP
 * {@code htu}, or the assertion {@code aud}) must be escaped here before it is embedded. Escaping the
 * backslash and quote characters alone (as a naive hand-rolled escaper commonly does) prevents an
 * embedded quote from breaking out of the JSON string, but RFC 8259 requires every other ASCII
 * control character to be escaped too; an un-escaped control character in an AS-supplied URL would
 * otherwise produce invalid JSON. This is defense-in-depth (canonicalize-before-use), not a
 * primary injection defense — the primary defense against structural injection remains the
 * quote/backslash escaping, which is preserved unchanged.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8259#section-7">RFC 8259 §7 - Strings</a>
 */
public final class JsonEscaper {

    private JsonEscaper() {
        // utility class — never instantiated
    }

    /**
     * Escapes {@code value} for embedding as a JSON string member.
     *
     * @param value the raw value to escape; must not be {@code null}
     * @return the escaped value, safe to embed between the surrounding quotes of a JSON string
     */
    public static String escape(String value) {
        StringBuilder escaped = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\' -> escaped.append("\\\\");
                case '"' -> escaped.append("\\\"");
                case '\b' -> escaped.append("\\b");
                case '\f' -> escaped.append("\\f");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '\t' -> escaped.append("\\t");
                default -> {
                    if (c < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) c));
                    } else {
                        escaped.append(c);
                    }
                }
            }
        }
        return escaped.toString();
    }
}
