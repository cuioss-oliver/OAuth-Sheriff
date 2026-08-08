/*
 * Copyright © 2022 CUI-OpenSource-Software (info@cuioss.de)
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
package de.cuioss.sheriff.token.validation.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/**
 * Utility for computing JWK Thumbprints per RFC 7638.
 * <p>
 * The thumbprint is computed by:
 * <ol>
 *   <li>Extracting the required members based on the key type ({@code kty})</li>
 *   <li>Constructing a minimal JSON representation with members in lexicographic order</li>
 *   <li>Hashing with SHA-256</li>
 *   <li>Base64url encoding without padding</li>
 * </ol>
 * <p>
 * Uses only {@link Sha256Util} and {@link Base64} — no external dependencies.
 *
 * @since 1.0
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7638">RFC 7638 - JSON Web Key (JWK) Thumbprint</a>
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class JwkThumbprintUtil {

    /**
     * Computes the JWK Thumbprint (RFC 7638) for the given JWK represented as a Map.
     *
     * @param jwkMap the JWK as a {@code Map<String, Object>} containing at least {@code kty}
     *               and the required members for that key type
     * @return the Base64url-encoded (no padding) SHA-256 thumbprint
     * @throws IllegalArgumentException if the JWK is missing required fields
     */
    public static String computeThumbprint(Map<String, Object> jwkMap) {
        String minimalJson = canonicalJson(jwkMap);
        byte[] hash = Sha256Util.digest(minimalJson.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    /**
     * Builds the canonical minimal JSON representation of a JWK with the required members in
     * lexicographic order as required by RFC 7638 Section 3.2.
     *
     * <p>This is the exact string {@link #computeThumbprint(Map)} hashes. A caller that must both
     * embed a JWK and publish its thumbprint — the DPoP proof header {@code jwk} together with
     * {@code cnf.jkt} — derives both from this one builder, so it cannot emit a header whose
     * thumbprint does not match the embedded key.</p>
     *
     * @param jwkMap the JWK as a {@code Map<String, Object>} containing at least {@code kty}
     *               and the required members for that key type
     * @return the canonical minimal JSON representation
     * @throws IllegalArgumentException if the key type is unsupported or a required member is missing
     * @since 1.0
     */
    public static String canonicalJson(Map<String, Object> jwkMap) {
        String kty = getRequired(jwkMap, "kty");
        return switch (kty) {
            case "RSA" -> buildJson(
                    "e", getRequired(jwkMap, "e"),
                    "kty", kty,
                    "n", getRequired(jwkMap, "n")
            );
            case "EC" -> buildJson(
                    "crv", getRequired(jwkMap, "crv"),
                    "kty", kty,
                    "x", getRequired(jwkMap, "x"),
                    "y", getRequired(jwkMap, "y")
            );
            case "OKP" -> buildJson(
                    "crv", getRequired(jwkMap, "crv"),
                    "kty", kty,
                    "x", getRequired(jwkMap, "x")
            );
            default -> throw new IllegalArgumentException("Unsupported key type for JWK Thumbprint: " + kty);
        };
    }

    /**
     * Builds a JSON object string from key-value pairs.
     * Keys must already be in lexicographic order.
     * <p>
     * Both keys and values are escaped per RFC 8259 (referenced by RFC 7638 Section 3) so the
     * canonical JSON is spec-correct. Conformant base64url members require no escaping, but escaping
     * is applied unconditionally so a non-conformant member can never produce malformed JSON.
     */
    private static String buildJson(String... keyValuePairs) {
        var sb = new StringBuilder("{");
        for (int i = 0; i < keyValuePairs.length; i += 2) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append('"').append(escapeJsonString(keyValuePairs[i])).append("\":\"")
                    .append(escapeJsonString(keyValuePairs[i + 1])).append('"');
        }
        sb.append('}');
        return sb.toString();
    }

    /**
     * Escapes a string for inclusion in a JSON string literal per RFC 8259 Section 7:
     * the quotation mark and reverse solidus are escaped, and all control characters
     * (U+0000 through U+001F) are escaped using their short form where defined and the
     * {@code \\uXXXX} form otherwise.
     */
    private static String escapeJsonString(String value) {
        var sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\t' -> sb.append("\\t");
                case '\n' -> sb.append("\\n");
                case '\f' -> sb.append("\\f");
                case '\r' -> sb.append("\\r");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }

    private static String getRequired(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value == null) {
            throw new IllegalArgumentException("JWK is missing required field for thumbprint: " + key);
        }
        return value.toString();
    }
}
