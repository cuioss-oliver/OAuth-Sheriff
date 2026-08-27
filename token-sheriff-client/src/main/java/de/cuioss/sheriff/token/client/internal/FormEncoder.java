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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.StringJoiner;

/**
 * Shared {@code application/x-www-form-urlencoded} encoder for the client engine's back-channel
 * request bodies and front-channel redirect query strings.
 * <p>
 * Every request this engine builds — the token endpoint POST, the PAR POST, the revocation POST,
 * and the front-channel authorization / end-session redirects — form-encodes a
 * {@code Map<String, String>} of parameters identically; this is the single shared implementation.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public final class FormEncoder {

    private FormEncoder() {
        // utility class — never instantiated
    }

    /**
     * Encodes the given parameters as {@code application/x-www-form-urlencoded}.
     *
     * @param params the parameters to encode; must not be {@code null}
     * @return the {@code key=value} pairs, percent-encoded and joined with {@code &}
     */
    public static String encode(Map<String, String> params) {
        StringJoiner joiner = new StringJoiner("&");
        params.forEach((key, value) -> joiner.add(URLEncoder.encode(key, StandardCharsets.UTF_8)
                + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8)));
        return joiner.toString();
    }
}
