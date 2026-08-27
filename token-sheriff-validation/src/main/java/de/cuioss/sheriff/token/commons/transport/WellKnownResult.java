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
package de.cuioss.sheriff.token.commons.transport;

import com.dslplatform.json.CompiledJson;
import com.dslplatform.json.JsonAttribute;

import java.util.Optional;

/**
 * Java representation of OpenID Connect Well-Known Configuration response.
 * <p>
 * This class represents the core fields from the standard OpenID Connect Discovery 1.0
 * well-known configuration document needed for JWT validation. It uses DSL-JSON's
 * {@code @CompiledJson} for compile-time code generation, enabling direct deserialization
 * and optimal performance for native compilation.
 * <p>
 * Key fields from RFC 8414 and OpenID Connect Discovery:
 * <ul>
 *   <li><strong>issuer</strong>: Authorization server's identifier URL</li>
 *   <li><strong>jwks_uri</strong>: URL of the authorization server's JWK Set document</li>
 * </ul>
 *
 * <p><strong>Note:</strong> Fields are {@code public} per DSL-JSON {@code @CompiledJson} requirement
 * for class-based deserialization. After deserialization, this object should be treated as read-only.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8414">RFC 8414 - OAuth 2.0 Authorization Server Metadata</a>
 */
@CompiledJson
@SuppressWarnings("java:S1104") // Public fields required by DSL-JSON @CompiledJson for class-based deserialization
public class WellKnownResult {

    public String issuer;

    @JsonAttribute(name = "jwks_uri")
    public String jwksUri;

    /**
     * Gets the issuer as Optional.
     *
     * @return Optional containing the issuer, empty if null
     */
    public Optional<String> getIssuer() {
        return Optional.ofNullable(issuer);
    }

    /**
     * Gets the JWKS URI as Optional.
     *
     * @return Optional containing the JWKS URI, empty if null
     */
    public Optional<String> getJwksUri() {
        return Optional.ofNullable(jwksUri);
    }

}
