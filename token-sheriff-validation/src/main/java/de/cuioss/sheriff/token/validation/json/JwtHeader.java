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

import com.dslplatform.json.CompiledJson;

import java.util.Optional;

/**
 * JWT Header representation for DSL-JSON deserialization.
 * <p>
 * This record represents the JWT header structure as defined in RFC 7515 (JWS),
 * RFC 7516 (JWE), and RFC 7519 (JWT), providing type-safe access to header parameters.
 * <p>
 * The header contains cryptographic metadata needed for JWT validation:
 * <ul>
 *   <li>Algorithm specification for signature verification (JWS) or key management (JWE)</li>
 *   <li>Key identification for key lookup</li>
 *   <li>Content type information</li>
 *   <li>JWE-specific fields: content encryption algorithm, compression, ephemeral keys</li>
 * </ul>
 * <p>
 * A JWE header is distinguished from a JWS header by the presence of the {@code enc}
 * (content encryption algorithm) field. When {@code enc} is present and non-blank,
 * the header belongs to a JWE token (RFC 7516).
 * <p>
 * For more details on JWT header structure, see:
 * <ul>
 *   <li><a href="https://datatracker.ietf.org/doc/html/rfc7515#section-4">RFC 7515 - 4. JWS Header</a></li>
 *   <li><a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4">RFC 7516 - 4. JWE Header</a></li>
 *   <li><a href="https://datatracker.ietf.org/doc/html/rfc7519#section-5">RFC 7519 - 5. JWT Header</a></li>
 * </ul>
 *
 * @param alg The "alg" (algorithm) Header Parameter. For JWS: signature algorithm.
 *            For JWE: key management algorithm (e.g., "RSA-OAEP", "ECDH-ES").
 * @param typ The "typ" (type) Header Parameter is used to declare the media type.
 * @param kid The "kid" (key ID) Header Parameter is a hint indicating which key was used.
 * @param jwk The "jwk" (JSON Web Key) Header Parameter.
 * @param cty The "cty" (content type) Header Parameter.
 * @param enc The "enc" (encryption algorithm) Header Parameter (JWE only, RFC 7516).
 *            Identifies the content encryption algorithm (e.g., "A256GCM", "A128CBC-HS256").
 *            Presence of this field distinguishes JWE from JWS headers.
 * @param zip The "zip" (compression algorithm) Header Parameter (JWE only, RFC 7516).
 *            If present, the plaintext was compressed before encryption (e.g., "DEF" for DEFLATE).
 * @param epk The "epk" (ephemeral public key) Header Parameter (JWE only, RFC 7518 Section 4.6.1.1).
 *            Used with ECDH-ES key agreement. Stored as String for DSL-JSON compatibility.
 * @param apu The "apu" (Agreement PartyUInfo) Header Parameter (JWE only, RFC 7518 Section 4.6.1.2).
 *            Base64URL-encoded value for key derivation.
 * @param apv The "apv" (Agreement PartyVInfo) Header Parameter (JWE only, RFC 7518 Section 4.6.1.3).
 *            Base64URL-encoded value for key derivation.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@CompiledJson
public record JwtHeader(
String alg,
String typ,
String kid,
String jwk,
String cty,
String enc,
String zip,
String epk,
String apu,
String apv
) {

    /**
     * Gets the algorithm parameter as Optional.
     *
     * @return Optional containing the algorithm, empty if null or blank
     */
    public Optional<String> getAlg() {
        return nonBlank(alg);
    }

    /**
     * Gets the type parameter as Optional.
     *
     * @return Optional containing the type, empty if null or blank
     */
    public Optional<String> getTyp() {
        return nonBlank(typ);
    }

    /**
     * Gets the key ID parameter as Optional.
     *
     * @return Optional containing the key ID, empty if null or blank
     */
    public Optional<String> getKid() {
        return nonBlank(kid);
    }

    /**
     * Gets the JSON Web Key parameter as Optional.
     *
     * @return Optional containing the JWK, empty if null or blank
     */
    public Optional<String> getJwk() {
        return nonBlank(jwk);
    }

    /**
     * Gets the content encryption algorithm parameter as Optional (JWE only).
     *
     * @return Optional containing the encryption algorithm, empty if null or blank
     */
    public Optional<String> getEnc() {
        return nonBlank(enc);
    }

    /**
     * Gets the compression algorithm parameter as Optional (JWE only).
     *
     * @return Optional containing the compression algorithm, empty if null or blank
     */
    public Optional<String> getZip() {
        return nonBlank(zip);
    }

    /**
     * Gets the ephemeral public key parameter as Optional (JWE ECDH-ES only).
     *
     * @return Optional containing the ephemeral public key JSON, empty if null or blank
     */
    public Optional<String> getEpk() {
        return nonBlank(epk);
    }

    /**
     * Gets the Agreement PartyUInfo parameter as Optional (JWE ECDH-ES only).
     *
     * @return Optional containing the apu value, empty if null or blank
     */
    public Optional<String> getApu() {
        return nonBlank(apu);
    }

    /**
     * Gets the Agreement PartyVInfo parameter as Optional (JWE ECDH-ES only).
     *
     * @return Optional containing the apv value, empty if null or blank
     */
    public Optional<String> getApv() {
        return nonBlank(apv);
    }

    /**
     * Determines whether this header represents a JWE (JSON Web Encryption) token.
     * <p>
     * A header is considered JWE when the {@code enc} (content encryption algorithm)
     * field is present and non-blank, as defined by RFC 7516.
     *
     * @return {@code true} if this is a JWE header, {@code false} if JWS
     */
    public boolean isJwe() {
        return getEnc().isPresent();
    }

    /**
     * Wraps a header parameter in an Optional, treating null and blank values as absent.
     *
     * @param value the raw header parameter value
     * @return Optional containing the value, empty if null or blank
     */
    private static Optional<String> nonBlank(String value) {
        return Optional.ofNullable(value).filter(s -> !s.isBlank());
    }
}