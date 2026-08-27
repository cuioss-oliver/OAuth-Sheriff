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
import de.cuioss.tools.logging.CuiLogger;

import java.math.BigInteger;
import java.util.Base64;
import java.util.Optional;
import java.util.regex.Pattern;


/**
 * Represents a JSON Web Key (JWK) for DSL-JSON mapping.
 * <p>
 * This class uses DSL-JSON's compile-time code generation for high-performance
 * JSON parsing without reflection. It supports both RSA and EC key types.
 * <p>
 * RSA keys have: kty, kid, alg, n (modulus), e (exponent)
 * EC keys have: kty, kid, alg, crv (curve), x, y (coordinates)
 * <p>
 * The kty field is nullable to support permissive JSON parsing - business rule
 * validation should happen later in the validation chain.
 * 
 * @since 1.0
 * @author Generated
 */
@CompiledJson
public record JwkKey(
String kty,    // Key type: "RSA", "EC"
String kid,   // Key ID (optional)
String alg,   // Algorithm: "RS256", "ES256", etc. (optional)
String n,     // RSA modulus (Base64url-encoded, RSA only)
String e,     // RSA exponent (Base64url-encoded, RSA only)
String crv,   // EC curve: "P-256", "P-384", "P-521" (EC only)
String x,     // EC x coordinate (Base64url-encoded, EC only)
String y      // EC y coordinate (Base64url-encoded, EC only)
) {

    private static final Pattern BASE64_URL_PATTERN = Pattern.compile("^[A-Za-z0-9\\-_]*=*$");
    private static final CuiLogger LOGGER = new CuiLogger(JwkKey.class);


    /**
     * Gets the key ID as Optional.
     * 
     * @return Optional containing the key ID, empty if null
     */
    public Optional<String> getKid() {
        return Optional.ofNullable(kid);
    }

    /**
     * Gets the algorithm as Optional.
     * 
     * @return Optional containing the algorithm, empty if null
     */
    public Optional<String> getAlg() {
        return Optional.ofNullable(alg);
    }


    /**
     * Gets the EC curve as Optional.
     * 
     * @return Optional containing the EC curve, empty if null
     */
    public Optional<String> getCrv() {
        return Optional.ofNullable(crv);
    }


    /**
     * Gets the RSA modulus as BigInteger with Base64 URL decoding and validation.
     * 
     * @return Optional containing the decoded modulus as BigInteger, empty if null or invalid
     */
    public Optional<BigInteger> getModulusAsBigInteger() {
        return decodeBase64UrlToBigInteger(n);
    }

    /**
     * Gets the RSA exponent as BigInteger with Base64 URL decoding and validation.
     * 
     * @return Optional containing the decoded exponent as BigInteger, empty if null or invalid
     */
    public Optional<BigInteger> getExponentAsBigInteger() {
        return decodeBase64UrlToBigInteger(e);
    }

    /**
     * Gets the EC x coordinate as BigInteger with Base64 URL decoding and validation.
     * 
     * @return Optional containing the decoded x coordinate as BigInteger, empty if null or invalid
     */
    public Optional<BigInteger> getXCoordinateAsBigInteger() {
        return decodeBase64UrlToBigInteger(x);
    }

    /**
     * Gets the EC y coordinate as BigInteger with Base64 URL decoding and validation.
     * 
     * @return Optional containing the decoded y coordinate as BigInteger, empty if null or invalid
     */
    public Optional<BigInteger> getYCoordinateAsBigInteger() {
        return decodeBase64UrlToBigInteger(y);
    }

    /**
     * Gets the x coordinate as raw bytes with Base64 URL decoding and validation.
     * This is needed for OKP (Octet Key Pair) keys where the x coordinate
     * represents the raw public key bytes rather than a BigInteger coordinate.
     *
     * @return Optional containing the decoded x coordinate as byte array, empty if null or invalid
     */
    public Optional<byte[]> getXCoordinateAsBytes() {
        return decodeBase64UrlToBytes(x);
    }

    /**
     * Helper method to decode Base64 URL encoded string to byte array with validation.
     *
     * @param base64String the Base64 URL encoded string
     * @return Optional containing the decoded byte array, empty if null, blank, or invalid
     */
    private Optional<byte[]> decodeBase64UrlToBytes(String base64String) {
        if (base64String == null || base64String.isBlank()) {
            return Optional.empty();
        }

        if (!BASE64_URL_PATTERN.matcher(base64String).matches()) {
            LOGGER.warn(TransportLogMessages.WARN.INVALID_BASE64_URL_ENCODING, base64String);
            return Optional.empty();
        }

        try {
            return Optional.of(Base64.getUrlDecoder().decode(base64String));
        } catch (IllegalArgumentException e) {
            LOGGER.warn(TransportLogMessages.WARN.INVALID_BASE64_URL_ENCODING, base64String);
            return Optional.empty();
        }
    }

    /**
     * Helper method to decode Base64 URL encoded string to BigInteger with validation.
     *
     * @param base64String the Base64 URL encoded string
     * @return Optional containing the decoded BigInteger, empty if null, blank, or invalid
     */
    private Optional<BigInteger> decodeBase64UrlToBigInteger(String base64String) {
        return decodeBase64UrlToBytes(base64String)
                .map(decoded -> new BigInteger(1, decoded));
    }
}