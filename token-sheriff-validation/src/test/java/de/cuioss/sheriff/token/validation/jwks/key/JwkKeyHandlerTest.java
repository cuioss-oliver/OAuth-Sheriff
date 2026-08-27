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
package de.cuioss.sheriff.token.validation.jwks.key;

import de.cuioss.sheriff.token.commons.transport.JwkKey;
import de.cuioss.sheriff.token.commons.transport.TransportLogMessages;
import de.cuioss.sheriff.token.validation.test.InMemoryKeyMaterialHandler;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.Key;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link JwkKeyHandler} with a focus on security aspects and potential attacks.
 */
@EnableTestLogger
class JwkKeyHandlerTest {

    private JwkKey createRsaJwk() {
        // Use hardcoded RSA values from InMemoryJWKSFactory for testing
        // These are Base64 URL encoded RSA parameters from the test factory
        return new JwkKey(
                "RSA",
                "test-key",
                "RS256",
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "AQAB",
                null, null, null
        );
    }

    private JwkKey createRsaJwk(String n, String e) {
        return new JwkKey("RSA", "test-key", null, n, e, null, null, null);
    }

    private JwkKey createEcJwk(String x, String y) {
        return new JwkKey("EC", "test-key", null, null, null, "P-256", x, y);
    }

    @Test
    void shouldParseValidRsaKey() throws Exception {
        JwkKey jwk = createRsaJwk();
        Key key = JwkKeyHandler.parseRsaKey(jwk);
        assertNotNull(key, "RSA key should not be null");
        assertEquals("RSA", key.getAlgorithm(), "Key algorithm should be RSA");
    }

    @Test
    void shouldValidateRsaKeyFields() {
        JwkKey jwk = createRsaJwk();
        assertDoesNotThrow(() -> JwkKeyHandler.parseRsaKey(jwk));
    }

    @Test
    void shouldRejectRsaKeyWithMissingModulus() {
        JwkKey jwk = createRsaJwk(null, "AQAB");

        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.parseRsaKey(jwk)
        );
        assertTrue(exception.getMessage().contains("Invalid Base64 URL encoded value for 'n'"), exception.getMessage());
    }

    @Test
    void shouldRejectRsaKeyWithMissingExponent() {
        JwkKey jwk = createRsaJwk("someModulus", null);

        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.parseRsaKey(jwk)
        );
        assertTrue(exception.getMessage().contains("Invalid Base64 URL encoded value for 'e'"));
    }

    @Test
    void shouldRejectRsaKeyWithInvalidBase64UrlModulus() {
        JwkKey jwk = createRsaJwk("invalid!base64", "AQAB");

        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.parseRsaKey(jwk)
        );
        assertTrue(exception.getMessage().contains("Invalid Base64 URL encoded value for 'n'"), exception.getMessage());

        // Verify that the warning was logged for invalid characters
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "invalid!base64");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                TransportLogMessages.WARN.INVALID_BASE64_URL_ENCODING.resolveIdentifierString());
    }

    @Test
    void shouldRejectRsaKeyWithInvalidBase64UrlExponent() {
        JwkKey jwk = createRsaJwk("validModulus", "invalid!base64");

        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.parseRsaKey(jwk)
        );
        assertTrue(exception.getMessage().contains("Invalid Base64 URL encoded value for 'e'"));

        // Verify that the warning was logged for invalid characters
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "invalid!base64");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                TransportLogMessages.WARN.INVALID_BASE64_URL_ENCODING.resolveIdentifierString());
    }

    @Test
    void shouldRejectEcKeyWithMissingXCoordinate() {
        JwkKey jwk = createEcJwk(null, "validYCoord");
        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.parseEcKey(jwk)
        );

        assertTrue(exception.getMessage().contains("Invalid Base64 URL encoded value for 'x'"), exception.getMessage());
    }

    @Test
    void shouldRejectEcKeyWithMissingYCoordinate() {
        JwkKey jwk = createEcJwk("validXCoord", null);

        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.parseEcKey(jwk)
        );

        assertTrue(exception.getMessage().contains("Invalid Base64 URL encoded value for 'y'"), exception.getMessage());
    }

    @Test
    void shouldRejectEcKeyWithInvalidBase64UrlXCoordinate() {
        JwkKey jwk = createEcJwk("invalid!base64", "validYCoord");

        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.parseEcKey(jwk)
        );

        assertTrue(exception.getMessage().contains("Invalid Base64 URL encoded value for 'x'"), "Actual message: " + exception.getMessage());

        // Verify that the warning was logged for invalid characters
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "invalid!base64");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                TransportLogMessages.WARN.INVALID_BASE64_URL_ENCODING.resolveIdentifierString());
    }

    @Test
    void shouldRejectEcKeyWithInvalidBase64UrlYCoordinate() {
        JwkKey jwk = createEcJwk("validXCoord", "invalid!base64");

        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.parseEcKey(jwk)
        );

        assertTrue(exception.getMessage().contains("Invalid Base64 URL encoded value for 'y'"), exception.getMessage());

        // Verify that the warning was logged for invalid characters
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "invalid!base64");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                TransportLogMessages.WARN.INVALID_BASE64_URL_ENCODING.resolveIdentifierString());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "P-256", "P-384", "P-521"
    })
    void shouldDetermineCorrectEcAlgorithm(String curve) {
        String algorithm = JwkKeyHandler.determineEcAlgorithm(curve);

        switch (curve) {
            case "P-256":
                assertEquals("ES256", algorithm, "Algorithm should be ES256 for P-256 curve");
                break;
            case "P-384":
                assertEquals("ES384", algorithm, "Algorithm should be ES384 for P-384 curve");
                break;
            case "P-521":
                assertEquals("ES512", algorithm, "Algorithm should be ES512 for P-521 curve");
                break;
            default:
                fail("Unexpected curve: " + curve);
        }
    }

    @Test
    void shouldRejectRsaKeyWithBase64Padding() {
        // This tests the specific case where Base64 URL should NOT have padding
        // Base64 URL (RFC 4648) explicitly forbids padding characters
        // Testing with "abc==" which has padding characters
        JwkKey jwk = createRsaJwk("abc==", "AQAB");  // Double padding - definitely invalid for Base64 URL

        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.parseRsaKey(jwk)
        );
        assertTrue(exception.getMessage().contains("Invalid Base64 URL encoded value for 'n'"),
                "Should reject Base64 with padding, actual message: " + exception.getMessage());

        // Verify that the warning was logged
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "abc==");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                TransportLogMessages.WARN.INVALID_BASE64_URL_ENCODING.resolveIdentifierString());
    }

    @Test
    void shouldRejectEcKeyWithBase64Padding() {
        // Test EC key with Base64 padding in coordinates
        JwkKey jwk = createEcJwk("validX", "abc==");  // Double padding - definitely invalid for Base64 URL

        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.parseEcKey(jwk)
        );
        assertTrue(exception.getMessage().contains("Invalid Base64 URL encoded value for 'y'"),
                "Should reject Base64 with padding, actual message: " + exception.getMessage());

        // Verify that the warning was logged
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "abc==");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                TransportLogMessages.WARN.INVALID_BASE64_URL_ENCODING.resolveIdentifierString());
    }

    @Test
    void shouldReturnDefaultAlgorithmForUnknownCurve() {
        String curve = "unknown-curve";

        assertThrows(IllegalArgumentException.class, () -> JwkKeyHandler.determineEcAlgorithm(curve),
                "Unknown curve should throw IllegalArgumentException (fail-closed)");
    }

    @Test
    void shouldParseValidEcKey() throws Exception {
        // These are example values for P-256 curve (secp256r1)
        String x = "f83OJ3D2xF4P4QJrL6Z4pWQ2vQKj6k1b6QJ6Qn6QJ6Q";
        String y = "x_FEzRu9QJ6Qn6QJ6QJ6Qn6QJ6Qn6QJ6Qn6QJ6Qn6Q";
        JwkKey jwk = new JwkKey("EC", "test-key", null, null, null, "P-256", x, y);

        Key key = JwkKeyHandler.parseEcKey(jwk);

        assertNotNull(key, "EC key should not be null");
        assertEquals("EC", key.getAlgorithm(), "Key algorithm should be EC");
    }

    @Test
    void shouldRejectEcKeyWithMissingCurve() {
        JwkKey jwk = new JwkKey("EC", "test-key", null, null, null, null, "validXCoord", "validYCoord");

        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.parseEcKey(jwk)
        );

        assertTrue(exception.getMessage().contains("Invalid Base64 URL encoded value for 'crv'"),
                "Actual message: " + exception.getMessage());
    }

    @Test
    void shouldRejectEcKeyWithUnsupportedCurve() {
        JwkKey jwk = new JwkKey("EC", "test-key", null, null, null, "P-192", "validXCoord", "validYCoord");

        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.parseEcKey(jwk)
        );

        assertTrue(exception.getMessage().contains("EC curve P-192 is not supported"),
                "Actual message: " + exception.getMessage());
    }

    // --- OKP / EdDSA Tests ---

    @Test
    void shouldParseValidEd25519Key() throws Exception {
        // Generate a real Ed25519 key pair and extract its JWK x coordinate
        JwkKey jwk = createOkpJwkFromKeyMaterial("Ed25519");

        Key key = JwkKeyHandler.parseOkpKey(jwk);
        assertNotNull(key, "EdDSA key should not be null");
        assertEquals("EdDSA", key.getAlgorithm(), "Key algorithm should be EdDSA");
        assertInstanceOf(EdECPublicKey.class, key, "Key should be an EdECPublicKey");
    }

    @Test
    void shouldRejectOkpKeyWithMissingCurve() {
        JwkKey jwk = new JwkKey("OKP", "test-key", "EdDSA", null, null, null, "validXCoord", null);

        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.parseOkpKey(jwk)
        );

        assertTrue(exception.getMessage().contains("Invalid Base64 URL encoded value for 'crv'"),
                "Actual message: " + exception.getMessage());
    }

    @Test
    void shouldRejectOkpKeyWithUnsupportedCurve() {
        JwkKey jwk = new JwkKey("OKP", "test-key", "EdDSA", null, null, "X25519", "validXCoord", null);

        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.parseOkpKey(jwk)
        );

        assertTrue(exception.getMessage().contains("OKP curve X25519 is not supported"),
                "Actual message: " + exception.getMessage());
    }

    @Test
    void shouldRejectOkpKeyWithMissingX() {
        JwkKey jwk = new JwkKey("OKP", "test-key", "EdDSA", null, null, "Ed25519", null, null);

        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.parseOkpKey(jwk)
        );

        assertTrue(exception.getMessage().contains("Invalid Base64 URL encoded value for 'x'"),
                "Actual message: " + exception.getMessage());
    }

    @Test
    void shouldRejectOkpKeyWithInvalidBase64UrlX() {
        JwkKey jwk = new JwkKey("OKP", "test-key", "EdDSA", null, null, "Ed25519", "invalid!base64", null);

        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.parseOkpKey(jwk)
        );

        assertTrue(exception.getMessage().contains("Invalid Base64 URL encoded value for 'x'"),
                "Actual message: " + exception.getMessage());

        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "invalid!base64");
    }

    @Test
    void shouldDetermineOkpAlgorithm() {
        assertEquals("EdDSA", JwkKeyHandler.determineOkpAlgorithm());
        assertEquals("EdDSA", JwkKeyHandler.determineOkpAlgorithm());
    }

    /**
     * Helper: creates a JwkKey from real key material generated by JJWT.
     */
    private JwkKey createOkpJwkFromKeyMaterial(String curve) {
        var publicKey = (EdECPublicKey) InMemoryKeyMaterialHandler.getDefaultPublicKey(
                InMemoryKeyMaterialHandler.Algorithm.ED_DSA);
        String xEncoded = InMemoryKeyMaterialHandler.encodeEdECPublicKey(publicKey);
        return new JwkKey("OKP", "test-ed-key", "EdDSA", null, null, curve, xEncoded, null);
    }

}
