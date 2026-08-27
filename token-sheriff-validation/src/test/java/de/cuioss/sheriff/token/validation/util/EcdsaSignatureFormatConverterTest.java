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
package de.cuioss.sheriff.token.validation.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link EcdsaSignatureFormatConverter}.
 */
@DisplayName("Tests EcdsaSignatureFormatConverter functionality")
class EcdsaSignatureFormatConverterTest {

    @Test
    @DisplayName("Should convert ES256 IEEE P1363 signature to ASN.1/DER format")
    void shouldConvertES256Signature() throws Exception {
        // Create test IEEE P1363 signature for ES256 (64 bytes: 32 for R + 32 for S)
        byte[] ieeeP1363Signature = new byte[64];

        // R component (32 bytes) - example value
        Arrays.fill(ieeeP1363Signature, 0, 32, (byte) 0x12);
        ieeeP1363Signature[0] = (byte) 0x01; // Ensure non-zero MSB
        
        // S component (32 bytes) - example value  
        Arrays.fill(ieeeP1363Signature, 32, 64, (byte) 0x34);
        ieeeP1363Signature[32] = (byte) 0x02; // Ensure non-zero MSB
        
        // Convert to ASN.1/DER format
        byte[] asn1Signature = EcdsaSignatureFormatConverter.toJCACompatibleSignature(ieeeP1363Signature, "ES256");

        // Verify the result is not null and has reasonable length
        assertNotNull(asn1Signature, "Converted signature should not be null");
        assertTrue(asn1Signature.length > 64, "ASN.1/DER signature should be longer than IEEE P1363 due to structure");
        assertTrue(asn1Signature.length < 80, "ASN.1/DER signature should not be excessively long");

        // Verify ASN.1/DER structure
        assertEquals(0x30, asn1Signature[0], "First byte should be SEQUENCE tag (0x30)");

        // Find R component (first INTEGER)
        int rStart = 2; // Skip SEQUENCE tag and length
        assertEquals(0x02, asn1Signature[rStart], "R component should start with INTEGER tag (0x02)");

        // Verify structure is parseable by extracting components
        verifyAsn1Structure(asn1Signature);
    }

    @Test
    @DisplayName("Should convert ES384 IEEE P1363 signature to ASN.1/DER format")
    void shouldConvertES384Signature() throws Exception {
        // Create test IEEE P1363 signature for ES384 (96 bytes: 48 for R + 48 for S)
        byte[] ieeeP1363Signature = new byte[96];

        // R component (48 bytes)
        Arrays.fill(ieeeP1363Signature, 0, 48, (byte) 0x56);
        ieeeP1363Signature[0] = (byte) 0x03; // Ensure non-zero MSB
        
        // S component (48 bytes)
        Arrays.fill(ieeeP1363Signature, 48, 96, (byte) 0x78);
        ieeeP1363Signature[48] = (byte) 0x04; // Ensure non-zero MSB
        
        // Convert to ASN.1/DER format
        byte[] asn1Signature = EcdsaSignatureFormatConverter.toJCACompatibleSignature(ieeeP1363Signature, "ES384");

        // Verify the result
        assertNotNull(asn1Signature, "Converted signature should not be null");
        assertTrue(asn1Signature.length > 96, "ASN.1/DER signature should be longer than IEEE P1363");
        assertEquals(0x30, asn1Signature[0], "First byte should be SEQUENCE tag (0x30)");

        // Verify structure is parseable
        verifyAsn1Structure(asn1Signature);
    }

    @Test
    @DisplayName("Should convert ES512 IEEE P1363 signature to ASN.1/DER format")
    void shouldConvertES512Signature() throws Exception {
        // Create test IEEE P1363 signature for ES512 (132 bytes: 66 for R + 66 for S)
        byte[] ieeeP1363Signature = new byte[132];

        // R component (66 bytes)
        Arrays.fill(ieeeP1363Signature, 0, 66, (byte) 0x9A);
        ieeeP1363Signature[0] = (byte) 0x05; // Ensure non-zero MSB
        
        // S component (66 bytes)
        Arrays.fill(ieeeP1363Signature, 66, 132, (byte) 0xBC);
        ieeeP1363Signature[66] = (byte) 0x06; // Ensure non-zero MSB
        
        // Convert to ASN.1/DER format
        byte[] asn1Signature = EcdsaSignatureFormatConverter.toJCACompatibleSignature(ieeeP1363Signature, "ES512");

        // Verify the result
        assertNotNull(asn1Signature, "Converted signature should not be null");
        assertTrue(asn1Signature.length > 132, "ASN.1/DER signature should be longer than IEEE P1363");
        assertEquals(0x30, asn1Signature[0], "First byte should be SEQUENCE tag (0x30)");

        // Verify structure is parseable
        verifyAsn1Structure(asn1Signature);
    }

    @Test
    @DisplayName("Should handle signatures with leading zeros in R component")
    void shouldHandleLeadingZerosInR() throws Exception {
        // Create IEEE P1363 signature with leading zeros in R component
        byte[] ieeeP1363Signature = new byte[64];

        // R component with leading zeros
        ieeeP1363Signature[0] = 0x00;
        ieeeP1363Signature[1] = 0x00;
        ieeeP1363Signature[2] = (byte) 0x12; // First non-zero byte
        Arrays.fill(ieeeP1363Signature, 3, 32, (byte) 0x34);

        // S component (normal case)
        Arrays.fill(ieeeP1363Signature, 32, 64, (byte) 0x56);
        ieeeP1363Signature[32] = (byte) 0x07; // Ensure non-zero MSB
        
        // Convert should succeed
        byte[] asn1Signature = EcdsaSignatureFormatConverter.toJCACompatibleSignature(ieeeP1363Signature, "ES256");

        assertNotNull(asn1Signature, "Conversion should succeed with leading zeros");
        verifyAsn1Structure(asn1Signature);
    }

    @Test
    @DisplayName("Should handle signatures with leading zeros in S component")
    void shouldHandleLeadingZerosInS() throws Exception {
        // Create IEEE P1363 signature with leading zeros in S component
        byte[] ieeeP1363Signature = new byte[64];

        // R component (normal case)
        Arrays.fill(ieeeP1363Signature, 0, 32, (byte) 0x78);
        ieeeP1363Signature[0] = (byte) 0x08; // Ensure non-zero MSB
        
        // S component with leading zeros
        ieeeP1363Signature[32] = 0x00;
        ieeeP1363Signature[33] = 0x00;
        ieeeP1363Signature[34] = (byte) 0x9A; // First non-zero byte
        Arrays.fill(ieeeP1363Signature, 35, 64, (byte) 0xBC);

        // Convert should succeed
        byte[] asn1Signature = EcdsaSignatureFormatConverter.toJCACompatibleSignature(ieeeP1363Signature, "ES256");

        assertNotNull(asn1Signature, "Conversion should succeed with leading zeros");
        verifyAsn1Structure(asn1Signature);
    }

    @Test
    @DisplayName("Should handle all-zero R or S components")
    void shouldHandleZeroComponents() throws Exception {
        // Create signature with zero R component (edge case)
        byte[] ieeeP1363Signature = new byte[64];

        // R component: all zeros
        Arrays.fill(ieeeP1363Signature, 0, 32, (byte) 0x00);

        // S component: non-zero
        Arrays.fill(ieeeP1363Signature, 32, 64, (byte) 0xDE);
        ieeeP1363Signature[32] = (byte) 0x09; // Ensure non-zero MSB
        
        // Convert should succeed (BigInteger handles zero correctly)
        byte[] asn1Signature = EcdsaSignatureFormatConverter.toJCACompatibleSignature(ieeeP1363Signature, "ES256");

        assertNotNull(asn1Signature, "Conversion should succeed with zero R component");
        verifyAsn1Structure(asn1Signature);
    }

    @ParameterizedTest
    @ValueSource(strings = {"ES256", "es256", "Es256", "ES384", "es384", "ES512", "es512"})
    @DisplayName("Should handle case-insensitive algorithm names")
    void shouldHandleCaseInsensitiveAlgorithms(String algorithm) throws Exception {
        // Determine expected length based on normalized algorithm
        String normalizedAlg = algorithm.toUpperCase();
        int expectedLength = switch (normalizedAlg) {
            case "ES256" -> 64;
            case "ES384" -> 96;
            case "ES512" -> 132;
            default -> throw new IllegalStateException("Unexpected algorithm: " + normalizedAlg);
        };

        // Create appropriate signature
        byte[] ieeeP1363Signature = new byte[expectedLength];
        Arrays.fill(ieeeP1363Signature, (byte) 0xAB);
        ieeeP1363Signature[0] = (byte) 0x0A; // Ensure non-zero MSB
        
        // Convert should succeed regardless of case
        byte[] asn1Signature = EcdsaSignatureFormatConverter.toJCACompatibleSignature(ieeeP1363Signature, algorithm);

        assertNotNull(asn1Signature, "Conversion should succeed with case variations");
        verifyAsn1Structure(asn1Signature);
    }

    @Test
    @DisplayName("Should throw SignatureException for null signature")
    void shouldThrowForNullSignature() {
        var exception = assertThrows(SignatureException.class, () ->
                EcdsaSignatureFormatConverter.toJCACompatibleSignature(null, "ES256"));

        assertEquals("Signature cannot be null", exception.getMessage());
    }

    @Test
    @DisplayName("Should throw SignatureException for unsupported algorithm")
    void shouldThrowForUnsupportedAlgorithm() {
        byte[] signature = new byte[64];

        var exception = assertThrows(SignatureException.class, () ->
                EcdsaSignatureFormatConverter.toJCACompatibleSignature(signature, "RS256"));

        assertTrue(exception.getMessage().contains("Unsupported ECDSA algorithm"));
    }

    @Test
    @DisplayName("Should throw SignatureException for wrong signature length - ES256")
    void shouldThrowForWrongSignatureLengthES256() {
        // ES256 expects 64 bytes, provide 32
        byte[] shortSignature = new byte[32];

        var exception = assertThrows(SignatureException.class, () ->
                EcdsaSignatureFormatConverter.toJCACompatibleSignature(shortSignature, "ES256"));

        assertTrue(exception.getMessage().contains("Invalid ES256 signature length"));
        assertTrue(exception.getMessage().contains("expected 64 bytes, got 32 bytes"));
    }

    @Test
    @DisplayName("Should throw SignatureException for wrong signature length - ES384")
    void shouldThrowForWrongSignatureLengthES384() {
        // ES384 expects 96 bytes, provide 64
        byte[] shortSignature = new byte[64];

        var exception = assertThrows(SignatureException.class, () ->
                EcdsaSignatureFormatConverter.toJCACompatibleSignature(shortSignature, "ES384"));

        assertTrue(exception.getMessage().contains("Invalid ES384 signature length"));
        assertTrue(exception.getMessage().contains("expected 96 bytes, got 64 bytes"));
    }

    @Test
    @DisplayName("Should throw SignatureException for wrong signature length - ES512")
    void shouldThrowForWrongSignatureLengthES512() {
        // ES512 expects 132 bytes, provide 96
        byte[] shortSignature = new byte[96];

        var exception = assertThrows(SignatureException.class, () ->
                EcdsaSignatureFormatConverter.toJCACompatibleSignature(shortSignature, "ES512"));

        assertTrue(exception.getMessage().contains("Invalid ES512 signature length"));
        assertTrue(exception.getMessage().contains("expected 132 bytes, got 96 bytes"));
    }

    @Test
    @DisplayName("Should throw SignatureException for empty signature")
    void shouldThrowForEmptySignature() {
        byte[] emptySignature = new byte[0];

        var exception = assertThrows(SignatureException.class, () ->
                EcdsaSignatureFormatConverter.toJCACompatibleSignature(emptySignature, "ES256"));

        assertTrue(exception.getMessage().contains("Invalid ES256 signature length"));
    }

    @Test
    @DisplayName("Should produce deterministic output for same input")
    void shouldProduceDeterministicOutput() throws Exception {
        byte[] ieeeP1363Signature = new byte[64];
        Arrays.fill(ieeeP1363Signature, 0, 32, (byte) 0x11);
        Arrays.fill(ieeeP1363Signature, 32, 64, (byte) 0x22);

        // Convert multiple times
        byte[] result1 = EcdsaSignatureFormatConverter.toJCACompatibleSignature(ieeeP1363Signature, "ES256");
        byte[] result2 = EcdsaSignatureFormatConverter.toJCACompatibleSignature(ieeeP1363Signature, "ES256");

        assertArrayEquals(result1, result2, "Conversion should produce deterministic results");
    }

    @Nested
    @DisplayName("Outbound ASN.1/DER to IEEE P1363 conversion")
    class ToJoseSignatureTests {

        private static final byte[] PAYLOAD = "dpop-proof-payload".getBytes(StandardCharsets.UTF_8);

        @ParameterizedTest(name = "{0} / {1}")
        @CsvSource({"secp256r1, ES256, 64", "secp384r1, ES384, 96", "secp521r1, ES512, 132"})
        @DisplayName("Should produce a P1363 signature the JDK verifies natively")
        void shouldProduceJdkVerifiableP1363Signature(String curve, String algorithm, int expectedLength) throws Exception {
            var generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(curve));
            KeyPair keyPair = generator.generateKeyPair();

            var signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(keyPair.getPrivate());
            signer.update(PAYLOAD);
            byte[] derSignature = signer.sign();

            byte[] joseSignature = EcdsaSignatureFormatConverter.toJoseSignature(derSignature, algorithm);

            var verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
            verifier.initVerify(keyPair.getPublic());
            verifier.update(PAYLOAD);

            assertAll("JDK-native P1363 verification",
                    () -> assertEquals(expectedLength, joseSignature.length,
                            "P1363 signature width must match the curve"),
                    () -> assertTrue(verifier.verify(joseSignature),
                            "JDK must verify the converted P1363 signature"));
        }

        @ParameterizedTest(name = "{0}")
        @CsvSource({"ES256, 32", "ES384, 48", "ES512, 66"})
        @DisplayName("Should round-trip P1363 to DER and back to the identical bytes")
        void shouldRoundTripP1363ToDerAndBack(String algorithm, int componentSize) throws Exception {
            byte[] original = new byte[componentSize * 2];
            // R keeps the high bit clear, S sets it — exercising both the padded and unpadded DER INTEGER forms
            Arrays.fill(original, 0, componentSize, (byte) 0x42);
            Arrays.fill(original, componentSize, original.length, (byte) 0x99);

            byte[] derSignature = EcdsaSignatureFormatConverter.toJCACompatibleSignature(original, algorithm);
            byte[] roundTripped = EcdsaSignatureFormatConverter.toJoseSignature(derSignature, algorithm);

            assertArrayEquals(original, roundTripped, "P1363 -> DER -> P1363 must be lossless");
        }

        @Test
        @DisplayName("Should left-pad a component whose big-endian form is shorter than the component width")
        void shouldLeftPadShortComponent() throws Exception {
            byte[] original = new byte[64];
            // R: three leading zero bytes DER drops and the conversion must restore
            original[3] = (byte) 0x7F;
            Arrays.fill(original, 4, 32, (byte) 0x11);
            // S: high bit set, so DER prepends a 0x00 pad byte the conversion must strip
            Arrays.fill(original, 32, 64, (byte) 0xF3);

            byte[] derSignature = EcdsaSignatureFormatConverter.toJCACompatibleSignature(original, "ES256");
            byte[] roundTripped = EcdsaSignatureFormatConverter.toJoseSignature(derSignature, "ES256");

            assertArrayEquals(original, roundTripped,
                    "Short and high-bit components must round-trip at full component width");
        }

        @Test
        @DisplayName("Should restore an all-zero component as a zero-filled P1363 component")
        void shouldRestoreZeroComponent() throws Exception {
            byte[] original = new byte[64];
            Arrays.fill(original, 32, 64, (byte) 0x2A);

            byte[] derSignature = EcdsaSignatureFormatConverter.toJCACompatibleSignature(original, "ES256");
            byte[] roundTripped = EcdsaSignatureFormatConverter.toJoseSignature(derSignature, "ES256");

            assertArrayEquals(original, roundTripped, "An all-zero R component must round-trip to 32 zero bytes");
        }

        @Test
        @DisplayName("Should throw SignatureException for null signature")
        void shouldThrowForNullSignature() {
            var exception = assertThrows(SignatureException.class, () ->
                    EcdsaSignatureFormatConverter.toJoseSignature(null, "ES256"));

            assertEquals("Signature cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw SignatureException for unsupported algorithm")
        void shouldThrowForUnsupportedAlgorithm() {
            byte[] derSignature = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};

            var exception = assertThrows(SignatureException.class, () ->
                    EcdsaSignatureFormatConverter.toJoseSignature(derSignature, "RS256"));

            assertTrue(exception.getMessage().contains("Unsupported ECDSA algorithm"),
                    "Message should name the unsupported algorithm rejection");
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("malformedDerSignatures")
        @DisplayName("Should throw SignatureException for malformed DER input")
        void shouldThrowForMalformedDer(String description, byte[] derSignature) {
            var exception = assertThrows(SignatureException.class, () ->
                            EcdsaSignatureFormatConverter.toJoseSignature(derSignature, "ES256"),
                    "Malformed DER (%s) must be rejected".formatted(description));

            assertTrue(exception.getMessage().startsWith("Invalid DER signature"),
                    "Message should identify the malformed DER encoding, was: " + exception.getMessage());
        }

        static Stream<Arguments> malformedDerSignatures() {
            return Stream.of(
                    Arguments.of("empty input", new byte[0]),
                    Arguments.of("wrong SEQUENCE tag", new byte[]{0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}),
                    Arguments.of("truncated after SEQUENCE tag", new byte[]{0x30}),
                    Arguments.of("SEQUENCE length exceeds available bytes", new byte[]{0x30, 0x20, 0x02, 0x01, 0x01}),
                    Arguments.of("unsupported long-form length", new byte[]{0x30, (byte) 0x85, 0x00, 0x00, 0x00, 0x00, 0x01}),
                    Arguments.of("wrong INTEGER tag for R", new byte[]{0x30, 0x06, 0x04, 0x01, 0x01, 0x02, 0x01, 0x01}),
                    Arguments.of("truncated R content", new byte[]{0x30, 0x03, 0x02, 0x05, 0x01}),
                    Arguments.of("zero-length R INTEGER", new byte[]{0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01}),
                    Arguments.of("trailing bytes after S",
                            new byte[]{0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00}),
                    Arguments.of("R component wider than the component size", oversizedRComponent()));
        }

        /**
         * Builds a structurally valid DER SEQUENCE whose R INTEGER carries 33 significant bytes —
         * one more than the ES256 component width.
         */
        static byte[] oversizedRComponent() {
            byte[] derSignature = new byte[40];
            derSignature[0] = 0x30;
            derSignature[1] = 0x26; // 38 content bytes
            derSignature[2] = 0x02;
            derSignature[3] = 0x21; // 33-byte R component
            Arrays.fill(derSignature, 4, 37, (byte) 0x01);
            derSignature[37] = 0x02;
            derSignature[38] = 0x01;
            derSignature[39] = 0x01;
            return derSignature;
        }
    }

    /**
     * Verifies that the ASN.1/DER signature has the correct basic structure.
     * This is a simple structural verification, not a complete ASN.1 parser.
     */
    private void verifyAsn1Structure(byte[] asn1Signature) {
        assertTrue(asn1Signature.length >= 8, "ASN.1 signature should have minimum length");

        // Should start with SEQUENCE tag
        assertEquals(0x30, asn1Signature[0], "Should start with SEQUENCE tag (0x30)");

        // Parse length
        int lengthByte = asn1Signature[1] & 0xFF;
        int contentStart = 2;

        if ((lengthByte & 0x80) != 0) {
            // Long form length
            int lengthBytes = lengthByte & 0x7F;
            contentStart = 2 + lengthBytes;
            assertTrue(contentStart < asn1Signature.length, "Content should start within signature bounds");
        }

        // Should contain two INTEGER components
        int pos = contentStart;

        // First INTEGER (R component)
        assertEquals(0x02, asn1Signature[pos], "R component should start with INTEGER tag (0x02)");

        // Skip R component
        pos++; // Skip INTEGER tag
        assertTrue(pos < asn1Signature.length, "Position should be valid after skipping INTEGER tag");
        int rLength = asn1Signature[pos] & 0xFF;
        pos++; // Skip length byte

        if ((rLength & 0x80) != 0) {
            // Long form length for R - we need to skip the length bytes but keep the actual length value
            int rLengthBytes = rLength & 0x7F;
            assertTrue(pos + rLengthBytes <= asn1Signature.length, "Long form length bytes should be within bounds");
            // For this basic verification, we'll just skip past the long form
            pos += rLengthBytes;
            // In real ASN.1 parsing, we'd read the actual length from these bytes
            // For now, just use a reasonable estimate for ECDSA signatures
            rLength = 32; // Typical for P-256
        }

        assertTrue(pos + rLength <= asn1Signature.length, "R component content should be within bounds");
        pos += rLength; // Skip R content

        // Second INTEGER (S component)
        assertTrue(pos < asn1Signature.length, "S component position should be valid");
        assertEquals(0x02, asn1Signature[pos], "S component should start with INTEGER tag (0x02)");
    }
}