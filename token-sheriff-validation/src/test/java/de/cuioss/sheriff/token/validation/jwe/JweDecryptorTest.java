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
package de.cuioss.sheriff.token.validation.jwe;

import com.dslplatform.json.DslJson;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.json.JwtHeader;
import de.cuioss.sheriff.token.validation.test.InMemoryKeyMaterialHandler;
import de.cuioss.sheriff.token.validation.test.JweTestTokenFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("JweDecryptor Tests")
class JweDecryptorTest {

    private JweDecryptor decryptor;
    private SecurityEventCounter counter;
    private KeyPair rsaEncryptionKeyPair;
    private DslJson<Object> dslJson;

    @BeforeEach
    void setUp() {
        decryptor = new JweDecryptor();
        counter = new SecurityEventCounter();
        rsaEncryptionKeyPair = JweTestTokenFactory.generateRsaKeyPair();
        dslJson = ParserConfig.builder().build().getDslJson();
    }

    @Nested
    @DisplayName("RSA-OAEP Algorithm Tests")
    class RsaOaepTests {

        @ParameterizedTest
        @CsvSource({
                "RSA-OAEP, A128GCM",
                "RSA-OAEP, A256GCM",
                "RSA-OAEP, A128CBC-HS256",
                "RSA-OAEP, A256CBC-HS512",
                "RSA-OAEP-256, A128GCM",
                "RSA-OAEP-256, A256GCM",
                "RSA-OAEP-256, A128CBC-HS256",
                "RSA-OAEP-256, A256CBC-HS512"
        })
        @DisplayName("Should decrypt JWE with RSA-OAEP variants")
        void shouldDecryptRsaOaep(String alg, String enc) {
            // Create a JWE token
            String jwe = JweTestTokenFactory.createJweWrappedAccessToken(
                    InMemoryKeyMaterialHandler.getDefaultPrivateKey(),
                    rsaEncryptionKeyPair.getPublic(),
                    "RS256", alg, enc, "https://test-issuer.example.com", "test-kid");

            String[] parts = jwe.split("\\.");
            assertEquals(5, parts.length);

            // Decode header
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            assertTrue(headerJson.contains("\"enc\""));

            // Build config
            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .decryptionKey("test-kid", rsaEncryptionKeyPair.getPrivate())
                    .defaultDecryptionKey(rsaEncryptionKeyPair.getPrivate())
                    .build();

            // Parse header
            JwtHeader header = parseHeader(parts[0]);

            // Decrypt
            String innerJws = decryptor.decrypt(parts, header, config, counter, dslJson);

            // Verify result is a valid JWS (3 parts)
            assertNotNull(innerJws);
            String[] jwsParts = innerJws.split("\\.");
            assertEquals(3, jwsParts.length, "Decrypted content should be a 3-part JWS");

            // Verify no security events were recorded
            assertEquals(0, counter.getCount(SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED));
        }
    }

    @Nested
    @DisplayName("Security Tests")
    class SecurityTests {

        @Test
        @DisplayName("Should reject RSA1_5 algorithm")
        void shouldRejectRsa15() {
            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .defaultDecryptionKey(rsaEncryptionKeyPair.getPrivate())
                    .build();

            // Create a fake header with RSA1_5
            JwtHeader header = new JwtHeader("RSA1_5", null, null, null, null,
                    "A128GCM", null, null, null, null);

            String[] parts = {"header", "encKey", "iv", "ciphertext", "authTag"};

            assertThrows(TokenValidationException.class,
                    () -> decryptor.decrypt(parts, header, config, counter, dslJson));
            assertEquals(1, counter.getCount(SecurityEventCounter.EventType.JWE_UNSUPPORTED_ALGORITHM));
        }

        @Test
        @DisplayName("Should reject unsupported enc algorithm")
        void shouldRejectUnsupportedEnc() {
            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .defaultDecryptionKey(rsaEncryptionKeyPair.getPrivate())
                    .build();

            JwtHeader header = new JwtHeader("RSA-OAEP", null, null, null, null,
                    "A192GCM", null, null, null, null);

            String[] parts = {"header", "encKey", "iv", "ciphertext", "authTag"};

            assertThrows(TokenValidationException.class,
                    () -> decryptor.decrypt(parts, header, config, counter, dslJson));
            assertEquals(1, counter.getCount(SecurityEventCounter.EventType.JWE_UNSUPPORTED_ALGORITHM));
        }

        @Test
        @DisplayName("Should fail with wrong decryption key")
        void shouldFailWithWrongKey() {
            KeyPair wrongKeyPair = JweTestTokenFactory.generateRsaKeyPair();

            String jwe = JweTestTokenFactory.createJweWrappedAccessToken(
                    InMemoryKeyMaterialHandler.getDefaultPrivateKey(),
                    rsaEncryptionKeyPair.getPublic(),
                    "RS256", "RSA-OAEP", "A256GCM", "https://test-issuer.example.com", null);

            String[] parts = jwe.split("\\.");
            JwtHeader header = parseHeader(parts[0]);

            // Use wrong private key
            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .defaultDecryptionKey(wrongKeyPair.getPrivate())
                    .build();

            assertThrows(TokenValidationException.class,
                    () -> decryptor.decrypt(parts, header, config, counter, dslJson));
        }

        @Test
        @DisplayName("Should fail with tampered auth tag")
        void shouldFailWithTamperedAuthTag() {
            String jwe = JweTestTokenFactory.createJweWithTamperedAuthTag(
                    InMemoryKeyMaterialHandler.getDefaultPrivateKey(),
                    rsaEncryptionKeyPair.getPublic(),
                    "https://test-issuer.example.com");

            String[] parts = jwe.split("\\.");
            JwtHeader header = parseHeader(parts[0]);

            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .defaultDecryptionKey(rsaEncryptionKeyPair.getPrivate())
                    .build();

            assertThrows(TokenValidationException.class,
                    () -> decryptor.decrypt(parts, header, config, counter, dslJson));
        }

        @Test
        @DisplayName("Should fail with tampered ciphertext")
        void shouldFailWithTamperedCiphertext() {
            String jwe = JweTestTokenFactory.createJweWithTamperedCiphertext(
                    InMemoryKeyMaterialHandler.getDefaultPrivateKey(),
                    rsaEncryptionKeyPair.getPublic(),
                    "https://test-issuer.example.com");

            String[] parts = jwe.split("\\.");
            JwtHeader header = parseHeader(parts[0]);

            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .defaultDecryptionKey(rsaEncryptionKeyPair.getPrivate())
                    .build();

            assertThrows(TokenValidationException.class,
                    () -> decryptor.decrypt(parts, header, config, counter, dslJson));
        }

        @Test
        @DisplayName("Should fail when no key matches kid")
        void shouldFailWhenNoKeyMatchesKid() {
            String jwe = JweTestTokenFactory.createJweWrappedAccessToken(
                    InMemoryKeyMaterialHandler.getDefaultPrivateKey(),
                    rsaEncryptionKeyPair.getPublic(),
                    "RS256", "RSA-OAEP", "A256GCM", "https://test-issuer.example.com", "unknown-kid");

            String[] parts = jwe.split("\\.");
            JwtHeader header = parseHeader(parts[0]);

            // Config with different kid, no default
            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .decryptionKey("other-kid", rsaEncryptionKeyPair.getPrivate())
                    .build();

            assertThrows(TokenValidationException.class,
                    () -> decryptor.decrypt(parts, header, config, counter, dslJson));
            assertEquals(1, counter.getCount(SecurityEventCounter.EventType.JWE_DECRYPTION_KEY_NOT_FOUND));
        }
    }

    @Nested
    @DisplayName("Key Resolution Tests")
    class KeyResolutionTests {

        @Test
        @DisplayName("Should resolve key by kid")
        void shouldResolveKeyByKid() {
            String jwe = JweTestTokenFactory.createJweWrappedAccessToken(
                    InMemoryKeyMaterialHandler.getDefaultPrivateKey(),
                    rsaEncryptionKeyPair.getPublic(),
                    "RS256", "RSA-OAEP", "A256GCM", "https://test-issuer.example.com", "my-kid");

            String[] parts = jwe.split("\\.");
            JwtHeader header = parseHeader(parts[0]);

            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .decryptionKey("my-kid", rsaEncryptionKeyPair.getPrivate())
                    .build();

            String innerJws = decryptor.decrypt(parts, header, config, counter, dslJson);
            assertNotNull(innerJws);
            assertEquals(3, innerJws.split("\\.").length);
        }

        @Test
        @DisplayName("Should fall back to default key when kid not found")
        void shouldFallBackToDefaultKey() {
            String jwe = JweTestTokenFactory.createJweWrappedAccessToken(
                    InMemoryKeyMaterialHandler.getDefaultPrivateKey(),
                    rsaEncryptionKeyPair.getPublic(),
                    "RS256", "RSA-OAEP", "A256GCM", "https://test-issuer.example.com", "unknown-kid");

            String[] parts = jwe.split("\\.");
            JwtHeader header = parseHeader(parts[0]);

            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .defaultDecryptionKey(rsaEncryptionKeyPair.getPrivate())
                    .build();

            String innerJws = decryptor.decrypt(parts, header, config, counter, dslJson);
            assertNotNull(innerJws);
        }
    }

    @Nested
    @DisplayName("ECDH-ES Algorithm Tests")
    class EcdhEsTests {

        @ParameterizedTest
        @CsvSource({
                "secp256r1, A128GCM",
                "secp256r1, A256GCM",
                "secp384r1, A128GCM",
                "secp384r1, A256GCM"
        })
        @DisplayName("Should decrypt JWE with ECDH-ES")
        void shouldDecryptEcdhEs(String curve, String enc) {
            KeyPair recipientKeyPair = JweTestTokenFactory.generateEcKeyPair(curve);
            KeyPair ephemeralKeyPair = JweTestTokenFactory.generateEcKeyPair(curve);

            String jwe = JweTestTokenFactory.createEcdhEsJweWrappedAccessToken(
                    InMemoryKeyMaterialHandler.getDefaultPrivateKey(),
                    ephemeralKeyPair,
                    (ECPublicKey) recipientKeyPair.getPublic(),
                    enc, "https://test-issuer.example.com");

            String[] parts = jwe.split("\\.");
            assertEquals(5, parts.length);

            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .defaultDecryptionKey(recipientKeyPair.getPrivate())
                    .build();

            JwtHeader header = parseHeader(parts[0]);

            String innerJws = decryptor.decrypt(parts, header, config, counter, dslJson);
            assertNotNull(innerJws);
            assertEquals(3, innerJws.split("\\.").length);
            assertEquals(0, counter.getCount(SecurityEventCounter.EventType.JWE_DECRYPTION_FAILED));
        }

        @Test
        @DisplayName("Should fail ECDH-ES with RSA key")
        void shouldFailEcdhEsWithRsaKey() {
            KeyPair ecKeyPair = JweTestTokenFactory.generateEcKeyPair("secp256r1");
            KeyPair ephemeralKeyPair = JweTestTokenFactory.generateEcKeyPair("secp256r1");

            String jwe = JweTestTokenFactory.createEcdhEsJweWrappedAccessToken(
                    InMemoryKeyMaterialHandler.getDefaultPrivateKey(),
                    ephemeralKeyPair,
                    (ECPublicKey) ecKeyPair.getPublic(),
                    "A128GCM", "https://test-issuer.example.com");

            String[] parts = jwe.split("\\.");
            JwtHeader header = parseHeader(parts[0]);

            // Use RSA key for ECDH-ES — should fail
            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .defaultDecryptionKey(rsaEncryptionKeyPair.getPrivate())
                    .build();

            assertThrows(TokenValidationException.class,
                    () -> decryptor.decrypt(parts, header, config, counter, dslJson));
        }

        @Test
        @DisplayName("Should reject ECDH-ES with mismatched curve (Invalid Curve Attack)")
        void shouldRejectMismatchedCurve() {
            // Recipient key on P-384, but ephemeral key on P-256
            KeyPair recipientKeyPair = JweTestTokenFactory.generateEcKeyPair("secp384r1");
            KeyPair ephemeralKeyPair = JweTestTokenFactory.generateEcKeyPair("secp256r1");

            String jwe = JweTestTokenFactory.createEcdhEsJweWrappedAccessToken(
                    InMemoryKeyMaterialHandler.getDefaultPrivateKey(),
                    ephemeralKeyPair,
                    (ECPublicKey) JweTestTokenFactory.generateEcKeyPair("secp256r1").getPublic(),
                    "A128GCM", "https://test-issuer.example.com");

            String[] parts = jwe.split("\\.");
            JwtHeader header = parseHeader(parts[0]);

            // Use P-384 private key for decryption — should reject due to curve mismatch
            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .defaultDecryptionKey(recipientKeyPair.getPrivate())
                    .build();

            TokenValidationException ex = assertThrows(TokenValidationException.class,
                    () -> decryptor.decrypt(parts, header, config, counter, dslJson));
            assertTrue(ex.getMessage().contains("curve does not match"));
        }

        @Test
        @DisplayName("L6: should reject an off-curve ephemeral point independent of the provider")
        void shouldRejectOffCurveEphemeralPoint() {
            String curve = "secp256r1";
            KeyPair recipientKeyPair = JweTestTokenFactory.generateEcKeyPair(curve);
            KeyPair ephemeralKeyPair = JweTestTokenFactory.generateEcKeyPair(curve);

            String jwe = JweTestTokenFactory.createEcdhEsJweWrappedAccessToken(
                    InMemoryKeyMaterialHandler.getDefaultPrivateKey(),
                    ephemeralKeyPair,
                    (ECPublicKey) recipientKeyPair.getPublic(),
                    "A128GCM", "https://test-issuer.example.com");

            String[] parts = jwe.split("\\.");
            // Move the embedded ephemeral point off the curve by mutating the first character of its
            // x coordinate. Curve parameters still match the recipient key, so only the independent
            // on-curve check can catch this — exactly the provider-independent guard under test.
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            int keyIdx = headerJson.indexOf("\"x\"");
            assertTrue(keyIdx >= 0, "The ECDH-ES header must embed an epk x coordinate");
            int valueStart = headerJson.indexOf('"', headerJson.indexOf(':', keyIdx) + 1) + 1;
            char original = headerJson.charAt(valueStart);
            char replacement = original == 'A' ? 'B' : 'A';
            String tamperedJson = headerJson.substring(0, valueStart) + replacement
                    + headerJson.substring(valueStart + 1);
            parts[0] = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(tamperedJson.getBytes(StandardCharsets.UTF_8));

            JwtHeader header = parseHeader(parts[0]);
            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .defaultDecryptionKey(recipientKeyPair.getPrivate())
                    .build();

            TokenValidationException ex = assertThrows(TokenValidationException.class,
                    () -> decryptor.decrypt(parts, header, config, counter, dslJson));
            assertTrue(ex.getMessage().contains("Ephemeral EC point"),
                    "An off-curve ephemeral point must be rejected by the independent on-curve check, but was: "
                            + ex.getMessage());
        }

        @Test
        @DisplayName("L7: RSA-OAEP-256 is preferred over the SHA-1 MGF1 RSA-OAEP variant")
        void shouldPreferOaep256OverSha1Mgf1() {
            assertEquals("RSA-OAEP-256", JweAlgorithmPreferences.getPreferredKeyManagementAlgorithm());
            assertEquals("RSA-OAEP-256", JweAlgorithmPreferences.getDefaultKeyManagementAlgorithms().getFirst(),
                    "OAEP-256 must be listed ahead of the SHA-1 MGF1 RSA-OAEP variant");
            assertTrue(JweAlgorithmPreferences.getDefaultKeyManagementAlgorithms().contains("RSA-OAEP"),
                    "RSA-OAEP is retained for interoperability");
        }

        @Test
        @DisplayName("Should fail ECDH-ES without epk in header")
        void shouldFailEcdhEsWithoutEpk() {
            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .defaultDecryptionKey(JweTestTokenFactory.generateEcKeyPair("secp256r1").getPrivate())
                    .build();

            // Header with ECDH-ES but no epk
            JwtHeader header = new JwtHeader("ECDH-ES", null, null, null, null,
                    "A128GCM", null, null, null, null);

            String[] parts = {"header", "", "iv", "ciphertext", "authTag"};

            assertThrows(TokenValidationException.class,
                    () -> decryptor.decrypt(parts, header, config, counter, dslJson));
        }
    }

    @Nested
    @DisplayName("Compression Tests")
    class CompressionTests {

        @Test
        @DisplayName("Should decrypt JWE with DEFLATE compression")
        void shouldDecryptWithDeflateCompression() {
            String jwe = JweTestTokenFactory.createCompressedJwe(
                    InMemoryKeyMaterialHandler.getDefaultPrivateKey(),
                    rsaEncryptionKeyPair.getPublic(),
                    "RSA-OAEP", "A256GCM", "https://test-issuer.example.com");

            String[] parts = jwe.split("\\.");
            assertEquals(5, parts.length);

            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .defaultDecryptionKey(rsaEncryptionKeyPair.getPrivate())
                    .compressionEnabled(true)
                    .build();

            JwtHeader header = parseHeader(parts[0]);
            assertTrue(header.getZip().isPresent());
            assertEquals("DEF", header.getZip().get());

            String innerJws = decryptor.decrypt(parts, header, config, counter, dslJson);
            assertNotNull(innerJws);
            assertEquals(3, innerJws.split("\\.").length);
        }

        @Test
        @DisplayName("Should reject unsupported compression algorithm")
        void shouldRejectUnsupportedCompression() {
            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .defaultDecryptionKey(rsaEncryptionKeyPair.getPrivate())
                    .build();

            JwtHeader header = new JwtHeader("RSA-OAEP", null, null, null, null,
                    "A256GCM", "GZIP", null, null, null);

            String[] parts = {"header", "encKey", "iv", "ciphertext", "authTag"};

            TokenValidationException ex = assertThrows(TokenValidationException.class,
                    () -> decryptor.decrypt(parts, header, config, counter, dslJson));
            assertTrue(ex.getMessage().contains("Unsupported compression"));
        }

        @Test
        @DisplayName("Should reject compression when disabled")
        void shouldRejectCompressionWhenDisabled() {
            JweDecryptionConfig config = JweDecryptionConfig.builder()
                    .defaultDecryptionKey(rsaEncryptionKeyPair.getPrivate())
                    .compressionEnabled(false)
                    .build();

            JwtHeader header = new JwtHeader("RSA-OAEP", null, null, null, null,
                    "A256GCM", "DEF", null, null, null);

            String[] parts = {"header", "encKey", "iv", "ciphertext", "authTag"};

            TokenValidationException ex = assertThrows(TokenValidationException.class,
                    () -> decryptor.decrypt(parts, header, config, counter, dslJson));
            assertTrue(ex.getMessage().contains("compression is disabled"));
        }
    }

    private static JwtHeader parseHeader(String encodedHeader) {
        String json = new String(Base64.getUrlDecoder().decode(encodedHeader), StandardCharsets.UTF_8);
        // Simple extraction for test purposes
        String alg = extractField(json, "alg");
        String enc = extractField(json, "enc");
        String kid = extractField(json, "kid");
        String zip = extractField(json, "zip");
        String epk = extractEpkObject(json);
        return new JwtHeader(alg, null, kid, null, null,
                enc, zip, epk, null, null);
    }

    private static String extractField(String json, String field) {
        String key = "\"" + field + "\":\"";
        int idx = json.indexOf(key);
        if (idx < 0) return null;
        int start = idx + key.length();
        int end = json.indexOf('"', start);
        return end > start ? json.substring(start, end) : null;
    }

    private static String extractEpkObject(String json) {
        String key = "\"epk\":";
        int idx = json.indexOf(key);
        if (idx < 0) return null;
        int start = idx + key.length();
        // Find matching closing brace
        int depth = 0;
        for (int i = start; i < json.length(); i++) {
            if (json.charAt(i) == '{') depth++;
            else if (json.charAt(i) == '}') {
                depth--;
                if (depth == 0) return json.substring(start, i + 1);
            }
        }
        return null;
    }
}
