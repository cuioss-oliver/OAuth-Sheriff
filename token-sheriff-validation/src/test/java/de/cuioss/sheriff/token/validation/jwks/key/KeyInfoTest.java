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

import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for {@link KeyInfo}.
 *
 * @author Oliver Wolff
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("KeyInfo")
class KeyInfoTest {

    private static final String RSA_ALGORITHM = "RS256";
    private static final String EC_ALGORITHM = "ES256";
    private static final String KEY_ID = "test-key-1";

    private PublicKey rsaPublicKey;
    private PublicKey ecPublicKey;

    @BeforeEach
    void setup() throws Exception {
        // Generate RSA key pair using standard JDK providers
        KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
        rsaGenerator.initialize(2048);
        KeyPair rsaKeyPair = rsaGenerator.generateKeyPair();
        rsaPublicKey = rsaKeyPair.getPublic();

        // Generate EC key pair using standard JDK providers
        KeyPairGenerator ecGenerator = KeyPairGenerator.getInstance("EC");
        ecGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ecKeyPair = ecGenerator.generateKeyPair();
        ecPublicKey = ecKeyPair.getPublic();
    }

    @Test
    @DisplayName("Should create KeyInfo with valid RSA key parameters")
    void shouldCreateKeyInfoWithValidRsaKeyParameters() {
        KeyInfo keyInfo = new KeyInfo(rsaPublicKey, RSA_ALGORITHM, KEY_ID);

        assertEquals(rsaPublicKey, keyInfo.key());
        assertEquals(RSA_ALGORITHM, keyInfo.algorithm());
        assertEquals(KEY_ID, keyInfo.keyId());
        assertInstanceOf(RSAPublicKey.class, keyInfo.key());
    }

    @Test
    @DisplayName("Should create KeyInfo with valid EC key parameters")
    void shouldCreateKeyInfoWithValidEcKeyParameters() {
        KeyInfo keyInfo = new KeyInfo(ecPublicKey, EC_ALGORITHM, KEY_ID);

        assertEquals(ecPublicKey, keyInfo.key());
        assertEquals(EC_ALGORITHM, keyInfo.algorithm());
        assertEquals(KEY_ID, keyInfo.keyId());
        assertInstanceOf(ECPublicKey.class, keyInfo.key());
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when key is null")
    void shouldThrowIllegalArgumentExceptionWhenKeyIsNull() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> new KeyInfo(null, RSA_ALGORITHM, KEY_ID));
        assertEquals("Key cannot be null", exception.getMessage());
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when algorithm is null")
    void shouldThrowIllegalArgumentExceptionWhenAlgorithmIsNull() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> new KeyInfo(rsaPublicKey, null, KEY_ID));
        assertEquals("Algorithm cannot be null", exception.getMessage());
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when keyId is null")
    void shouldThrowIllegalArgumentExceptionWhenKeyIdIsNull() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> new KeyInfo(rsaPublicKey, RSA_ALGORITHM, null));
        assertEquals("KeyId cannot be null", exception.getMessage());
    }

    @Test
    @DisplayName("Should implement equals and hashCode correctly")
    void shouldImplementEqualsAndHashCodeCorrectly() {
        KeyInfo keyInfo1 = new KeyInfo(rsaPublicKey, RSA_ALGORITHM, KEY_ID);
        KeyInfo keyInfo2 = new KeyInfo(rsaPublicKey, RSA_ALGORITHM, KEY_ID);
        KeyInfo keyInfo3 = new KeyInfo(ecPublicKey, EC_ALGORITHM, KEY_ID);

        assertEquals(keyInfo1, keyInfo2);
        assertEquals(keyInfo1.hashCode(), keyInfo2.hashCode());
        assertNotEquals(keyInfo1, keyInfo3);
    }

    @Test
    @DisplayName("Should have proper toString representation")
    void shouldHaveProperToStringRepresentation() {
        KeyInfo keyInfo = new KeyInfo(rsaPublicKey, RSA_ALGORITHM, KEY_ID);
        String toString = keyInfo.toString();

        assertNotNull(toString);
        assertTrue(toString.contains("KeyInfo"));
        assertTrue(toString.contains(RSA_ALGORITHM));
        assertTrue(toString.contains(KEY_ID));
    }

    @Test
    @DisplayName("Should handle different algorithm types")
    void shouldHandleDifferentAlgorithmTypes() {
        String[] algorithms = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"};

        for (String algorithm : algorithms) {
            KeyInfo keyInfo = new KeyInfo(rsaPublicKey, algorithm, KEY_ID);
            assertEquals(algorithm, keyInfo.algorithm());
        }
    }

    @Test
    @DisplayName("Should handle different key ID formats")
    void shouldHandleDifferentKeyIdFormats() {
        String[] keyIds = {"simple-key", "key_with_underscores", "key-with-dashes", "123456", "key.with.dots"};

        for (String keyId : keyIds) {
            KeyInfo keyInfo = new KeyInfo(rsaPublicKey, RSA_ALGORITHM, keyId);
            assertEquals(keyId, keyInfo.keyId());
        }
    }

}
