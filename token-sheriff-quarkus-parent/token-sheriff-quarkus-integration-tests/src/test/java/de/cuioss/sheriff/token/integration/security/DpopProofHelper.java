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
package de.cuioss.sheriff.token.integration.security;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

/**
 * Test helper for generating RFC 9449 DPoP proofs for integration tests.
 * Uses only {@code java.security.*} — no JWT library dependency required.
 * <p>
 * Pattern borrowed from {@code DpopPipelineIntegrationTest} in token-sheriff-validation.
 */
public class DpopProofHelper {

    private final KeyPair keyPair;
    private final Map<String, Object> jwkMap;
    private final String jwkJson;

    /**
     * Creates a helper over a freshly generated RSA key pair.
     */
    public DpopProofHelper() {
        this(generateRsaKeyPair());
    }

    /**
     * Creates a helper over a caller-supplied key pair, so the same proof key can be presented across
     * several legs of one flow — for example the acquisition and the refresh leg of a
     * sender-constrained exchange, where {@code cnf.jkt} continuity is the property under test.
     *
     * @param keyPair the RSA key pair to sign proofs with; its public key is advertised in the
     *                proof header's {@code jwk}
     */
    public DpopProofHelper(KeyPair keyPair) {
        this.keyPair = keyPair;
        this.jwkMap = rsaPublicKeyToJwkMap((RSAPublicKey) keyPair.getPublic());
        this.jwkJson = mapToJson(jwkMap);
    }

    /**
     * Creates a DPoP proof for the Keycloak token endpoint.
     * Includes {@code htm} and {@code htu} claims (Keycloak requires these).
     * No {@code ath} claim since we don't have an access token yet.
     */
    public String createTokenEndpointProof(String tokenEndpointUrl) {
        String bodyJson = """
                {"jti":"%s","iat":%d,"htm":"POST","htu":"%s"}""".formatted(
                UUID.randomUUID().toString(),
                System.currentTimeMillis() / 1000,
                tokenEndpointUrl);
        return buildSignedProof(bodyJson);
    }

    /**
     * Creates a DPoP proof for the resource server with {@code ath}, {@code htm}, and {@code htu} claims.
     * RFC 9449 requires all three for resource server DPoP validation.
     */
    public String createResourceProof(String rawAccessToken) {
        return createResourceProof(rawAccessToken, "POST", null);
    }

    /**
     * Creates a DPoP proof for the resource server with {@code ath}, {@code htm}, and {@code htu} claims.
     *
     * @param rawAccessToken the raw access token string for ath computation
     * @param htm            the HTTP method
     * @param htu            the HTTP URI (optional — omitted if null)
     */
    public String createResourceProof(String rawAccessToken, String htm, String htu) {
        var sb = new StringBuilder();
        sb.append("{\"jti\":\"%s\",\"iat\":%d,\"ath\":\"%s\",\"htm\":\"%s\"".formatted(
                UUID.randomUUID().toString(),
                System.currentTimeMillis() / 1000,
                computeAth(rawAccessToken),
                htm));
        if (htu != null) {
            sb.append(",\"htu\":\"%s\"".formatted(htu));
        }
        sb.append("}");
        return buildSignedProof(sb.toString());
    }

    /**
     * Creates a DPoP proof with a custom {@code iat} timestamp (for stale proof testing).
     */
    public String createResourceProofWithIat(String rawAccessToken, long iatSeconds) {
        String bodyJson = """
                {"jti":"%s","iat":%d,"ath":"%s","htm":"POST","htu":"https://localhost/jwt/validate"}""".formatted(
                UUID.randomUUID().toString(),
                iatSeconds,
                computeAth(rawAccessToken));
        return buildSignedProof(bodyJson);
    }

    /**
     * Creates a DPoP proof with a wrong {@code ath} value (for ath mismatch testing).
     */
    public String createResourceProofWithAth(String wrongAth) {
        String bodyJson = """
                {"jti":"%s","iat":%d,"ath":"%s","htm":"POST","htu":"https://localhost/jwt/validate"}""".formatted(
                UUID.randomUUID().toString(),
                System.currentTimeMillis() / 1000,
                wrongAth);
        return buildSignedProof(bodyJson);
    }

    /**
     * Creates a DPoP proof with a specific {@code jti} (for replay testing).
     */
    public String createResourceProofWithJti(String rawAccessToken, String jti, String htm, String htu) {
        String bodyJson = """
                {"jti":"%s","iat":%d,"ath":"%s","htm":"%s","htu":"%s"}""".formatted(
                jti,
                System.currentTimeMillis() / 1000,
                computeAth(rawAccessToken),
                htm, htu);
        return buildSignedProof(bodyJson);
    }

    /**
     * Creates a new DpopProofHelper with a different key pair (for wrong-key testing).
     */
    public static DpopProofHelper createWithDifferentKey() {
        return new DpopProofHelper();
    }

    // === Internal helpers ===

    private String buildSignedProof(String bodyJson) {
        String headerJson = """
                {"typ":"dpop+jwt","alg":"RS256","jwk":%s}""".formatted(jwkJson);

        String encodedHeader = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String encodedBody = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(bodyJson.getBytes(StandardCharsets.UTF_8));
        String dataToSign = encodedHeader + "." + encodedBody;

        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(keyPair.getPrivate());
            signer.update(dataToSign.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = signer.sign();
            String encodedSignature = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(signatureBytes);
            return dataToSign + "." + encodedSignature;
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new IllegalStateException("Failed to sign DPoP proof", e);
        }
    }

    private static String computeAth(String accessToken) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(accessToken.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            return gen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA not available", e);
        }
    }

    private static Map<String, Object> rsaPublicKeyToJwkMap(RSAPublicKey publicKey) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("kty", "RSA");
        map.put("n", Base64.getUrlEncoder().withoutPadding()
                .encodeToString(toUnsignedBytes(publicKey.getModulus())));
        map.put("e", Base64.getUrlEncoder().withoutPadding()
                .encodeToString(toUnsignedBytes(publicKey.getPublicExponent())));
        return map;
    }

    private static byte[] toUnsignedBytes(BigInteger bigInteger) {
        byte[] bytes = bigInteger.toByteArray();
        if (bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    private static String mapToJson(Map<String, Object> map) {
        var sb = new StringBuilder("{");
        boolean first = true;
        for (var entry : map.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(entry.getKey()).append("\":\"").append(entry.getValue()).append('"');
        }
        sb.append('}');
        return sb.toString();
    }
}
