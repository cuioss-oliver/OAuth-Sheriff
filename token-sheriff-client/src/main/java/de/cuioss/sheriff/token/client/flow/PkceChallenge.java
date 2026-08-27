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
package de.cuioss.sheriff.token.client.flow;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

/**
 * A PKCE {@code S256} code challenge/verifier pair (RFC 7636).
 * <p>
 * The high-entropy {@code code_verifier} is generated from a {@link SecureRandom} and the
 * {@code code_challenge} is {@code BASE64URL(SHA-256(code_verifier))}. Only the {@code S256}
 * transform is supported — the {@code plain} method is deliberately omitted so a downgrade to it can
 * never occur ({@code CLIENT-2}). The verifier is a secret and is never logged nor placed in a URL;
 * only the derived challenge travels on the authorization request.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7636">RFC 7636 - Proof Key for Code Exchange</a>
 */
public final class PkceChallenge {

    /** The only supported PKCE code-challenge method (SHA-256). */
    public static final String METHOD_S256 = "S256";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();
    private static final int VERIFIER_ENTROPY_BYTES = 32;

    private final String codeVerifier;
    private final String codeChallenge;

    private PkceChallenge(String codeVerifier, String codeChallenge) {
        this.codeVerifier = codeVerifier;
        this.codeChallenge = codeChallenge;
    }

    /**
     * Generates a fresh {@code S256} challenge from a cryptographically strong random verifier.
     *
     * @return a new challenge/verifier pair
     */
    public static PkceChallenge generate() {
        byte[] entropy = new byte[VERIFIER_ENTROPY_BYTES];
        SECURE_RANDOM.nextBytes(entropy);
        String verifier = BASE64_URL.encodeToString(entropy);
        String challenge = BASE64_URL.encodeToString(sha256(verifier));
        return new PkceChallenge(verifier, challenge);
    }

    /**
     * @return the secret {@code code_verifier} sent only on the back-channel token exchange
     */
    public String codeVerifier() {
        return codeVerifier;
    }

    /**
     * @return the {@code code_challenge} sent on the front-channel authorization request
     */
    public String codeChallenge() {
        return codeChallenge;
    }

    /**
     * @return the code-challenge method, always {@link #METHOD_S256}
     */
    public String method() {
        return METHOD_S256;
    }

    private static byte[] sha256(String verifier) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required for PKCE S256 but is unavailable", e);
        }
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        return other instanceof PkceChallenge that
                && codeVerifier.equals(that.codeVerifier)
                && codeChallenge.equals(that.codeChallenge);
    }

    @Override
    public int hashCode() {
        return Objects.hash(codeVerifier, codeChallenge);
    }
}
