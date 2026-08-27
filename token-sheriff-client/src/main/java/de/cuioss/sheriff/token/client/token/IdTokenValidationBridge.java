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
package de.cuioss.sheriff.token.client.token;

import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.context.IdTokenRequest;
import de.cuioss.sheriff.token.validation.domain.token.IdTokenContent;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Bridges an OpenID Connect ID token into the {@code token-sheriff-validation} pipeline and binds it
 * to the flow {@code nonce} ({@code CLIENT-6} / {@code CLIENT-16}).
 * <p>
 * The ID token is validated through the same multi-issuer pipeline that guards inbound tokens
 * (signature, {@code iss}, {@code aud}, {@code exp} / {@code iat}), and the {@code nonce} claim is
 * then compared, in constant time, against the {@code nonce} the client generated for this flow. A
 * mismatch — the signature of a replayed or injected ID token — fails closed. The client never
 * trusts an ID token on the strength of a successful HTTP exchange alone.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation">OIDC Core §3.1.3.7</a>
 */
public class IdTokenValidationBridge {

    private static final String NONCE_CLAIM = "nonce";
    private static final String AT_HASH_CLAIM = "at_hash";
    private static final Pattern JWS_ALG_PATTERN = Pattern.compile("\"alg\"\\s*:\\s*\"([^\"]+)\"");

    private final TokenValidator tokenValidator;

    /**
     * @param tokenValidator the configured multi-issuer validator; must not be {@code null}
     */
    public IdTokenValidationBridge(TokenValidator tokenValidator) {
        this.tokenValidator = Objects.requireNonNull(tokenValidator, "tokenValidator must not be null");
    }

    /**
     * Validates an ID token and asserts its {@code nonce} matches the expected flow nonce.
     *
     * @param idToken       the raw ID token string; must not be {@code null}
     * @param expectedNonce the {@code nonce} the client generated for this flow; must not be
     *                      {@code null}
     * @return the validated ID token content
     * @throws de.cuioss.sheriff.token.validation.exception.TokenValidationException if the token
     *         fails pipeline validation
     * @throws ClientProtocolException if the ID token carries no {@code nonce} or it does not match
     */
    public IdTokenContent validateIdToken(String idToken, String expectedNonce) {
        Objects.requireNonNull(idToken, "idToken must not be null");
        Objects.requireNonNull(expectedNonce, "expectedNonce must not be null");

        IdTokenContent content = tokenValidator.createIdToken(IdTokenRequest.of(idToken));

        ClaimValue nonceClaim = content.getClaims().get(NONCE_CLAIM);
        String actualNonce = nonceClaim == null ? null : nonceClaim.getOriginalString();
        if (!noncesMatch(expectedNonce, actualNonce)) {
            throw new ClientProtocolException("ID token 'nonce' does not match the flow nonce");
        }
        return content;
    }

    /**
     * Validates an ID token, asserts its {@code nonce}, and — when the ID token carries an
     * {@code at_hash} — asserts that hash binds the accompanying access token (OIDC Core §3.1.3.6, M4).
     * <p>
     * {@code at_hash} is the base64url encoding of the left-most half of the hash of the ASCII octets
     * of the access token, where the hash function is selected by the ID token's JWS {@code alg}
     * (SHA-256 for {@code *256}, SHA-384 for {@code *384}, SHA-512 for {@code *512}). A present but
     * non-matching {@code at_hash} means the ID token and access token were not issued together and
     * fails closed. {@code at_hash} is OPTIONAL in the {@code authorization_code} flow, so an absent
     * claim is not an error — there is simply nothing to bind.
     *
     * @param idToken       the raw ID token string; must not be {@code null}
     * @param expectedNonce the {@code nonce} the client generated for this flow; must not be
     *                      {@code null}
     * @param accessToken   the access token the ID token should bind via {@code at_hash}; must not be
     *                      {@code null}
     * @return the validated ID token content
     * @throws de.cuioss.sheriff.token.validation.exception.TokenValidationException if the token
     *         fails pipeline validation
     * @throws ClientProtocolException if the {@code nonce} does not match, or the ID token asserts an
     *         {@code at_hash} that does not bind the supplied access token
     */
    public IdTokenContent validateIdToken(String idToken, String expectedNonce, String accessToken) {
        Objects.requireNonNull(accessToken, "accessToken must not be null");
        IdTokenContent content = validateIdToken(idToken, expectedNonce);
        verifyAccessTokenHash(idToken, content, accessToken);
        return content;
    }

    private static void verifyAccessTokenHash(String idToken, IdTokenContent content, String accessToken) {
        ClaimValue atHashClaim = content.getClaims().get(AT_HASH_CLAIM);
        if (atHashClaim == null) {
            // at_hash is OPTIONAL in the authorization_code flow (OIDC Core §3.1.3.6); when the OP does
            // not assert it there is nothing to bind, so the binding check is skipped, not failed.
            return;
        }
        String expected = atHashClaim.getOriginalString();
        String computed = computeAccessTokenHash(idToken, accessToken);
        if (expected == null || !MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                computed.getBytes(StandardCharsets.UTF_8))) {
            throw new ClientProtocolException("ID token 'at_hash' does not bind the access token");
        }
    }

    private static String computeAccessTokenHash(String idToken, String accessToken) {
        MessageDigest digest = accessTokenHashDigest(idToken);
        byte[] hash = digest.digest(accessToken.getBytes(StandardCharsets.US_ASCII));
        byte[] leftHalf = Arrays.copyOf(hash, hash.length / 2);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(leftHalf);
    }

    private static MessageDigest accessTokenHashDigest(String idToken) {
        String alg = jwsAlgorithm(idToken);
        String shaAlgorithm;
        if (alg.endsWith("384")) {
            shaAlgorithm = "SHA-384";
        } else if (alg.endsWith("512")) {
            shaAlgorithm = "SHA-512";
        } else {
            shaAlgorithm = "SHA-256";
        }
        try {
            return MessageDigest.getInstance(shaAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("unsupported at_hash digest " + shaAlgorithm, e);
        }
    }

    private static String jwsAlgorithm(String idToken) {
        int dot = idToken.indexOf('.');
        if (dot <= 0) {
            return "";
        }
        String header = new String(Base64.getUrlDecoder().decode(idToken.substring(0, dot)),
                StandardCharsets.UTF_8);
        Matcher matcher = JWS_ALG_PATTERN.matcher(header);
        return matcher.find() ? matcher.group(1) : "";
    }

    /**
     * Validates an ID token returned on a {@code refresh_token} exchange, without a {@code nonce}
     * check (OIDC Core §12.2).
     * <p>
     * A refreshed ID token is validated through the same multi-issuer pipeline (signature,
     * {@code iss}, {@code aud}, {@code exp} / {@code iat}) as an authorization-code ID token, but the
     * {@code nonce} is deliberately not asserted: §12.2 states the ID token issued on a refresh
     * SHOULD NOT carry a {@code nonce}, and no fresh flow {@code nonce} exists to compare against. The
     * caller instead enforces the §12.2 {@code iss}/{@code sub} consistency against the refreshed
     * access token.
     *
     * @param idToken the raw refreshed ID token string; must not be {@code null}
     * @return the validated ID token content
     * @throws de.cuioss.sheriff.token.validation.exception.TokenValidationException if the token
     *         fails pipeline validation
     */
    public IdTokenContent validateRefreshedIdToken(String idToken) {
        Objects.requireNonNull(idToken, "idToken must not be null");
        return tokenValidator.createIdToken(IdTokenRequest.of(idToken));
    }

    private static boolean noncesMatch(String expected, String actual) {
        if (actual == null) {
            return false;
        }
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }
}
