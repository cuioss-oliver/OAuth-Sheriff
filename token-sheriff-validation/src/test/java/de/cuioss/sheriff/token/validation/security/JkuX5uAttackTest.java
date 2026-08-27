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
package de.cuioss.sheriff.token.validation.security;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter.EventType;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.test.InMemoryKeyMaterialHandler;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Certifies the real defense against JKU (JWK Set URL) / X5U (X.509 URL) header-injection attacks (H4).
 * <p>
 * A JKU/X5U attack instructs the validator to fetch and trust key material from an attacker-controlled
 * URL carried in the token header. Token-Sheriff's defense is that it <em>never</em> honors {@code jku}
 * or {@code x5u}: signature verification is driven exclusively by the pre-configured issuer JWKS, so a
 * token whose signature only verifies against the attacker's advertised key is rejected.
 * <p>
 * Both tests below construct the attack the honest way (mirroring
 * {@link WiredNegativePathAttackTest}): the token is <em>re-signed</em> with an attacker RSA key and
 * carries a {@code jku}/{@code x5u} header pointing at that attacker's key set, while presenting the
 * configured {@code kid}. If the library honored the header it would fetch the attacker key and accept
 * the token; because it uses the configured key instead, verification fails with
 * {@link EventType#SIGNATURE_VALIDATION_FAILED}. A mutation that made the validator fetch keys from the
 * {@code jku}/{@code x5u} URL would make the attacker signature verify and turn both tests red — so the
 * rejection is attributable to the named defense, not to an incidental broken signature.
 */
@DisplayName("Tests for JKU/X5U Header Abuse Protection")
class JkuX5uAttackTest {

    private static final String TEST_ISSUER = "https://jku-x5u-attack-test.example.com";
    private static final String TEST_AUDIENCE = "test-client";
    private static final String DEFAULT_KEY_ID = InMemoryKeyMaterialHandler.DEFAULT_KEY_ID;
    private static final String ATTACKER_JKU = "https://attacker-controlled-site.com/jwks.json";
    private static final String ATTACKER_X5U = "https://attacker-controlled-site.com/keys.pem";

    private TokenValidator tokenValidator;

    @BeforeEach
    void setUp() {
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuerIdentifier(TEST_ISSUER)
                .expectedAudience(TEST_AUDIENCE)
                .jwksContent(InMemoryKeyMaterialHandler.createDefaultJwks())
                .build();
        tokenValidator = TokenValidator.builder()
                .parserConfig(ParserConfig.builder().build())
                .issuerConfig(issuerConfig)
                .build();
    }

    @Test
    @DisplayName("Should reject a token whose signature only verifies against a JKU-advertised attacker key")
    void shouldRejectTokenWithJkuHeader() {
        // Attacker signs the token with their own key and advertises the matching key set via `jku`,
        // presenting the configured kid. The validator ignores `jku` and verifies against the configured
        // key, so the attacker signature fails — proving the library never fetched the advertised keys.
        String forged = forgeAttackerToken("jku", ATTACKER_JKU);

        var request = AccessTokenRequest.of(forged);
        var ex = assertThrows(TokenValidationException.class,
                () -> tokenValidator.createAccessToken(request),
                "A token trusting a jku-advertised attacker key must be rejected");
        assertEquals(EventType.SIGNATURE_VALIDATION_FAILED, ex.getEventType(),
                "Rejection must come from the configured-key signature check, not the jku header");
        assertEquals(1, tokenValidator.getSecurityEventCounter().getCount(EventType.SIGNATURE_VALIDATION_FAILED),
                "Exactly one signature-validation failure must be recorded for the jku attack");
    }

    @Test
    @DisplayName("Should reject a token whose signature only verifies against an X5U-advertised attacker key")
    void shouldRejectTokenWithX5uHeader() {
        // Same honest construction as the jku case, advertising the attacker key set via `x5u`.
        String forged = forgeAttackerToken("x5u", ATTACKER_X5U);

        var request = AccessTokenRequest.of(forged);
        var ex = assertThrows(TokenValidationException.class,
                () -> tokenValidator.createAccessToken(request),
                "A token trusting an x5u-advertised attacker key must be rejected");
        assertEquals(EventType.SIGNATURE_VALIDATION_FAILED, ex.getEventType(),
                "Rejection must come from the configured-key signature check, not the x5u header");
        assertEquals(1, tokenValidator.getSecurityEventCounter().getCount(EventType.SIGNATURE_VALIDATION_FAILED),
                "Exactly one signature-validation failure must be recorded for the x5u attack");
    }

    /**
     * Builds a well-formed RS256 access token signed with a freshly generated attacker key and carrying
     * a {@code jku}/{@code x5u} header pointing at the attacker's advertised key set. The configured
     * {@code kid} and issuer are used so validation reaches (and fails at) the signature check.
     */
    private String forgeAttackerToken(String headerName, String attackerUrl) {
        KeyPair attackerKeyPair = generateRsaKeyPair();
        return Jwts.builder()
                .header().keyId(DEFAULT_KEY_ID).add(headerName, attackerUrl).and()
                .issuer(TEST_ISSUER)
                .subject("attacker")
                .audience().add(TEST_AUDIENCE).and()
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusSeconds(3600)))
                .signWith(attackerKeyPair.getPrivate(), Jwts.SIG.RS256)
                .compact();
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
}
