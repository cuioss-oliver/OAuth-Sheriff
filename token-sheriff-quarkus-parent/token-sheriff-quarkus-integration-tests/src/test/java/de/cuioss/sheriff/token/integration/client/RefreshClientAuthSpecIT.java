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
package de.cuioss.sheriff.token.integration.client;

import de.cuioss.sheriff.token.client.auth.ClientAuthentication;
import de.cuioss.sheriff.token.client.auth.ClientAuthenticationSelector;
import de.cuioss.sheriff.token.client.auth.ClientSecretBasicAuth;
import de.cuioss.sheriff.token.client.auth.ClientSecretPostAuth;
import de.cuioss.sheriff.token.client.auth.PrivateKeyJwtAuth;
import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import de.cuioss.sheriff.token.client.discovery.ProviderMetadata;
import de.cuioss.sheriff.token.client.flow.RefreshFlow;
import de.cuioss.sheriff.token.client.flow.TokenEndpointClient;
import de.cuioss.sheriff.token.client.token.RotationResult;
import de.cuioss.sheriff.token.client.token.TokenResponse;
import de.cuioss.sheriff.token.client.token.TokenValidationBridge;
import de.cuioss.sheriff.token.integration.BaseIntegrationTest;
import de.cuioss.sheriff.token.integration.TestRealm;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Drives the {@code refresh_token} leg through the production client-authentication strategies other
 * than {@code client_secret_basic}, against the real Keycloak container.
 * <p>
 * The engine ships four strategies behind {@link ClientAuthenticationSelector}, but only
 * {@link ClientSecretBasicAuth} had ever authenticated a refresh against a real authorization server:
 * every other refresh spec in this module builds its flow from
 * {@link RefreshEngineSupport#clientAuthentication(ClientConfiguration)}, which is Basic. This spec
 * closes {@link ClientSecretPostAuth} and {@link PrivateKeyJwtAuth}, and pins the selector's routing
 * against the realm's genuinely advertised {@code token_endpoint_auth_methods_supported}.
 * <p>
 * {@code MtlsClientAuth} is deliberately absent: it is a transport-layer binding the client transport
 * cannot honor (no client key material is plumbed through the {@code SSLContext}), and
 * {@link ClientAuthenticationSelector} skips {@code tls_client_auth} for exactly that reason. Driving
 * it would need certificate infrastructure this fixture does not have.
 *
 * <h2>Ephemeral {@code private_key_jwt} key material</h2>
 * The assertion signing key is generated per test run and its public half is pushed onto the realm's
 * {@code private-key-jwt-client} through {@link KeycloakAdminSupport}. No private key is committed:
 * the realm import ships {@code use.jwks.string=true} with no {@code jwks.string}, so a failed
 * registration cannot be masked by a stale inline key — the {@code private_key_jwt} tests would fail
 * with {@code invalid_client} instead of silently passing against the wrong key.
 *
 * <h2>The {@code private_key_jwt} audience trap</h2>
 * The assertion audience must be {@link RefreshEngineSupport#INTERNAL_TOKEN_ENDPOINT} — the endpoint URL
 * the realm derives from its own {@code frontendUrl} — even though the request is sent to the
 * externally reachable {@link RefreshEngineSupport#TOKEN_ENDPOINT}. Audiencing the assertion at the
 * URL actually connected to is rejected with {@code invalid_client / Invalid token audience}.
 */
@DisplayName("RefreshFlow client authentication against real Keycloak")
class RefreshClientAuthSpecIT extends BaseIntegrationTest {

    private static final String FAST_CLIENT_ID = "refresh-fast-client";
    private static final String FAST_CLIENT_SECRET = "refresh-fast-secret";

    private static final String PRIVATE_KEY_JWT_CLIENT_ID = "private-key-jwt-client";

    /** {@code kid} this fixture registers the generated public key under. */
    private static final String PRIVATE_KEY_JWT_KEY_ID = "private-key-jwt-test-key";

    private static final String PRIVATE_KEY_JWT_ALGORITHM = "RS256";

    /** Realm the {@code private_key_jwt} client lives in. */
    private static final String REALM = "integration";

    /** RSA key size for the generated assertion signing key. */
    private static final int PRIVATE_KEY_JWT_KEY_SIZE = 2048;

    /** Assertion signing key, generated per run and registered on the realm client by {@link #registerAssertionSigningKey()}. */
    private static KeyPair assertionSigningKey;

    /**
     * Generates the {@code private_key_jwt} signing key and registers its public half on the realm's
     * {@code private-key-jwt-client}. Any failure — key generation, admin authentication, a missing
     * client, or a rejected update — propagates and fails the whole class; it is never downgraded to a
     * skip, because a skipped {@code private_key_jwt} spec is indistinguishable from a passing one in
     * CI.
     *
     * @throws NoSuchAlgorithmException never in practice — RSA is a mandatory JDK algorithm
     */
    @BeforeAll
    static void registerAssertionSigningKey() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(PRIVATE_KEY_JWT_KEY_SIZE);
        assertionSigningKey = generator.generateKeyPair();

        KeycloakAdminSupport.registerSigningJwk(REALM, PRIVATE_KEY_JWT_CLIENT_ID, PRIVATE_KEY_JWT_KEY_ID,
                (RSAPublicKey) assertionSigningKey.getPublic());
    }

    @Test
    @DisplayName("Should refresh with client_secret_post client authentication")
    void shouldRefreshWithClientSecretPost() {
        TestRealm.TokenResponse acquired = TestRealm.createFastRefreshRealm().obtainValidToken();
        assertNotNull(acquired.refreshToken(), "the fast-expiry client must issue a refresh token");

        ClientConfiguration configuration = RefreshEngineSupport.clientConfiguration(
                FAST_CLIENT_ID, FAST_CLIENT_SECRET, ClientAuthMethod.CLIENT_SECRET_POST);
        ClientAuthentication postAuth = new ClientSecretPostAuth(FAST_CLIENT_ID, FAST_CLIENT_SECRET);
        RefreshFlow refreshFlow = RefreshEngineSupport.refreshFlow(configuration,
                accessBridge(), postAuth);

        RotationResult rotation =
                refreshFlow.refresh(RefreshEngineSupport.providerMetadata(), acquired.refreshToken());

        assertAll("client_secret_post refresh",
                () -> assertTrue(rotation.rotated(), "the AS must accept the body-carried credentials"),
                () -> assertNotEquals(acquired.refreshToken(), rotation.refreshToken(),
                        "the rotated refresh token must differ from the redeemed one"),
                () -> assertEquals(KeycloakUrlSupport.INTERNAL_ISSUER, rotation.accessToken().getIssuer(),
                        "the validated access token must carry the realm's issuer identity"));
    }

    @Test
    @DisplayName("Should refresh with private_key_jwt client authentication")
    void shouldRefreshWithPrivateKeyJwt() {
        ClientConfiguration configuration = RefreshEngineSupport.clientConfiguration(
                PRIVATE_KEY_JWT_CLIENT_ID, null, ClientAuthMethod.PRIVATE_KEY_JWT);
        ClientAuthentication assertionAuth = privateKeyJwtAuth();

        String acquiredRefreshToken = acquireRefreshToken(configuration, assertionAuth);
        RefreshFlow refreshFlow =
                RefreshEngineSupport.refreshFlow(configuration, accessBridge(), assertionAuth);

        RotationResult rotation =
                refreshFlow.refresh(RefreshEngineSupport.providerMetadata(), acquiredRefreshToken);

        assertAll("private_key_jwt refresh",
                () -> assertTrue(rotation.rotated(), "the AS must accept the signed client assertion"),
                () -> assertNotEquals(acquiredRefreshToken, rotation.refreshToken(),
                        "the rotated refresh token must differ from the redeemed one"),
                () -> assertEquals(KeycloakUrlSupport.INTERNAL_ISSUER, rotation.accessToken().getIssuer(),
                        "the validated access token must carry the realm's issuer identity"),
                () -> assertTrue(rotation.accessToken().getSubject().isPresent(),
                        "the validated access token must be subject bound"));
    }

    @Test
    @DisplayName("Should select private_key_jwt over a shared secret and refresh with the selection")
    void shouldSelectPrivateKeyJwtAndRefreshWithIt() {
        ClientConfiguration configuration = RefreshEngineSupport.clientConfiguration(
                PRIVATE_KEY_JWT_CLIENT_ID, null, ClientAuthMethod.PRIVATE_KEY_JWT);
        ClientAuthentication assertionAuth = privateKeyJwtAuth();
        ProviderMetadata metadata = RefreshEngineSupport.providerMetadata();
        // The realm genuinely advertises both, verified against its live discovery document; the
        // selector must therefore have a real choice to make rather than a single candidate.
        metadata.tokenEndpointAuthMethodsSupported =
                List.of("client_secret_basic", "client_secret_post", "private_key_jwt", "tls_client_auth");

        ClientAuthentication selected = new ClientAuthenticationSelector().select(
                List.of(new ClientSecretBasicAuth(PRIVATE_KEY_JWT_CLIENT_ID, "unused-shared-secret"),
                        assertionAuth),
                metadata);

        assertEquals(ClientAuthMethod.PRIVATE_KEY_JWT, selected.method(),
                "the selector must prefer the key-based method over the shared secret");

        String acquiredRefreshToken = acquireRefreshToken(configuration, selected);
        RotationResult rotation = RefreshEngineSupport.refreshFlow(configuration, accessBridge(), selected)
                .refresh(metadata, acquiredRefreshToken);

        assertTrue(rotation.rotated(),
                "the selected strategy must actually authenticate the refresh at the AS");
    }

    private static TokenValidationBridge accessBridge() {
        return RefreshEngineSupport.accessTokenBridge(RefreshEngineSupport.tokenValidator());
    }

    /**
     * Acquires a refresh token for a client the shared {@link TestRealm} fixture cannot serve, because
     * that fixture always posts a {@code client_secret} and a {@code client-jwt} client has none.
     * The acquisition runs over the production {@link TokenEndpointClient} with the production
     * {@link ClientAuthentication} decorating the request, so the credential presented on the
     * acquisition is the same one the refresh leg will present.
     *
     * @param configuration        the client configuration carrying the TLS policy
     * @param clientAuthentication the strategy to authenticate the acquisition with
     * @return the acquired refresh token
     */
    private static String acquireRefreshToken(ClientConfiguration configuration,
            ClientAuthentication clientAuthentication) {
        Map<String, String> form = new HashMap<>(Map.of(
                "grant_type", "password",
                "username", "integration-user",
                "password", "integration-password",
                "scope", "openid profile email"));
        Map<String, String> headers = new HashMap<>();
        clientAuthentication.decorate(form, headers);

        TokenResponse acquired = new TokenEndpointClient(configuration)
                .requestToken(RefreshEngineSupport.TOKEN_ENDPOINT, form, headers);
        assertNotNull(acquired.refreshToken, "the acquisition must issue a refresh token to redeem");
        return acquired.refreshToken;
    }

    /**
     * @return {@code private_key_jwt} authentication over the run-generated signing key registered by
     *         {@link #registerAssertionSigningKey()}, audienced at the realm's own (internal) token
     *         endpoint — see the class-level audience note
     */
    private static PrivateKeyJwtAuth privateKeyJwtAuth() {
        return new PrivateKeyJwtAuth(PRIVATE_KEY_JWT_CLIENT_ID, RefreshEngineSupport.INTERNAL_TOKEN_ENDPOINT,
                assertionSigningKey.getPrivate(), PRIVATE_KEY_JWT_KEY_ID, PRIVATE_KEY_JWT_ALGORITHM);
    }
}
