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

import io.restassured.http.ContentType;
import io.restassured.specification.RequestSpecification;

import java.math.BigInteger;
import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static io.restassured.RestAssured.given;

/**
 * Registers ephemeral client key material on the running Keycloak container through the Admin REST API.
 * <p>
 * A {@code private_key_jwt} client must have its <em>public</em> key known to the authorization server.
 * The obvious fixture — commit the key pair and register the public half inline in the realm import —
 * would put a real {@code BEGIN PRIVATE KEY} block into a public repository, so this module instead
 * generates the pair per test run and pushes the public half onto the client at fixture time. The realm
 * import consequently ships {@code use.jwks.string=true} with <em>no</em> {@code jwks.string}: there is
 * no stale key that could keep the tests green if this registration silently failed.
 * <p>
 * Every call asserts its HTTP status and the write is read back and compared, so an unreachable admin
 * API, a rejected update, or a silently ignored attribute fails the fixture loudly rather than degrading
 * into a skipped or falsely passing test.
 * <p>
 * The admin credentials are the container bootstrap pair from {@code docker-compose.yml}
 * ({@code KC_BOOTSTRAP_ADMIN_USERNAME} / {@code KC_BOOTSTRAP_ADMIN_PASSWORD}); the admin interface is
 * reachable on {@link KeycloakUrlSupport#EXTERNAL_BASE} through the {@code 1443:8443} host port mapping.
 */
final class KeycloakAdminSupport {

    /** Bootstrap admin user of the container, from {@code docker-compose.yml}. */
    private static final String ADMIN_USERNAME = "admin";

    /** Bootstrap admin password of the container, from {@code docker-compose.yml}. */
    private static final String ADMIN_PASSWORD = "admin";

    /** Built-in Keycloak client the bootstrap admin authenticates through. */
    private static final String ADMIN_CLI = "admin-cli";

    /** Realm the bootstrap admin lives in. */
    private static final String MASTER_REALM = "master";

    private static final String ATTRIBUTES = "attributes";
    private static final String JWKS_STRING = "jwks.string";
    private static final String USE_JWKS_STRING = "use.jwks.string";

    /**
     * Externally reachable Keycloak authority, split into base and port because
     * {@code BaseIntegrationTest} pins the global REST Assured port to the <em>application</em>
     * container; the admin calls must override it per request.
     */
    private static final URI EXTERNAL = URI.create(KeycloakUrlSupport.EXTERNAL_BASE);

    private KeycloakAdminSupport() {
        // utility class
    }

    /**
     * Registers {@code publicKey} as the sole signing JWK of {@code clientId}, replacing whatever the
     * client carried before, and verifies the write took effect.
     *
     * @param realm     the realm holding the client
     * @param clientId  the {@code clientId} (not the internal UUID) of the client to update
     * @param keyId     the {@code kid} the client assertions will reference
     * @param publicKey the public half of the freshly generated assertion signing key
     * @throws IllegalStateException if the client cannot be found, or if the stored JWKS does not match
     *         what was written — either way the {@code private_key_jwt} tests cannot be trusted
     */
    static void registerSigningJwk(String realm, String clientId, String keyId, RSAPublicKey publicKey) {
        String adminToken = adminAccessToken();
        String internalId = clientInternalId(adminToken, realm, clientId);
        String jwks = signingJwks(keyId, publicKey);

        Map<String, Object> representation = clientRepresentation(adminToken, realm, internalId);
        Map<String, Object> attributes = new HashMap<>(attributesOf(representation));
        attributes.put(USE_JWKS_STRING, "true");
        attributes.put(JWKS_STRING, jwks);
        representation.put(ATTRIBUTES, attributes);

        given().relaxedHTTPSValidation()
                .baseUri(baseUri()).port(EXTERNAL.getPort())
                .auth().oauth2(adminToken)
                .contentType(ContentType.JSON)
                .body(representation)
                .when().put("/admin/realms/{realm}/clients/{id}", realm, internalId)
                .then().statusCode(204);

        Object stored = attributesOf(clientRepresentation(adminToken, realm, internalId)).get(JWKS_STRING);
        if (!jwks.equals(stored)) {
            throw new IllegalStateException("Keycloak did not persist the generated JWKS on client '"
                    + clientId + "' in realm '" + realm + "'; stored value was: " + stored);
        }
    }

    /**
     * @return an access token for the bootstrap admin, obtained from the {@code master} realm
     */
    private static String adminAccessToken() {
        return adminRequest()
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "password")
                .formParam("client_id", ADMIN_CLI)
                .formParam("username", ADMIN_USERNAME)
                .formParam("password", ADMIN_PASSWORD)
                .when().post("/realms/{realm}/protocol/openid-connect/token", MASTER_REALM)
                .then().statusCode(200)
                .extract().path("access_token");
    }

    /**
     * @param adminToken the admin bearer token
     * @param realm      the realm to search
     * @param clientId   the {@code clientId} to resolve
     * @return the internal UUID Keycloak addresses the client by
     * @throws IllegalStateException if no client with that {@code clientId} exists in the realm
     */
    private static String clientInternalId(String adminToken, String realm, String clientId) {
        List<String> ids = adminRequest()
                .auth().oauth2(adminToken)
                .queryParam("clientId", clientId)
                .when().get("/admin/realms/{realm}/clients", realm)
                .then().statusCode(200)
                .extract().jsonPath().getList("id", String.class);
        if (ids.isEmpty()) {
            throw new IllegalStateException(
                    "Realm '" + realm + "' has no client with clientId '" + clientId + "'");
        }
        return ids.getFirst();
    }

    /**
     * @param adminToken the admin bearer token
     * @param realm      the realm holding the client
     * @param internalId the client's internal UUID
     * @return a mutable copy of the client's representation
     */
    private static Map<String, Object> clientRepresentation(String adminToken, String realm, String internalId) {
        return new HashMap<>(adminRequest()
                .auth().oauth2(adminToken)
                .when().get("/admin/realms/{realm}/clients/{id}", realm, internalId)
                .then().statusCode(200)
                .extract().jsonPath().getMap(""));
    }

    /**
     * @param representation a client representation
     * @return its {@code attributes} map, or an empty map when the client carries none
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> attributesOf(Map<String, Object> representation) {
        Object attributes = representation.get(ATTRIBUTES);
        return attributes instanceof Map ? (Map<String, Object>) attributes : Map.of();
    }

    /**
     * @return a request specification addressing the Keycloak admin interface, overriding the global
     *         REST Assured host/port that points at the application container
     */
    private static RequestSpecification adminRequest() {
        return given().relaxedHTTPSValidation().baseUri(baseUri()).port(EXTERNAL.getPort());
    }

    private static String baseUri() {
        return EXTERNAL.getScheme() + "://" + EXTERNAL.getHost();
    }

    /**
     * Renders a single-key JWK Set for {@code publicKey}. All emitted values are base64url or literals,
     * so no JSON escaping is required.
     *
     * @param keyId     the {@code kid}
     * @param publicKey the RSA public key to publish
     * @return the JWKS document Keycloak stores in {@code jwks.string}
     */
    private static String signingJwks(String keyId, RSAPublicKey publicKey) {
        return "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"" + keyId
                + "\",\"alg\":\"RS256\",\"n\":\"" + base64Url(publicKey.getModulus())
                + "\",\"e\":\"" + base64Url(publicKey.getPublicExponent()) + "\"}]}";
    }

    /**
     * Encodes an RSA parameter the way RFC 7518 §6.3.1 requires: the unsigned big-endian magnitude,
     * base64url without padding. {@link BigInteger#toByteArray()} prepends a zero byte whenever the high
     * bit is set, which must be stripped.
     *
     * @param value the RSA modulus or exponent
     * @return the base64url-encoded magnitude
     */
    private static String base64Url(BigInteger value) {
        byte[] magnitude = value.toByteArray();
        int offset = 0;
        while (offset < magnitude.length - 1 && magnitude[offset] == 0) {
            offset++;
        }
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(Arrays.copyOfRange(magnitude, offset, magnitude.length));
    }
}
