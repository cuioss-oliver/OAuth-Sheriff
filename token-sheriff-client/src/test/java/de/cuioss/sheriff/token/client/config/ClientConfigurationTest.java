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
package de.cuioss.sheriff.token.client.config;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnableGeneratorController
@DisplayName("ClientConfiguration value object")
class ClientConfigurationTest {

    private static String issuer() {
        return "https://" + Generators.letterStrings(3, 12).next() + ".example.com";
    }

    @Test
    @DisplayName("Should expose all configured fields through its builder")
    void shouldExposeConfiguredFields() {
        var issuer = issuer();
        var clientId = Generators.nonBlankStrings().next();
        var secret = Generators.nonBlankStrings().next();
        var redirect = issuer() + "/callback";

        var config = ClientConfiguration.builder()
                .issuer(issuer)
                .clientId(clientId)
                .clientSecret(secret)
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .scope("openid")
                .scope("profile")
                .redirectUri(redirect)
                .allowInsecureHttp(false)
                .build();

        assertAll("configuration fields",
                () -> assertEquals(issuer, config.getIssuer()),
                () -> assertEquals(clientId, config.getClientId()),
                () -> assertEquals(secret, config.getClientSecret()),
                () -> assertEquals(ClientAuthMethod.CLIENT_SECRET_BASIC, config.getAuthMethod()),
                () -> assertEquals(2, config.getScopes().size()),
                () -> assertEquals(redirect, config.getRedirectUri()),
                () -> assertFalse(config.isAllowInsecureHttp()));
    }

    @Test
    @DisplayName("Should permit a null secret and redirect for non-interactive clients")
    void shouldPermitNullSecretAndRedirect() {
        var config = ClientConfiguration.builder()
                .issuer(issuer())
                .clientId(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.PRIVATE_KEY_JWT)
                .build();

        assertAll(
                () -> assertTrue(config.getScopes().isEmpty()),
                () -> assertNull(config.getClientSecret()),
                () -> assertNull(config.getRedirectUri()));
    }

    @Test
    @DisplayName("Should reject a blank client secret while still permitting an absent (null) one — blank != absent")
    void shouldRejectBlankSecretButPermitAbsentSecret() {
        var blankSecret = ClientConfiguration.builder()
                .issuer(issuer()).clientId(Generators.nonBlankStrings().next())
                .clientSecret("   ").authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC);
        var emptySecret = ClientConfiguration.builder()
                .issuer(issuer()).clientId(Generators.nonBlankStrings().next())
                .clientSecret("").authMethod(ClientAuthMethod.CLIENT_SECRET_POST);
        // A key-based method carries no shared secret: an absent (null) secret must remain valid.
        var absentSecret = ClientConfiguration.builder()
                .issuer(issuer()).clientId(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.PRIVATE_KEY_JWT).build();

        assertAll("blank-secret rejection, null-secret acceptance",
                () -> assertThrows(IllegalArgumentException.class, blankSecret::build,
                        "a whitespace-only client secret is a misconfiguration and must be rejected at construction"),
                () -> assertThrows(IllegalArgumentException.class, emptySecret::build,
                        "an empty client secret must be rejected at construction"),
                () -> assertNull(absentSecret.getClientSecret(),
                        "an absent (null) secret stays valid for a key-based auth method"));
    }

    @Test
    @DisplayName("Should reject a non-positive connect or read timeout at construction")
    void shouldRejectNonPositiveTimeouts() {
        var zeroConnect = ClientConfiguration.builder()
                .issuer(issuer()).clientId(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC).connectTimeoutSeconds(0);
        var negativeConnect = ClientConfiguration.builder()
                .issuer(issuer()).clientId(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC).connectTimeoutSeconds(-1);
        var zeroRead = ClientConfiguration.builder()
                .issuer(issuer()).clientId(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC).readTimeoutSeconds(0);
        var negativeRead = ClientConfiguration.builder()
                .issuer(issuer()).clientId(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC).readTimeoutSeconds(-5);

        assertAll("timeout guards",
                () -> assertThrows(IllegalArgumentException.class, zeroConnect::build,
                        "a zero connect timeout is invalid"),
                () -> assertThrows(IllegalArgumentException.class, negativeConnect::build,
                        "a negative connect timeout is invalid"),
                () -> assertThrows(IllegalArgumentException.class, zeroRead::build,
                        "a zero read timeout is invalid"),
                () -> assertThrows(IllegalArgumentException.class, negativeRead::build,
                        "a negative read timeout is invalid"));
    }

    @Test
    @DisplayName("Should build with explicit positive timeouts and a valid secret, and default the timeouts otherwise")
    void shouldBuildWithValidTimeoutsAndSecret() {
        var explicit = ClientConfiguration.builder()
                .issuer(issuer()).clientId(Generators.nonBlankStrings().next())
                .clientSecret(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .connectTimeoutSeconds(7).readTimeoutSeconds(11).build();
        var defaulted = ClientConfiguration.builder()
                .issuer(issuer()).clientId(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC).build();

        assertAll("valid timeout configuration",
                () -> assertEquals(7, explicit.getConnectTimeoutSeconds()),
                () -> assertEquals(11, explicit.getReadTimeoutSeconds()),
                () -> assertEquals(ClientConfiguration.DEFAULT_CONNECT_TIMEOUT_SECONDS,
                        defaulted.getConnectTimeoutSeconds()),
                () -> assertEquals(ClientConfiguration.DEFAULT_READ_TIMEOUT_SECONDS,
                        defaulted.getReadTimeoutSeconds()));
    }

    @Test
    @DisplayName("Should default the discovery-document ceiling above the JWT payload ceiling and keep it settable")
    void shouldExposeDiscoveryDocumentMaxSize() {
        var defaulted = ClientConfiguration.builder()
                .issuer(issuer()).clientId(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC).build();
        var explicit = ClientConfiguration.builder()
                .issuer(issuer()).clientId(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .discoveryDocumentMaxSize(256 * 1024).build();

        assertAll("discovery-document ceiling",
                () -> assertEquals(ClientConfiguration.DEFAULT_DISCOVERY_DOCUMENT_MAX_SIZE,
                        defaulted.getDiscoveryDocumentMaxSize()),
                // The defect: the ceiling used to be the 8 KiB JWT payload bound, which an ordinary
                // Keycloak realm already exceeds. The default must leave real documents room.
                () -> assertTrue(defaulted.getDiscoveryDocumentMaxSize() > 8 * 1024,
                        "the default must exceed the JWT payload ceiling it used to borrow"),
                () -> assertEquals(256 * 1024, explicit.getDiscoveryDocumentMaxSize(),
                        "an embedder facing a larger document can raise the ceiling"));
    }

    @Test
    @DisplayName("Should reject a non-positive discovery-document ceiling at construction")
    void shouldRejectNonPositiveDiscoveryDocumentMaxSize() {
        var zero = ClientConfiguration.builder()
                .issuer(issuer()).clientId(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC).discoveryDocumentMaxSize(0);
        var negative = ClientConfiguration.builder()
                .issuer(issuer()).clientId(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC).discoveryDocumentMaxSize(-1);

        assertAll("discovery-document ceiling guards",
                () -> assertThrows(IllegalArgumentException.class, zero::build,
                        "a zero ceiling would reject every discovery document"),
                () -> assertThrows(IllegalArgumentException.class, negative::build,
                        "a negative ceiling is not a size"));
    }

    @Test
    @DisplayName("Should reject a null issuer, client id or auth method")
    void shouldRejectNullRequiredFields() {
        var clientId = Generators.nonBlankStrings().next();
        var missingIssuer = ClientConfiguration.builder()
                .clientId(clientId).authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC);
        var missingClientId = ClientConfiguration.builder()
                .issuer(issuer()).authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC);
        var missingAuthMethod = ClientConfiguration.builder()
                .issuer(issuer()).clientId(clientId);
        assertAll(
                () -> assertThrows(NullPointerException.class, missingIssuer::build),
                () -> assertThrows(NullPointerException.class, missingClientId::build),
                () -> assertThrows(NullPointerException.class, missingAuthMethod::build));
    }

    @Test
    @DisplayName("Should keep the scopes list immutable")
    void shouldKeepScopesImmutable() {
        var config = ClientConfiguration.builder()
                .issuer(issuer())
                .clientId(Generators.nonBlankStrings().next())
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .scope("openid")
                .build();

        var scopes = config.getScopes();
        assertThrows(UnsupportedOperationException.class, () -> scopes.add("extra"));
    }

    @Test
    @DisplayName("Should honour value-based equals and hashCode")
    void shouldHonourValueEquality() {
        var issuer = issuer();
        var clientId = Generators.nonBlankStrings().next();

        var first = ClientConfiguration.builder()
                .issuer(issuer).clientId(clientId).authMethod(ClientAuthMethod.CLIENT_SECRET_POST).build();
        var second = ClientConfiguration.builder()
                .issuer(issuer).clientId(clientId).authMethod(ClientAuthMethod.CLIENT_SECRET_POST).build();
        var different = ClientConfiguration.builder()
                .issuer(issuer).clientId(clientId).authMethod(ClientAuthMethod.PRIVATE_KEY_JWT).build();

        assertAll(
                () -> assertEquals(first, second),
                () -> assertEquals(first.hashCode(), second.hashCode()),
                () -> assertNotEquals(first, different));
    }

    @Test
    @DisplayName("Should exclude the client secret from toString so an incidental dump cannot leak it (TEST-16, H8)")
    void shouldExcludeSecretFromToString() {
        var secret = Generators.letterStrings(20, 40).next();
        var clientId = Generators.nonBlankStrings().next();
        var config = ClientConfiguration.builder()
                .issuer(issuer())
                .clientId(clientId)
                .clientSecret(secret)
                .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                .build();

        String rendered = config.toString();

        assertAll("secret never leaks through toString",
                () -> assertFalse(rendered.contains(secret),
                        "the client secret value must never appear in the string representation"),
                () -> assertFalse(rendered.contains("clientSecret"),
                        "the excluded field is not even named in the string representation"),
                () -> assertTrue(rendered.contains(clientId),
                        "non-secret fields remain visible for diagnostics"));
    }

    @Nested
    @DisplayName("Per-client TLS trust (sslContext)")
    class SslContextTest {

        @Test
        @DisplayName("Should leave the SSL context absent when the builder never sets one")
        void shouldDefaultToAbsentSslContext() {
            var config = minimalBuilder().build();

            assertNull(config.getSslContext(),
                    "an unconfigured sslContext means 'use the cui-http / JVM default truststore'");
        }

        @Test
        @DisplayName("Should return the supplied SSL context identically — trust material is never copied")
        void shouldReturnSuppliedSslContextIdentically() {
            var supplied = defaultSslContext();

            var config = minimalBuilder().sslContext(supplied).build();

            assertSame(supplied, config.getSslContext(),
                    "the caller's trust material must reach the transport unchanged");
        }

        @Test
        @DisplayName("Should exclude the SSL context from toString so a dump cannot expose the trust material")
        void shouldExcludeSslContextFromToString() {
            var supplied = defaultSslContext();
            var config = minimalBuilder().sslContext(supplied).build();

            String rendered = config.toString();

            assertAll("sslContext never appears in the string representation",
                    () -> assertFalse(rendered.contains(supplied.toString()),
                            "the SSLContext's own string form must not be rendered"),
                    () -> assertFalse(rendered.contains("sslContext"),
                            "the excluded field is not even named in the string representation"));
        }

        @Test
        @DisplayName("Should keep two configurations equal when they differ only in their SSL context")
        void shouldIgnoreSslContextForEquality() {
            var issuer = issuer();
            var clientId = Generators.nonBlankStrings().next();
            var withDefaultTrust = ClientConfiguration.builder()
                    .issuer(issuer).clientId(clientId).authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                    .sslContext(defaultSslContext()).build();
            var withPrivateTrust = ClientConfiguration.builder()
                    .issuer(issuer).clientId(clientId).authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                    .sslContext(freshSslContext()).build();
            var withoutTrust = ClientConfiguration.builder()
                    .issuer(issuer).clientId(clientId).authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC).build();

            // An SSLContext has identity semantics and no value form, so it is deliberately excluded
            // from the generated equals/hashCode — configurations stay comparable by their value fields.
            assertAll("sslContext is excluded from value equality by design",
                    () -> assertEquals(withDefaultTrust, withPrivateTrust),
                    () -> assertEquals(withDefaultTrust.hashCode(), withPrivateTrust.hashCode()),
                    () -> assertEquals(withDefaultTrust, withoutTrust),
                    () -> assertEquals(withDefaultTrust.hashCode(), withoutTrust.hashCode()));
        }

        private ClientConfiguration.ClientConfigurationBuilder minimalBuilder() {
            return ClientConfiguration.builder()
                    .issuer(issuer())
                    .clientId(Generators.nonBlankStrings().next())
                    .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC);
        }
    }

    static SSLContext defaultSslContext() {
        return assertDoesNotThrow(SSLContext::getDefault);
    }

    static SSLContext freshSslContext() {
        return assertDoesNotThrow(() -> {
            var context = SSLContext.getInstance("TLSv1.3");
            context.init(null, null, null);
            return context;
        });
    }

    @Nested
    @DisplayName("ClientAuthMethod metadata")
    class ClientAuthMethodTest {

        @Test
        @DisplayName("Should rank key-based methods above shared-secret methods")
        void shouldRankKeyBasedMethodsStronger() {
            assertAll(
                    () -> assertTrue(ClientAuthMethod.PRIVATE_KEY_JWT.getStrength()
                            > ClientAuthMethod.CLIENT_SECRET_BASIC.getStrength()),
                    () -> assertTrue(ClientAuthMethod.TLS_CLIENT_AUTH.getStrength()
                            > ClientAuthMethod.CLIENT_SECRET_POST.getStrength()));
        }

        @Test
        @DisplayName("Should resolve a method from its advertised metadata value")
        void shouldResolveFromMetadataValue() {
            assertAll(
                    () -> assertEquals(ClientAuthMethod.PRIVATE_KEY_JWT,
                            ClientAuthMethod.fromMetadataValue("private_key_jwt").orElseThrow()),
                    () -> assertEquals(ClientAuthMethod.TLS_CLIENT_AUTH,
                            ClientAuthMethod.fromMetadataValue("tls_client_auth").orElseThrow()),
                    () -> assertTrue(ClientAuthMethod.fromMetadataValue("none").isEmpty()),
                    () -> assertTrue(ClientAuthMethod.fromMetadataValue(null).isEmpty()));
        }
    }

    @Nested
    @DisplayName("Construction-time issuer and scope validation (L14)")
    class IssuerAndScopeValidation {

        private ClientConfiguration.ClientConfigurationBuilder builderWithIssuer(String issuerValue) {
            return ClientConfiguration.builder()
                    .issuer(issuerValue)
                    .clientId(Generators.nonBlankStrings().next())
                    .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC)
                    .clientSecret(Generators.nonBlankStrings().next());
        }

        @Test
        @DisplayName("Should reject a blank issuer or client id — a present-but-empty value is not a value")
        void shouldRejectBlankIssuerAndClientId() {
            var blankIssuer = builderWithIssuer("   ");
            var blankClientId = ClientConfiguration.builder()
                    .issuer(issuer()).clientId("  ")
                    .authMethod(ClientAuthMethod.CLIENT_SECRET_BASIC);

            assertAll("blank required fields",
                    () -> assertThrows(IllegalArgumentException.class, blankIssuer::build,
                            "a whitespace-only issuer must be rejected at construction"),
                    () -> assertThrows(IllegalArgumentException.class, blankClientId::build,
                            "a whitespace-only client id must be rejected at construction"));
        }

        @Test
        @DisplayName("Should reject a relative issuer that carries no scheme at all")
        void shouldRejectRelativeIssuer() {
            var relative = builderWithIssuer("issuer.example.com/auth");

            assertThrows(IllegalArgumentException.class, relative::build,
                    "a relative reference cannot identify an authorization server");
        }

        @Test
        @DisplayName("Should reject an absolute issuer URI that carries no host")
        void shouldRejectIssuerWithoutHost() {
            var hostless = builderWithIssuer("urn:example:issuer");

            assertThrows(IllegalArgumentException.class, hostless::build,
                    "an absolute URI without a host cannot be dereferenced for discovery");
        }

        @Test
        @DisplayName("Should reject an issuer whose scheme is neither http nor https")
        void shouldRejectNonHttpIssuerScheme() {
            var ftp = builderWithIssuer("ftp://issuer.example.com");

            assertThrows(IllegalArgumentException.class, ftp::build,
                    "only http(s) issuers can be resolved over the discovery transport");
        }

        @Test
        @DisplayName("Should reject a malformed issuer URL that cannot be parsed at all")
        void shouldRejectUnparseableIssuer() {
            var malformed = builderWithIssuer("https://issuer.example.com/ a path");

            assertThrows(IllegalArgumentException.class, malformed::build,
                    "an unparseable issuer must fail at construction, not later on the wire");
        }

        @Test
        @DisplayName("Should accept an http issuer so a cleartext local test setup stays configurable")
        void shouldAcceptHttpIssuer() {
            var config = builderWithIssuer("http://localhost:8080/auth").allowInsecureHttp(true).build();

            assertEquals("http://localhost:8080/auth", config.getIssuer(),
                    "a plaintext http issuer remains constructible for local test setups");
        }

        @Test
        @DisplayName("Should reject a blank scope entry that would otherwise serialise into the scope parameter")
        void shouldRejectBlankScopeEntry() {
            var blankScope = builderWithIssuer(issuer()).scope("openid").scope("   ");

            assertThrows(IllegalArgumentException.class, blankScope::build,
                    "a blank scope would serialise as stray whitespace in the scope parameter");
        }

        @Test
        @DisplayName("Should reject a null scope entry that would otherwise serialise as the literal \"null\"")
        void shouldRejectNullScopeEntry() {
            var scopes = new ArrayList<String>();
            scopes.add("openid");
            scopes.add(null);
            var nullScope = builderWithIssuer(issuer()).scopes(scopes);

            assertThrows(IllegalArgumentException.class, nullScope::build,
                    "a null scope would serialise as the literal \"null\" in the scope parameter");
        }
    }
}
