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
package de.cuioss.sheriff.token.client.discovery;

import com.dslplatform.json.CompiledJson;
import com.dslplatform.json.JsonAttribute;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * The subset of an authorization server's OpenID Connect Discovery / RFC 8414 metadata document
 * that the client engine consumes.
 * <p>
 * Instances are produced by {@link DiscoveryResolver} from the AS
 * {@code .well-known/openid-configuration} response. It records the resolved endpoint URLs plus
 * the capability flags the flows branch on (PKCE {@code S256}, pushed authorization requests,
 * DPoP, RP-initiated end-session).
 * <p>
 * Parsing uses DSL-JSON's compile-time {@code @CompiledJson} mapping — the same secure,
 * native-image-friendly approach {@code commons.transport.WellKnownResult} uses. Fields are
 * {@code public} because DSL-JSON class-based deserialization requires it; after deserialization
 * the object is treated as read-only and callers should use the accessor methods.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8414">RFC 8414 - OAuth 2.0 Authorization Server Metadata</a>
 */
@CompiledJson
@SuppressWarnings("java:S1104") // Public fields required by DSL-JSON @CompiledJson for class-based deserialization
public class ProviderMetadata {

    /** PKCE code-challenge method identifier for SHA-256 ({@code S256}, RFC 7636). */
    public static final String CODE_CHALLENGE_METHOD_S256 = "S256";

    /** The authorization server's issuer identifier. */
    public String issuer;

    /** The OAuth 2.0 authorization endpoint URL. */
    @JsonAttribute(name = "authorization_endpoint")
    public String authorizationEndpoint;

    /** The OAuth 2.0 token endpoint URL. */
    @JsonAttribute(name = "token_endpoint")
    public String tokenEndpoint;

    /** The OpenID Connect userinfo endpoint URL. */
    @JsonAttribute(name = "userinfo_endpoint")
    public String userinfoEndpoint;

    /** The JWK Set document URL. */
    @JsonAttribute(name = "jwks_uri")
    public String jwksUri;

    /** The RP-initiated logout end-session endpoint URL (OpenID Connect RP-Initiated Logout). */
    @JsonAttribute(name = "end_session_endpoint")
    public String endSessionEndpoint;

    /** The RFC 7009 token revocation endpoint URL. */
    @JsonAttribute(name = "revocation_endpoint")
    public String revocationEndpoint;

    /** The RFC 7662 token introspection endpoint URL. */
    @JsonAttribute(name = "introspection_endpoint")
    public String introspectionEndpoint;

    /** The RFC 9126 pushed-authorization-request (PAR) endpoint URL. */
    @JsonAttribute(name = "pushed_authorization_request_endpoint")
    public String pushedAuthorizationRequestEndpoint;

    /** The advertised PKCE code-challenge methods (RFC 7636 / RFC 8414). */
    @JsonAttribute(name = "code_challenge_methods_supported")
    public List<String> codeChallengeMethodsSupported;

    /** The advertised client-authentication methods for the token endpoint (RFC 8414). */
    @JsonAttribute(name = "token_endpoint_auth_methods_supported")
    public List<String> tokenEndpointAuthMethodsSupported;

    /** The advertised DPoP proof signing algorithms (RFC 9449). */
    @JsonAttribute(name = "dpop_signing_alg_values_supported")
    public List<String> dpopSigningAlgValuesSupported;

    /**
     * Whether the AS stamps the authorization response with its own {@code iss} (RFC 9207). When
     * {@code true}, the client requires the {@code iss} on the callback and rejects its absence as a
     * mix-up signal.
     */
    @JsonAttribute(name = "authorization_response_iss_parameter_supported")
    public boolean authorizationResponseIssParameterSupported;

    /**
     * @return the issuer identifier, or {@link Optional#empty()} if absent
     */
    public Optional<String> getIssuer() {
        return Optional.ofNullable(issuer);
    }

    /**
     * @return the authorization endpoint URL, or {@link Optional#empty()} if absent
     */
    public Optional<String> getAuthorizationEndpoint() {
        return Optional.ofNullable(authorizationEndpoint);
    }

    /**
     * @return the token endpoint URL, or {@link Optional#empty()} if absent
     */
    public Optional<String> getTokenEndpoint() {
        return Optional.ofNullable(tokenEndpoint);
    }

    /**
     * @return the userinfo endpoint URL, or {@link Optional#empty()} if absent
     */
    public Optional<String> getUserinfoEndpoint() {
        return Optional.ofNullable(userinfoEndpoint);
    }

    /**
     * @return the JWK Set URL, or {@link Optional#empty()} if absent
     */
    public Optional<String> getJwksUri() {
        return Optional.ofNullable(jwksUri);
    }

    /**
     * @return the end-session endpoint URL, or {@link Optional#empty()} if absent
     */
    public Optional<String> getEndSessionEndpoint() {
        return Optional.ofNullable(endSessionEndpoint);
    }

    /**
     * @return the revocation endpoint URL, or {@link Optional#empty()} if absent
     */
    public Optional<String> getRevocationEndpoint() {
        return Optional.ofNullable(revocationEndpoint);
    }

    /**
     * @return the introspection endpoint URL, or {@link Optional#empty()} if absent
     */
    public Optional<String> getIntrospectionEndpoint() {
        return Optional.ofNullable(introspectionEndpoint);
    }

    /**
     * @return the pushed-authorization-request endpoint URL, or {@link Optional#empty()} if absent
     */
    public Optional<String> getPushedAuthorizationRequestEndpoint() {
        return Optional.ofNullable(pushedAuthorizationRequestEndpoint);
    }

    /**
     * The advertised token-endpoint client-authentication methods with any JSON {@code null} array
     * elements removed. DSL-JSON maps a {@code null} element in
     * {@code token_endpoint_auth_methods_supported} to a {@code null} list entry; returning a
     * null-element-free list lets consumers copy it into a {@link java.util.Set} without a
     * {@link NullPointerException} (L6).
     *
     * @return the advertised auth methods, never {@code null} and never containing {@code null}
     *         elements (empty when the AS omitted the field)
     */
    public List<String> getTokenEndpointAuthMethods() {
        return nonNullElements(tokenEndpointAuthMethodsSupported);
    }

    /**
     * Whether the AS advertises the PKCE {@code S256} code-challenge method — a precondition for
     * the interactive {@code authorization_code} flow ({@code CLIENT-2}). A {@code null} array
     * element is tolerated (it is never the {@code S256} marker).
     *
     * @return {@code true} if {@code S256} is advertised
     */
    public boolean supportsS256() {
        return codeChallengeMethodsSupported != null
                && codeChallengeMethodsSupported.contains(CODE_CHALLENGE_METHOD_S256);
    }

    private static List<String> nonNullElements(@Nullable List<String> values) {
        if (values == null) {
            return List.of();
        }
        return values.stream().filter(Objects::nonNull).toList();
    }

    /**
     * Whether the AS exposes a pushed-authorization-request endpoint (RFC 9126).
     *
     * @return {@code true} if a PAR endpoint is advertised
     */
    public boolean supportsPushedAuthorizationRequests() {
        return pushedAuthorizationRequestEndpoint != null && !pushedAuthorizationRequestEndpoint.isBlank();
    }

    /**
     * Whether the AS advertises DPoP proof support (RFC 9449).
     *
     * @return {@code true} if at least one DPoP signing algorithm is advertised
     */
    public boolean supportsDpop() {
        return dpopSigningAlgValuesSupported != null && !dpopSigningAlgValuesSupported.isEmpty();
    }

    /**
     * Whether the AS advertises the RFC 9207 {@code iss} authorization-response parameter. When
     * {@code true}, the {@code authorization_code} flow requires the {@code iss} on the callback and
     * treats its absence as a mix-up ({@code CLIENT-8}).
     *
     * @return {@code true} if {@code authorization_response_iss_parameter_supported} is advertised
     */
    public boolean supportsAuthorizationResponseIssParameter() {
        return authorizationResponseIssParameterSupported;
    }

    /**
     * Whether the AS exposes an RP-initiated logout end-session endpoint.
     *
     * @return {@code true} if an end-session endpoint is advertised
     */
    public boolean supportsEndSession() {
        return endSessionEndpoint != null && !endSessionEndpoint.isBlank();
    }
}
