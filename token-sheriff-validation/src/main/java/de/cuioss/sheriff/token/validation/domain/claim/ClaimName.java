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
package de.cuioss.sheriff.token.validation.domain.claim;

import de.cuioss.sheriff.token.validation.domain.claim.mapper.*;
import lombok.Getter;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Defines standard JWT claim names and their expected value types.
 * Based on RFC 7519, OpenID Connect, and OAuth 2.0 specifications.
 * Includes information about whether each claim is mandatory according to its
 * respective specification.
 * <p>
 * Provides a standardized set of JWT claim names and types.
 *
 * @since 1.0
 */
@Getter
public enum ClaimName {
    /**
     * The "iss" (issuer) claim identifies the principal that issued the JWT.
     * Required by RFC 7519 for ACCESS_TOKEN and ID_TOKEN types.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1">RFC 7519 - 4.1.1. "iss" (Issuer) Claim</a>
     */
    ISSUER("iss", ClaimValueType.STRING, "The \"iss\" (issuer) claim identifies the principal that issued the JWT. Required by RFC 7519 for ACCESS_TOKEN and ID_TOKEN types.", new IdentityMapper()),

    /**
     * The "sub" (subject) claim identifies the principal that is the subject of the JWT.
     * Required by RFC 7519 for ACCESS_TOKEN and ID_TOKEN types.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2">RFC 7519 - 4.1.2. "sub" (Subject) Claim</a>
     */
    SUBJECT("sub", ClaimValueType.STRING, "The \"sub\" (subject) claim identifies the principal that is the subject of the JWT. Required by RFC 7519 for ACCESS_TOKEN and ID_TOKEN types.", new IdentityMapper()),

    /**
     * The "aud" (audience) claim identifies the recipients that the JWT is intended for.
     * Required by RFC 7519 for ID_TOKEN type.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3">RFC 7519 - 4.1.3. "aud" (Audience) Claim</a>
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0 - ID Token</a>
     */
    AUDIENCE("aud", ClaimValueType.STRING_LIST, "The \"aud\" (audience) claim identifies the recipients that the JWT is intended for. Required by RFC 7519 for ID_TOKEN type.", new JsonCollectionMapper()),

    /**
     * The "exp" (expiration time) claim identifies the expiration time on or after which
     * the JWT MUST NOT be accepted for processing.
     * Required by RFC 7519 for ACCESS_TOKEN and ID_TOKEN types.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4">RFC 7519 - 4.1.4. "exp" (Expiration Time) Claim</a>
     */
    EXPIRATION("exp", ClaimValueType.DATETIME, "The \"exp\" (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing. Required by RFC 7519 for ACCESS_TOKEN and ID_TOKEN types.", new OffsetDateTimeMapper()),

    /**
     * The "nbf" (not before) claim identifies the time before which the JWT
     * MUST NOT be accepted for processing.
     * Optional by RFC 7519 for all token types.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5">RFC 7519 - 4.1.5. "nbf" (Not Before) Claim</a>
     */
    NOT_BEFORE("nbf", ClaimValueType.DATETIME, "The \"nbf\" (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing. Optional by RFC 7519 for all token types.", new OffsetDateTimeMapper()),

    /**
     * The "iat" (issued at) claim identifies the time at which the JWT was issued.
     * Required by RFC 7519 for ACCESS_TOKEN and ID_TOKEN types.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6">RFC 7519 - 4.1.6. "iat" (Issued At) Claim</a>
     */
    ISSUED_AT("iat", ClaimValueType.DATETIME, "The \"iat\" (issued at) claim identifies the time at which the JWT was issued. Required by RFC 7519 for ACCESS_TOKEN and ID_TOKEN types.", new OffsetDateTimeMapper()),

    /**
     * The "jti" (JWT ID) claim provides a unique identifier for the JWT.
     * Optional by RFC 7519 for all token types.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7">RFC 7519 - 4.1.7. "jti" (JWT ID) Claim</a>
     */
    TOKEN_ID("jti", ClaimValueType.STRING, "The \"jti\" (JWT ID) claim provides a unique identifier for the JWT. Optional by RFC 7519 for all token types.", new IdentityMapper()),

    /**
     * The "name" claim contains the full name of the end-user.
     * Optional for all token types.
     *
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 - Standard Claims</a>
     */
    NAME("name", ClaimValueType.STRING, "The \"name\" claim contains the full name of the end-user. Optional for all token types.", new IdentityMapper()),

    /**
     * The "email" claim contains the preferred email address of the end-user.
     * Optional for all token types.
     *
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 - Standard Claims</a>
     */
    EMAIL("email", ClaimValueType.STRING, "The \"email\" claim contains the preferred email address of the end-user. Optional for all token types.", new IdentityMapper()),

    /**
     * The "preferred_username" claim contains the shorthand name by which the end-user
     * wishes to be referred to.
     * Optional for all token types.
     *
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 - Standard Claims</a>
     */
    PREFERRED_USERNAME("preferred_username", ClaimValueType.STRING, "The \"preferred_username\" claim contains the shorthand name by which the end-user wishes to be referred to. Optional for all token types.", new IdentityMapper()),

    /**
     * The "scope" claim identifies the scope of the access token.
     * Optional per RFC 9068 Section 2.2 for JWT access tokens.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc9068#section-2.2">RFC 9068 - 2.2. Data Structure</a>
     */
    SCOPE("scope", ClaimValueType.STRING_LIST, "The \"scope\" claim identifies the scope of the access token. Optional per RFC 9068 Section 2.2 for JWT access tokens.", new ScopeMapper()),

    /**
     * The "typ" claim identifies the token type.
     * Implementation-specific claim, not defined in standard specifications.
     */
    TYPE("typ", ClaimValueType.STRING, "The \"typ\" claim identifies the token type. Implementation-specific claim, not defined in standard specifications.", new IdentityMapper()),

    /**
     * The "roles" claim identifies the roles assigned to the user.
     * This is a common but not specified claim in JWT tokens.
     * <p>
     * While not part of the core JWT or OpenID Connect specifications,
     * this claim is commonly used in authorization scenarios to represent
     * the user's roles for role-based access control (RBAC).
     */
    ROLES("roles", ClaimValueType.STRING_LIST, "The \"roles\" claim identifies the roles assigned to the user. This is a common but not specified claim in JWT tokens commonly used in authorization scenarios to represent the user's roles for role-based access control (RBAC).", new JsonCollectionMapper()),

    /**
     * The "groups" claim identifies the groups the user belongs to.
     * This is a common but not specified claim in JWT tokens.
     * <p>
     * While not part of the core JWT or OpenID Connect specifications,
     * this claim is commonly used in authorization scenarios to represent
     * the user's group memberships for group-based access control.
     */
    GROUPS("groups", ClaimValueType.STRING_LIST, "The \"groups\" claim identifies the groups the user belongs to. This is a common but not specified claim in JWT tokens commonly used in authorization scenarios to represent the user's group memberships for group-based access control.", new JsonCollectionMapper()),

    /**
     * The "azp" (authorized party) claim identifies the party to which the ID Token was issued.
     * Optional by OpenID Connect Core 1.0 for ID_TOKEN type.
     *
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0 - ID Token</a>
     */
    AUTHORIZED_PARTY("azp", ClaimValueType.STRING, "The \"azp\" (authorized party) claim identifies the party to which the ID Token was issued. Optional by OpenID Connect Core 1.0 for ID_TOKEN type.", new IdentityMapper()),

    /**
     * The "client_id" claim identifies the OAuth 2.0 client that requested the token.
     * Defined by RFC 9068 Section 2.2 for JWT access tokens. Used as a fallback
     * when the "azp" claim is absent for authorized party validation.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc9068#section-2.2">RFC 9068 - JWT Access Tokens</a>
     */
    CLIENT_ID("client_id", ClaimValueType.STRING, "The \"client_id\" claim identifies the OAuth 2.0 client that requested the token. Defined by RFC 9068 Section 2.2 for JWT access tokens.", new IdentityMapper()),

    // Design Decision: UPN is a MicroProfile JWT Auth invention, not an RFC or OIDC claim.
    // It lives in core (not the Quarkus layer) because ClaimName is a framework-agnostic
    // claim name registry. The MP-JWT fallback chain (upn -> preferred_username -> sub)
    // is typically handled by adapters providing MicroProfile JWT compatibility.
    /**
     * The "upn" (user principal name) claim uniquely identifies the subject or user principal
     * of the token. Commonly used for principal name resolution with a fallback chain:
     * {@code upn} -> {@code preferred_username} -> {@code sub}.
     * Optional for all token types.
     */
    UPN("upn", ClaimValueType.STRING, "The \"upn\" (user principal name) claim uniquely identifies the subject or user principal of the token. Commonly used with a fallback chain: upn -> preferred_username -> sub.", new IdentityMapper());

    private final String name;
    private final ClaimValueType valueType;
    private final String spec;
    private final ClaimMapper claimMapper;

    ClaimName(String name, ClaimValueType valueType, String spec, ClaimMapper claimMapper) {
        this.name = name;
        this.valueType = valueType;
        this.spec = spec;
        this.claimMapper = claimMapper;
    }

    // Pre-built immutable lookup map from claim name string to ClaimName enum constant.
    // Bounded by the number of enum values — no unbounded growth from unknown names.
    private static final Map<String, ClaimName> CLAIM_NAME_LOOKUP =
            Arrays.stream(values())
                    .collect(Collectors.toUnmodifiableMap(ClaimName::getName, c -> c));

    /**
     * Gets a ClaimName by its string name.
     * Uses a pre-built immutable map for O(1) lookup. Unknown names return
     * {@code Optional.empty()} without being cached, preventing unbounded cache growth.
     *
     * @param name the claim name string
     * @return an Optional containing the ClaimName if found, empty otherwise
     */
    public static Optional<ClaimName> fromString(String name) {
        if (name == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(CLAIM_NAME_LOOKUP.get(name));
    }

}
