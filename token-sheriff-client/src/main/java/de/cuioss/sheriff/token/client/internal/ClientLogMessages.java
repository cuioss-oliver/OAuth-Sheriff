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
package de.cuioss.sheriff.token.client.internal;

import de.cuioss.tools.logging.LogRecord;
import de.cuioss.tools.logging.LogRecordModel;
import lombok.experimental.UtilityClass;

/**
 * DSL-style {@link LogRecord} catalogue for the Token-Sheriff client engine.
 * <p>
 * Structured {@code INFO} / {@code WARN} / {@code ERROR} messages carry the
 * {@code TokenSheriffClient} prefix and a stable numeric identifier, so they are greppable and
 * assertable via {@code LogAsserts}. {@code DEBUG} / {@code TRACE} diagnostics use the logger
 * directly and are not catalogued here.
 *
 * @since 1.0
 */
@UtilityClass
public final class ClientLogMessages {

    private static final String PREFIX = "TokenSheriffClient";

    /**
     * Info-level messages (INFO range 1-99).
     */
    @UtilityClass
    public static final class INFO {

        /** Provider metadata successfully resolved for the given issuer. */
        public static final LogRecord DISCOVERY_RESOLVED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(1)
                .template("Resolved OIDC provider metadata for issuer '%s'")
                .build();

        /**
         * Held tokens for a session were cleared from the local store as part of RP-initiated logout.
         * This records the client-side store clear only; revocation at the authorization server (RFC
         * 7009) is performed separately by the relying party on the returned bundle, so this event must
         * not claim the tokens were revoked (L17).
         */
        public static final LogRecord LOGOUT_TOKENS_CLEARED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(2)
                .template("Cleared held tokens for session '%s' as part of RP-initiated logout")
                .build();
    }

    /**
     * Warn-level messages (WARN range 100-199).
     */
    @UtilityClass
    public static final class WARN {

        /** A non-TLS issuer was rejected for discovery. */
        public static final LogRecord NON_TLS_ISSUER = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(100)
                .template("Rejecting non-TLS issuer '%s' for discovery; enable allowInsecureHttp only for local test setups")
                .build();

        /** The discovery request returned a non-success HTTP status. */
        public static final LogRecord DISCOVERY_STATUS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(101)
                .template("Discovery for issuer '%s' returned unexpected HTTP status %s")
                .build();

        /** The AS does not advertise the PKCE 'S256' code-challenge method. */
        public static final LogRecord S256_NOT_ADVERTISED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(102)
                .template("Authorization server '%s' does not advertise PKCE 'S256'; interactive authorization_code flows will be refused")
                .build();

        /** The discovery document's issuer does not match the configured issuer. */
        public static final LogRecord ISSUER_MISMATCH = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(103)
                .template("Discovery document issuer '%s' does not match configured issuer '%s'")
                .build();

        /** A superseded refresh token was replayed; the rotation family has been revoked. */
        public static final LogRecord REFRESH_TOKEN_REUSE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(104)
                .template("Refresh token reuse detected; the refresh token family has been revoked")
                .build();

        /** The RFC 9207 authorization-response {@code iss} does not match the initiating issuer (mix-up). */
        public static final LogRecord ISS_MISMATCH = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(105)
                .template("Authorization response 'iss' '%s' does not match the initiating issuer '%s'; rejecting the callback (mix-up defence)")
                .build();

        /** A DPoP proof {@code jti} was reused; the proof would be replayable and is refused. */
        public static final LogRecord DPOP_JTI_REUSE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(106)
                .template("DPoP proof 'jti' reuse detected; refusing to emit a replayable proof (RFC 9449 token-replay defence)")
                .build();

        /** A post-logout redirect URI did not exactly match a registered URI; the logout is refused. */
        public static final LogRecord POST_LOGOUT_REDIRECT_MISMATCH = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(107)
                .template("Post-logout redirect URI '%s' does not exactly match any registered URI; refusing RP-initiated logout (open-redirect defence)")
                .build();

        /** Refresh-token reuse was detected on a stored session; the family is revoked at the AS and the store cleared. */
        public static final LogRecord REFRESH_REUSE_REVOCATION = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(108)
                .template("Refresh token reuse detected for session '%s'; revoking the family at the authorization server (RFC 7009) and clearing the store")
                .build();

        /** A refreshed ID token was inconsistent with the refreshed access token; the refresh is refused. */
        public static final LogRecord REFRESHED_ID_TOKEN_INCONSISTENT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(109)
                .template("Refreshed ID token is inconsistent with the refreshed access token (OIDC Core §12.2 'iss'/'sub'); refusing to apply the refresh")
                .build();

        /**
         * The authorization server granted a narrower scope than this client requested. Reported, not
         * refused — RFC 6749 §3.3 permits the server to withhold requested scopes provided it
         * discloses the result.
         */
        public static final LogRecord SCOPE_NARROWED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(110)
                .template("Authorization server granted a narrower scope than requested on refresh; granted '%s', requested '%s'")
                .build();

        /**
         * The authorization server granted a scope this client did not request. Reported by default,
         * and refused only when the client opted in via
         * {@code ClientConfiguration.strictScopeReconciliation}. This is an anomaly report for the
         * operator and the calling application, not a violation notice.
         */
        public static final LogRecord SCOPE_BROADENED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(111)
                .template("Authorization server granted a broader scope than requested on refresh; granted '%s', requested '%s'")
                .build();

        /**
         * A refresh the authorization server had already rotated was refused by the identity or
         * sender-constraint binding check; the session is quarantined fail-closed because the presented
         * token is burned at the AS and the rotated one must not be kept.
         */
        public static final LogRecord REFRESH_IDENTITY_REJECTED_QUARANTINE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(112)
                .template("Refresh refused after the authorization server rotated the token for session '%s'; revoking the rotated token at the authorization server (RFC 7009) and clearing the store and rotation family")
                .build();
    }

    /**
     * Error-level messages (ERROR range 200-299).
     */
    @UtilityClass
    public static final class ERROR {

        /** OIDC discovery failed for the given issuer. */
        public static final LogRecord DISCOVERY_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(200)
                .template("OIDC discovery failed for issuer '%s': %s")
                .build();
    }
}
