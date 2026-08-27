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
package de.cuioss.sheriff.token.client.dpop;

import java.util.Objects;

/**
 * Records the sender-constraint bound to a retrieved access token ({@code CLIENT-11}).
 * <p>
 * When a token is obtained under a sender-constraint, the authorization server issues a token whose
 * {@code cnf} (confirmation) claim ties it to a key the client holds — a DPoP proof-key thumbprint
 * ({@code cnf.jkt}, RFC 9449) or the client certificate thumbprint ({@code cnf."x5t#S256"},
 * RFC 8705). This value object carries that binding alongside the stored token so the constraint
 * survives storage and refresh (consumed by the token lifecycle, {@code CLIENT-18}).
 * <p>
 * The engine only <em>records</em> the binding here; verifying that a presented token actually
 * matches the confirmed key is inherited from the validation pipeline ({@code VALIDATION-8.7}) and
 * is not duplicated in the client.
 *
 * @param method       the sender-constraining method; never {@code null}
 * @param confirmation the confirmation value — the base64url JWK thumbprint ({@code jkt}) for DPoP,
 *                     or the base64url certificate thumbprint ({@code x5t#S256}) for mTLS; never
 *                     {@code null} or blank
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9449">RFC 9449 - OAuth 2.0 DPoP</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8705">RFC 8705 - Mutual-TLS Client Authentication and Certificate-Bound Access Tokens</a>
 */
public record ConstraintBinding(Method method, String confirmation) {

    /**
     * The sender-constraining method and the {@code cnf} member it populates.
     */
    public enum Method {

        /** DPoP proof-of-possession (RFC 9449); confirmed via the JWK thumbprint {@code cnf.jkt}. */
        DPOP("jkt"),

        /** Certificate-bound mutual TLS (RFC 8705); confirmed via {@code cnf."x5t#S256"}. */
        MTLS("x5t#S256");

        private final String confirmationMember;

        Method(String confirmationMember) {
            this.confirmationMember = confirmationMember;
        }

        /**
         * @return the {@code cnf} member name that carries this method's confirmation value
         *         ({@code jkt} for DPoP, {@code x5t#S256} for mTLS)
         */
        public String confirmationMember() {
            return confirmationMember;
        }
    }

    /**
     * @param method       the sender-constraining method; must not be {@code null}
     * @param confirmation the confirmation value; must not be {@code null} or blank
     */
    public ConstraintBinding {
        Objects.requireNonNull(method, "method must not be null");
        Objects.requireNonNull(confirmation, "confirmation must not be null");
        if (confirmation.isBlank()) {
            throw new IllegalArgumentException("confirmation must not be blank");
        }
    }

    /**
     * @param jkt the base64url-encoded RFC 7638 JWK thumbprint of the DPoP proof key
     * @return a DPoP sender-constraint binding
     */
    public static ConstraintBinding dpop(String jkt) {
        return new ConstraintBinding(Method.DPOP, jkt);
    }

    /**
     * @param x5tS256 the base64url-encoded SHA-256 thumbprint of the client certificate
     * @return an mTLS certificate-bound sender-constraint binding
     */
    public static ConstraintBinding mtls(String x5tS256) {
        return new ConstraintBinding(Method.MTLS, x5tS256);
    }
}
