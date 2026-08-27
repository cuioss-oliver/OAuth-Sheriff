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
package de.cuioss.sheriff.token.quarkus.producer;

import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.token.TokenContent;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.time.OffsetDateTime;
import java.util.*;

/**
 * Adapter that wraps a {@link TokenContent} to provide the
 * {@link JsonWebToken} interface for MicroProfile JWT Auth compatibility.
 * <p>
 * This enables standard MP-JWT CDI injection:
 * <pre>{@code
 * @Inject JsonWebToken callerPrincipal;
 * @Inject Principal principal;
 * }</pre>
 *
 * @since 1.0
 */
public final class JsonWebTokenAdapter implements JsonWebToken {

    private final TokenContent delegate;

    public JsonWebTokenAdapter(TokenContent delegate) {
        this.delegate = Objects.requireNonNull(delegate);
    }

    /**
     * Returns the principal name using the MP-JWT fallback chain:
     * {@code upn} -> {@code preferred_username} -> {@code sub}.
     */
    @Override
    public String getName() {
        return delegate.getClaimOption(ClaimName.UPN)
                .map(ClaimValue::getOriginalString)
                .or(() -> delegate.getClaimOption(ClaimName.PREFERRED_USERNAME).map(ClaimValue::getOriginalString))
                .or(delegate::getSubject)
                .orElse(null);
    }

    @Override
    public String getRawToken() {
        return delegate.getRawToken();
    }

    @Override
    public String getIssuer() {
        return delegate.getIssuer();
    }

    @Override
    public String getSubject() {
        return delegate.getSubject()
                .orElse(null);
    }

    @Override
    public Set<String> getAudience() {
        return delegate.getClaimOption(ClaimName.AUDIENCE)
                .map(ClaimValue::getAsList)
                .<Set<String>>map(list -> new LinkedHashSet<>(list))
                .orElse(Set.of());
    }

    @Override
    public String getTokenID() {
        return delegate.getClaimOption(ClaimName.TOKEN_ID)
                .map(ClaimValue::getOriginalString)
                .orElse(null);
    }

    @Override
    public long getExpirationTime() {
        return delegate.getExpirationDateTime().toEpochSecond();
    }

    @Override
    public long getIssuedAtTime() {
        return delegate.getIssuedAtDateTime().toEpochSecond();
    }

    @Override
    public Set<String> getGroups() {
        return delegate.getClaimOption(ClaimName.GROUPS)
                .map(ClaimValue::getAsList)
                .<Set<String>>map(list -> new LinkedHashSet<>(list))
                .orElse(Set.of());
    }

    @Override
    public Set<String> getClaimNames() {
        return delegate.getClaimNames();
    }

    @Override
    public boolean containsClaim(String claimName) {
        return delegate.getClaims().containsKey(claimName);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T getClaim(String claimName) {
        var claimValue = delegate.getClaims().get(claimName);
        if (claimValue == null) {
            return null;
        }
        var knownClaim = ClaimName.fromString(claimName);
        if (knownClaim.isPresent()) {
            var type = knownClaim.get().getValueType();
            return (T) switch (type) {
                case DATETIME -> Optional.ofNullable(claimValue.getDateTime()).map(OffsetDateTime::toEpochSecond).orElse(null);
                case STRING_LIST -> new LinkedHashSet<>(claimValue.getAsList());
                default -> claimValue.getOriginalString();
            };
        }
        return (T) claimValue.getOriginalString();
    }

}
