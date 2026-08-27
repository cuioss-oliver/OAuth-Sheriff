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
package de.cuioss.sheriff.token.client.flow;

import de.cuioss.sheriff.token.client.flow.StepUpChallengeParser.StepUpChallenge;
import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.token.IdTokenContent;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Verifies, after an elevated {@code authorization_code} exchange, that the RFC 9470 step-up was
 * actually satisfied ({@code CLIENT-12}, {@code H1} / {@code H2}).
 * <p>
 * A resource server drives a step-up by challenging for stronger {@code acr_values} and/or a fresher
 * {@code max_age}. Nothing forces the authorization server to honour that challenge, so the client
 * MUST inspect the returned ID token itself: the {@code acr} claim must be one the challenge required,
 * and — when {@code max_age} was requested — the {@code auth_time} must be within it. A step-up the
 * IdP silently ignored is rejected fail-closed rather than treated as a successful elevation, so an
 * unsatisfied challenge can never be mistaken for a satisfied one.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9470">RFC 9470 - OAuth 2.0 Step Up Authentication Challenge</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OIDC Core - acr / auth_time</a>
 */
public class StepUpResultVerifier {

    private static final String CLAIM_ACR = "acr";
    private static final String CLAIM_AUTH_TIME = "auth_time";

    /**
     * Verifies the completed step-up against the challenge that drove it.
     *
     * @param challenge the step-up challenge; must not be {@code null}
     * @param idToken   the validated ID token returned by the elevated exchange; must not be
     *                  {@code null}
     * @throws ClientProtocolException if the {@code acr} is absent or not among the required values, or
     *                               the {@code auth_time} is absent, unparseable, or older than the
     *                               required {@code max_age}
     */
    public void verify(StepUpChallenge challenge, IdTokenContent idToken) {
        Objects.requireNonNull(challenge, "challenge must not be null");
        Objects.requireNonNull(idToken, "idToken must not be null");
        challenge.getAcrValues().ifPresent(required -> verifyAcr(idToken, required));
        challenge.getMaxAge().ifPresent(maxAge -> verifyAuthTime(idToken, maxAge));
    }

    private static void verifyAcr(IdTokenContent idToken, String requiredAcrValues) {
        Set<String> required = Arrays.stream(requiredAcrValues.strip().split("\\s+"))
                .filter(value -> !value.isBlank())
                .collect(Collectors.toSet());
        if (required.isEmpty()) {
            // Fail closed (H1): the challenge asked for an acr constraint, but it parses to no actual
            // value — so there is nothing to check. Returning normally here would report "verified" to a
            // caller that reads a normal return as proof of elevation, granting a privileged operation on
            // an unelevated authentication. A constraint we cannot evaluate is a rejection, not a pass.
            throw new ClientProtocolException(
                    "step-up challenge carries an 'acr_values' constraint that names no value; "
                            + "the required step-up cannot be verified");
        }
        ClaimValue acrClaim = idToken.getClaims().get(CLAIM_ACR);
        String actualAcr = acrClaim == null ? null : acrClaim.getOriginalString();
        if (actualAcr == null || actualAcr.isBlank()) {
            throw new ClientProtocolException(
                    "step-up ID token carries no 'acr' claim; the required step-up was not satisfied");
        }
        if (!required.contains(actualAcr)) {
            throw new ClientProtocolException(
                    "step-up 'acr' does not satisfy the challenge; the required step-up was not satisfied");
        }
    }

    private static void verifyAuthTime(IdTokenContent idToken, int maxAgeSeconds) {
        ClaimValue authTimeClaim = idToken.getClaims().get(CLAIM_AUTH_TIME);
        if (authTimeClaim == null) {
            throw new ClientProtocolException(
                    "step-up ID token carries no 'auth_time' claim; freshness cannot be verified");
        }
        long authTimeEpochSeconds = resolveAuthTimeEpochSeconds(authTimeClaim);
        long ageSeconds = Instant.now().getEpochSecond() - authTimeEpochSeconds;
        if (ageSeconds > maxAgeSeconds) {
            throw new ClientProtocolException(
                    "step-up authentication is stale: auth_time is older than the required max_age");
        }
    }

    private static long resolveAuthTimeEpochSeconds(ClaimValue authTimeClaim) {
        OffsetDateTime dateTime = authTimeClaim.getDateTime();
        if (dateTime != null) {
            return dateTime.toEpochSecond();
        }
        String raw = authTimeClaim.getOriginalString();
        if (raw == null || raw.isBlank()) {
            throw new ClientProtocolException(
                    "step-up ID token 'auth_time' is empty; freshness cannot be verified");
        }
        try {
            return Long.parseLong(raw.strip());
        } catch (NumberFormatException e) {
            throw new ClientProtocolException("step-up ID token 'auth_time' is not a numeric date", e);
        }
    }
}
