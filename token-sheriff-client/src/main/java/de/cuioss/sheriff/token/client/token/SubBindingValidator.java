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
package de.cuioss.sheriff.token.client.token;

import de.cuioss.tools.logging.CuiLogger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Objects;

/**
 * Binds a userinfo response to the validated ID token by asserting their {@code sub} claims match
 * (OIDC Core §5.3.2, {@code CLIENT-16}).
 * <p>
 * OIDC Core requires that the {@code sub} returned from the userinfo endpoint MUST exactly match the
 * {@code sub} in the ID token; otherwise the userinfo response MUST NOT be used. Because an unsigned
 * userinfo document is only transport-authenticated, this binding is what stops one user's ID token
 * from being paired with another user's userinfo claims. The comparison is constant-time and fails
 * closed on a missing or mismatched {@code sub}.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse">OIDC Core §5.3.2</a>
 */
public class SubBindingValidator {

    private static final CuiLogger LOGGER = new CuiLogger(SubBindingValidator.class);

    /**
     * Asserts the userinfo {@code sub} matches the validated ID token {@code sub}.
     *
     * @param idTokenSubject the {@code sub} from the validated ID token; must not be {@code null}
     * @param userInfo       the userinfo response to bind; must not be {@code null}
     * @throws IllegalStateException if the userinfo {@code sub} is absent or does not match
     */
    public void validate(String idTokenSubject, UserInfoResponse userInfo) {
        Objects.requireNonNull(idTokenSubject, "idTokenSubject must not be null");
        Objects.requireNonNull(userInfo, "userInfo must not be null");

        String userInfoSubject = userInfo.getSub().orElse(null);
        if (userInfoSubject == null) {
            LOGGER.debug("Rejecting userinfo response: missing 'sub'");
            throw new IllegalStateException("userinfo response is missing the 'sub' claim");
        }
        if (!subjectsMatch(idTokenSubject, userInfoSubject)) {
            LOGGER.debug("Rejecting userinfo response: 'sub' does not match the ID token subject");
            throw new IllegalStateException("userinfo 'sub' does not match the ID token subject");
        }
    }

    private static boolean subjectsMatch(String expected, String actual) {
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }
}
