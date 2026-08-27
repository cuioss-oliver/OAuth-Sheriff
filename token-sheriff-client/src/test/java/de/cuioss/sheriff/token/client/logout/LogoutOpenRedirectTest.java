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
package de.cuioss.sheriff.token.client.logout;

import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Open-redirect defence tests for {@link PostLogoutRedirectValidator} and {@link EndSessionFlow}
 * ({@code CLIENT-13}, {@code T-LOGOUT}) — deliverable 9.
 * <p>
 * The {@code post_logout_redirect_uri} is matched only by exact, whole-string equality: prefixes,
 * sub-paths, extra query strings, and look-alike hosts must all fail closed.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("RP-initiated logout open-redirect defence")
class LogoutOpenRedirectTest {

    private static final String REGISTERED = "https://rp.example.com/postlogout";
    private static final String END_SESSION_ENDPOINT =
            "https://as.example.com/realms/demo/protocol/openid-connect/logout";

    private final PostLogoutRedirectValidator validator =
            new PostLogoutRedirectValidator(Set.of(REGISTERED));

    @Test
    @DisplayName("Should accept only the exact registered post_logout_redirect_uri")
    void shouldAcceptExactMatchOnly() {
        assertAll("exact match",
                () -> assertEquals(REGISTERED, validator.validate(REGISTERED), "the exact URI is accepted"),
                () -> assertTrue(validator.isRegistered(REGISTERED), "the exact URI is registered"));
    }

    @Test
    @DisplayName("Should reject look-alike, prefix, sub-path, and appended-parameter redirect URIs")
    void shouldRejectNonExactMatches() {
        assertAll("open-redirect variants",
                () -> assertThrows(ClientProtocolException.class,
                        () -> validator.validate("https://rp.example.com.evil.test/postlogout"),
                        "a look-alike host is rejected"),
                () -> assertThrows(ClientProtocolException.class,
                        () -> validator.validate("https://rp.example.com/postlogout/extra"),
                        "a sub-path is rejected"),
                () -> assertThrows(ClientProtocolException.class,
                        () -> validator.validate(REGISTERED + "?next=https://evil.test"),
                        "an appended query string is rejected"),
                () -> assertThrows(ClientProtocolException.class,
                        () -> validator.validate("https://rp.example.com/"),
                        "a prefix is rejected"));
    }

    @Test
    @DisplayName("Should fail closed and log when EndSessionFlow is given an unregistered redirect URI")
    void shouldFailClosedThroughEndSessionFlow() {
        var flow = new EndSessionFlow(validator);
        String idTokenHint = Generators.letterStrings(30, 60).next();
        String state = Generators.letterStrings(20, 40).next();

        assertThrows(ClientProtocolException.class,
                () -> flow.buildLogoutRedirect(END_SESSION_ENDPOINT, idTokenHint,
                        "https://evil.test/postlogout", state),
                "an unregistered redirect URI must abort the logout build");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "does not exactly match any registered URI");
    }

    @Test
    @DisplayName("Should reject null/blank candidates and refuse an empty registration set")
    void shouldRejectInvalidInputs() {
        assertAll("input guards",
                () -> assertThrows(NullPointerException.class, () -> validator.validate(null)),
                () -> assertThrows(IllegalArgumentException.class, () -> validator.validate("  ")),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> new PostLogoutRedirectValidator(Set.of())),
                () -> assertFalse(validator.isRegistered(null), "a null candidate is never registered"));
    }
}
