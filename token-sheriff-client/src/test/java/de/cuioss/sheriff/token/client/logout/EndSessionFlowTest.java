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

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * RP-initiated logout request-building tests for {@link EndSessionFlow} ({@code CLIENT-13}) —
 * deliverable 9.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("EndSessionFlow RP-initiated logout request")
class EndSessionFlowTest {

    private static final String END_SESSION_ENDPOINT =
            "https://as.example.com/realms/demo/protocol/openid-connect/logout";
    private static final String REGISTERED_REDIRECT = "https://rp.example.com/postlogout";

    private final EndSessionFlow flow =
            new EndSessionFlow(new PostLogoutRedirectValidator(Set.of(REGISTERED_REDIRECT)));

    @Test
    @DisplayName("Should build a logout URL carrying id_token_hint, exact post_logout_redirect_uri, and state")
    void shouldBuildLogoutUrl() {
        String idTokenHint = Generators.letterStrings(30, 60).next();
        String state = Generators.letterStrings(20, 40).next();

        String url = flow.buildLogoutRedirect(END_SESSION_ENDPOINT, idTokenHint, REGISTERED_REDIRECT, state);

        assertAll("logout url",
                () -> assertTrue(url.startsWith(END_SESSION_ENDPOINT + "?"), "targets the end_session_endpoint"),
                () -> assertTrue(url.contains("id_token_hint=" + urlEncode(idTokenHint)), "carries the id_token_hint"),
                () -> assertTrue(url.contains("post_logout_redirect_uri=" + urlEncode(REGISTERED_REDIRECT)),
                        "carries the exact post_logout_redirect_uri"),
                () -> assertTrue(url.contains("state=" + urlEncode(state)), "carries the session-bound state"));
    }

    @Test
    @DisplayName("Should refuse to build a logout without an id_token_hint")
    void shouldRejectMissingIdTokenHint() {
        String state = Generators.letterStrings(20, 40).next();

        assertAll("id_token_hint required",
                () -> assertThrows(NullPointerException.class,
                        () -> flow.buildLogoutRedirect(END_SESSION_ENDPOINT, null, REGISTERED_REDIRECT, state)),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> flow.buildLogoutRedirect(END_SESSION_ENDPOINT, "  ", REGISTERED_REDIRECT, state)));
    }

    @Test
    @DisplayName("Should refuse to build a logout without a state")
    void shouldRejectMissingState() {
        String idTokenHint = Generators.letterStrings(30, 60).next();

        assertAll("state required",
                () -> assertThrows(NullPointerException.class,
                        () -> flow.buildLogoutRedirect(END_SESSION_ENDPOINT, idTokenHint, REGISTERED_REDIRECT, null)),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> flow.buildLogoutRedirect(END_SESSION_ENDPOINT, idTokenHint, REGISTERED_REDIRECT, "  ")));
    }

    @Test
    @DisplayName("Should reject a null redirect validator at construction")
    void shouldRejectNullValidator() {
        assertThrows(NullPointerException.class, () -> new EndSessionFlow(null));
    }

    @Test
    @DisplayName("Should accept a post-logout state that matches the session-bound state (M2)")
    void shouldAcceptMatchingPostLogoutState() {
        String state = Generators.letterStrings(20, 40).next();

        assertDoesNotThrow(() -> flow.verifyPostLogoutState(state, state),
                "a matching echoed state closes the RP-initiated-logout CSRF check");
    }

    @Test
    @DisplayName("Should reject a post-logout state that does not match the session-bound state (M2)")
    void shouldRejectMismatchedPostLogoutState() {
        String expectedState = Generators.letterStrings(20, 40).next();
        String returnedState = Generators.letterStrings(41, 60).next();

        var thrown = assertThrows(IllegalStateException.class,
                () -> flow.verifyPostLogoutState(expectedState, returnedState));
        assertTrue(thrown.getMessage().contains("state"),
                "the fail-closed rejection must name the mismatched state");
    }

    @Test
    @DisplayName("Should reject an absent or blank echoed post-logout state (M2)")
    void shouldRejectMissingReturnedState() {
        String expectedState = Generators.letterStrings(20, 40).next();

        assertAll("echoed state required",
                () -> assertThrows(IllegalStateException.class,
                        () -> flow.verifyPostLogoutState(expectedState, null)),
                () -> assertThrows(IllegalStateException.class,
                        () -> flow.verifyPostLogoutState(expectedState, "   ")));
    }

    @Test
    @DisplayName("Should reject a null or blank expected post-logout state (M2)")
    void shouldRejectInvalidExpectedState() {
        String returnedState = Generators.letterStrings(20, 40).next();

        assertAll("expected state required",
                () -> assertThrows(NullPointerException.class,
                        () -> flow.verifyPostLogoutState(null, returnedState)),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> flow.verifyPostLogoutState("   ", returnedState)));
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
