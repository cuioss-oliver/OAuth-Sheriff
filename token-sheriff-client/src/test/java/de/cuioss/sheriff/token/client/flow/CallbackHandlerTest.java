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

import de.cuioss.sheriff.token.commons.error.ClientProtocolException;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnableTestLogger
@EnableGeneratorController
@DisplayName("CallbackHandler authorization_code redirect validation (RFC 6749 §4.1.2)")
class CallbackHandlerTest {

    private final CallbackHandler handler = new CallbackHandler();

    private static FlowContext context() {
        return FlowContext.create("https://rp.example.com/callback");
    }

    private static CallbackParameters success(String code, String state) {
        return new CallbackParameters(code, state, null, null, null);
    }

    @Nested
    @DisplayName("Happy path")
    class HappyPath {

        @Test
        @DisplayName("Should return the authorization code when the state echoes the flow context")
        void shouldReturnCodeOnMatchingState() {
            var context = context();
            String code = Generators.nonBlankStrings().next();
            var parameters = success(code, context.state());

            String result = handler.handle(context, parameters);

            assertEquals(code, result, "the validated authorization code is returned for redemption");
        }
    }

    @Nested
    @DisplayName("Fail-closed")
    class FailClosed {

        @Test
        @DisplayName("Should reject an error callback before any code is trusted")
        void shouldRejectErrorCallback() {
            var context = context();
            var parameters = new CallbackParameters(null, context.state(), "access_denied", "user said no", null);

            assertThrows(ClientProtocolException.class, () -> handler.handle(context, parameters));
        }

        @Test
        @DisplayName("Should reject an error callback even when a code is smuggled alongside it")
        void shouldRejectErrorCallbackWithCode() {
            var context = context();
            var parameters = new CallbackParameters(Generators.nonBlankStrings().next(),
                    context.state(), "invalid_request", null, null);

            assertThrows(ClientProtocolException.class, () -> handler.handle(context, parameters));
        }

        @Test
        @DisplayName("Should reject a callback whose state does not match the flow context (CSRF defence)")
        void shouldRejectStateMismatch() {
            var context = context();
            var parameters = success(Generators.nonBlankStrings().next(), Generators.nonBlankStrings().next());

            assertThrows(ClientProtocolException.class, () -> handler.handle(context, parameters));
        }

        @Test
        @DisplayName("Should reject a callback with an absent state")
        void shouldRejectAbsentState() {
            var context = context();
            var parameters = success(Generators.nonBlankStrings().next(), null);

            assertThrows(ClientProtocolException.class, () -> handler.handle(context, parameters));
        }

        @Test
        @DisplayName("Should reject a state that differs only in length from the expected value")
        void shouldRejectLengthMismatch() {
            var context = context();
            var parameters = success(Generators.nonBlankStrings().next(), context.state() + "x");

            assertThrows(ClientProtocolException.class, () -> handler.handle(context, parameters));
        }

        @Test
        @DisplayName("Should reject a matching-state callback that carries no code")
        void shouldRejectMissingCode() {
            var context = context();
            var parameters = success(null, context.state());

            assertThrows(ClientProtocolException.class, () -> handler.handle(context, parameters));
        }

        @Test
        @DisplayName("Should reject a matching-state callback whose code is blank")
        void shouldRejectBlankCode() {
            var context = context();
            var parameters = success("   ", context.state());

            assertThrows(ClientProtocolException.class, () -> handler.handle(context, parameters));
        }

        @Test
        @DisplayName("Should reject null arguments")
        void shouldRejectNullArguments() {
            var context = context();
            var parameters = success(Generators.nonBlankStrings().next(), context.state());

            assertAll("null-guards",
                    () -> assertThrows(NullPointerException.class, () -> handler.handle(null, parameters)),
                    () -> assertThrows(NullPointerException.class, () -> handler.handle(context, null)));
        }
    }

    /**
     * H8: the callback parameters carry the authorization {@code code} and the anti-CSRF {@code state};
     * a stray {@code toString()} must never leak either. The secret-bearing fields are asserted absent
     * and the non-secret diagnostics fields asserted present.
     */
    @Nested
    @DisplayName("Secret redaction in toString() (H8)")
    class SecretRedaction {

        @Test
        @DisplayName("Should redact the authorization code and CSRF state in CallbackParameters.toString()")
        void shouldRedactCodeAndState() {
            String code = Generators.letterStrings(20, 40).next();
            String state = Generators.letterStrings(20, 40).next();
            var parameters = new CallbackParameters(code, state, "access_denied", "user said no",
                    "https://issuer.example.com");

            String rendered = parameters.toString();

            assertAll("redacted CallbackParameters rendering",
                    () -> assertFalse(rendered.contains(code),
                            "the authorization code must not appear in toString()"),
                    () -> assertFalse(rendered.contains(state), "the CSRF state must not appear in toString()"),
                    () -> assertTrue(rendered.contains("<redacted>"), "the secret-carrying fields are redacted"),
                    () -> assertTrue(rendered.contains("access_denied"),
                            "the non-secret error is shown for diagnostics"),
                    () -> assertTrue(rendered.contains("https://issuer.example.com"),
                            "the non-secret issuer is shown for diagnostics"));
        }

        @Test
        @DisplayName("Should render absent code and state as null rather than a redacted marker")
        void shouldRenderAbsentSecretsAsNull() {
            var parameters = new CallbackParameters(null, null, "server_error", null, null);

            String rendered = parameters.toString();

            assertAll("absent optional secrets",
                    () -> assertTrue(rendered.contains("code=null"), "an absent code reads as null"),
                    () -> assertTrue(rendered.contains("state=null"), "an absent state reads as null"));
        }
    }

    /**
     * M8 / L18: browser-controlled callback input reaches an exception message on the fail-closed path.
     * That message must be neutralized against CRLF log-forging (M8) and bounded in length so an
     * attacker cannot flood the log with an arbitrarily long value (L18).
     */
    @Nested
    @DisplayName("External-input sanitization in exception messages (M8, L18)")
    class ExternalInputSanitization {

        @Test
        @DisplayName("Should escape CR/LF in the error-callback exception message to prevent log forging")
        void shouldEscapeCrlfInErrorMessage() {
            var context = context();
            var parameters = new CallbackParameters(null, context.state(),
                    "access_denied\r\nWARN forged log line", "desc", null);

            var thrown = assertThrows(ClientProtocolException.class,
                    () -> handler.handle(context, parameters));

            assertAll("sanitized exception message",
                    () -> assertFalse(thrown.getMessage().contains("\n"),
                            "no raw newline survives to forge a log line"),
                    () -> assertFalse(thrown.getMessage().contains("\r"),
                            "no raw carriage return survives to forge a log line"),
                    () -> assertTrue(thrown.getMessage().contains("\\r\\n"),
                            "CR/LF are escaped, preserving the investigative content"));
        }

        @Test
        @DisplayName("Should route both error and error_description through the commons normalizer (COMMONS-11)")
        void shouldSurfaceSanitizedErrorDescription() {
            var context = context();
            // The previous inline rejection dropped error_description entirely; the normalizer now
            // surfaces it — sanitized — so both directions share one contract.
            var parameters = new CallbackParameters(null, context.state(),
                    "access_denied", "the resource owner denied\r\nWARN forged the request", null);

            var thrown = assertThrows(ClientProtocolException.class,
                    () -> handler.handle(context, parameters));

            assertAll("normalized error callback",
                    () -> assertTrue(thrown.getMessage().contains("access_denied"),
                            "the error code is surfaced"),
                    () -> assertTrue(thrown.getMessage().contains("the resource owner denied"),
                            "the (sanitized) error_description is now surfaced, not dropped"),
                    () -> assertFalse(thrown.getMessage().contains("\n"),
                            "no raw newline from the error_description survives"),
                    () -> assertFalse(thrown.getMessage().contains("\r"),
                            "no raw carriage return from the error_description survives"));
        }

        @Test
        @DisplayName("Should truncate an over-long error value in the exception message to bound log flooding")
        void shouldTruncateOverlongError() {
            var context = context();
            String overlong = "a".repeat(300);
            var parameters = new CallbackParameters(null, context.state(), overlong, null, null);

            var thrown = assertThrows(ClientProtocolException.class,
                    () -> handler.handle(context, parameters));

            assertAll("bounded exception message",
                    () -> assertTrue(thrown.getMessage().contains("...[truncated]"),
                            "an over-long value is marked truncated"),
                    () -> assertFalse(thrown.getMessage().contains(overlong),
                            "the full over-long value is not carried into the message"));
        }
    }
}
