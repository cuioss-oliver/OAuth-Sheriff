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
package de.cuioss.sheriff.token.commons.error;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("InboundErrorNormalizer (COMMONS-11)")
class InboundErrorNormalizerTest {

    /** The BEL control character (0x07), used to prove non-CR/LF control chars are also escaped. */
    private static final char BELL = 0x07;

    @ParameterizedTest
    @ValueSource(strings = {"invalid_request", "invalid_client", "invalid_grant", "unauthorized_client",
            "unsupported_grant_type", "unsupported_response_type", "access_denied", "invalid_scope",
            "server_error", "temporarily_unavailable"})
    @DisplayName("Should recognize each registered RFC 6749 error code")
    void shouldRecognizeRegisteredErrorCodes(String code) {
        ClientProtocolException exception = InboundErrorNormalizer.normalize(code, null);

        assertAll("recognized error code",
                () -> assertTrue(exception.getMessage().contains(code), "the recognized code is named"),
                () -> assertFalse(exception.getMessage().contains("unrecognized"),
                        "a registered code must not be reported as unrecognized"));
    }

    @Test
    @DisplayName("Should report an unregistered error code as unrecognized")
    void shouldReportUnknownErrorCodeAsUnrecognized() {
        ClientProtocolException exception = InboundErrorNormalizer.normalize("totally_made_up", null);

        assertAll("unrecognized error code",
                () -> assertTrue(exception.getMessage().contains("unrecognized"),
                        "an unregistered code is flagged as unrecognized"),
                () -> assertTrue(exception.getMessage().contains("totally_made_up"),
                        "the (sanitized) offending code is still surfaced for diagnostics"));
    }

    @Test
    @DisplayName("Should report a null error code as a missing error code")
    void shouldReportNullErrorCode() {
        ClientProtocolException exception = InboundErrorNormalizer.normalize(null, "some description");

        assertTrue(exception.getMessage().contains("without an error code"),
                "a null error code produces the missing-code message");
    }

    @Test
    @DisplayName("Should omit a null or blank error_description from the message")
    void shouldOmitBlankDescription() {
        String withNull = InboundErrorNormalizer.normalize("access_denied", null).getMessage();
        String withBlank = InboundErrorNormalizer.normalize("access_denied", "   ").getMessage();

        assertAll("blank description omitted",
                () -> assertFalse(withNull.contains("("), "a null description adds no parenthetical clause"),
                () -> assertFalse(withBlank.contains("("), "a blank description adds no parenthetical clause"));
    }

    @Test
    @DisplayName("Should include a present error_description in the message")
    void shouldIncludePresentDescription() {
        ClientProtocolException exception =
                InboundErrorNormalizer.normalize("access_denied", "the resource owner denied the request");

        assertTrue(exception.getMessage().contains("the resource owner denied the request"),
                "a non-blank description is surfaced alongside the error code");
    }

    @Test
    @DisplayName("Should sanitize CR/LF in both the error code and the error_description (CWE-117)")
    void shouldSanitizeCrlfInBothFields() {
        ClientProtocolException exception = InboundErrorNormalizer.normalize(
                "access_denied\r\nWARN forged-code-line",
                "denied\r\nWARN forged-description-line");

        String message = exception.getMessage();
        assertAll("sanitized fields",
                () -> assertFalse(message.indexOf('\r') >= 0, "no raw CR survives from either field"),
                () -> assertFalse(message.indexOf('\n') >= 0, "no raw LF survives from either field"),
                () -> assertTrue(message.contains("\\r\\n"),
                        "the embedded CR/LF is escaped, preserving the investigative content"));
    }

    @Test
    @DisplayName("Should escape other ASCII control characters in the description")
    void shouldEscapeControlCharacters() {
        ClientProtocolException exception =
                InboundErrorNormalizer.normalize("access_denied", "denied" + BELL + "bell");

        String message = exception.getMessage();
        assertAll("escaped control character",
                () -> assertFalse(message.indexOf(BELL) >= 0, "the raw control character does not survive"),
                () -> assertTrue(message.contains("\\u0007"), "the control character is rendered as an escape"));
    }

    @Test
    @DisplayName("Should truncate an over-long field to bound log flooding")
    void shouldTruncateOverlongField() {
        String overlong = "x".repeat(300);
        ClientProtocolException exception = InboundErrorNormalizer.normalize(overlong, null);

        String message = exception.getMessage();
        assertAll("bounded field",
                () -> assertNotNull(message),
                () -> assertTrue(message.contains("...[truncated]"), "an over-long value is marked truncated"),
                () -> assertFalse(message.contains(overlong), "the full over-long value is not carried"));
    }
}
