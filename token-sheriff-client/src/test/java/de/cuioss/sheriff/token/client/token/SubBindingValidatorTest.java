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

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

@EnableTestLogger
@EnableGeneratorController
@DisplayName("SubBindingValidator userinfo→ID-token sub binding (OIDC Core §5.3.2)")
class SubBindingValidatorTest {

    private final SubBindingValidator validator = new SubBindingValidator();

    private static UserInfoResponse userInfoWithSub(String sub) {
        var response = new UserInfoResponse();
        response.sub = sub;
        return response;
    }

    @Nested
    @DisplayName("Accepts")
    class Accepts {

        @Test
        @DisplayName("Should accept a userinfo sub that matches the ID token subject")
        void shouldAcceptMatchingSub() {
            String subject = Generators.nonBlankStrings().next();

            assertDoesNotThrow(() -> validator.validate(subject, userInfoWithSub(subject)));
        }
    }

    @Nested
    @DisplayName("Rejects")
    class Rejects {

        @Test
        @DisplayName("Should reject a userinfo sub that does not match the ID token subject")
        void shouldRejectMismatchedSub() {
            var userInfo = userInfoWithSub("other-subject");

            assertThrows(IllegalStateException.class, () -> validator.validate("id-token-subject", userInfo));
        }

        @Test
        @DisplayName("Should reject a userinfo response that carries no sub")
        void shouldRejectAbsentSub() {
            var userInfo = userInfoWithSub(null);
            var subject = Generators.nonBlankStrings().next();

            assertThrows(IllegalStateException.class,
                    () -> validator.validate(subject, userInfo));
        }

        @Test
        @DisplayName("Should reject a sub that differs only in trailing length")
        void shouldRejectLengthMismatch() {
            String subject = Generators.letterStrings(8, 16).next();
            var mismatchedUserInfo = userInfoWithSub(subject + "x");

            assertThrows(IllegalStateException.class,
                    () -> validator.validate(subject, mismatchedUserInfo));
        }

        @Test
        @DisplayName("Should reject null arguments")
        void shouldRejectNullArguments() {
            var userInfo = userInfoWithSub(Generators.nonBlankStrings().next());
            var subject = Generators.nonBlankStrings().next();

            assertAll("null-guards",
                    () -> assertThrows(NullPointerException.class, () -> validator.validate(null, userInfo)),
                    () -> assertThrows(NullPointerException.class,
                            () -> validator.validate(subject, null)));
        }
    }
}
