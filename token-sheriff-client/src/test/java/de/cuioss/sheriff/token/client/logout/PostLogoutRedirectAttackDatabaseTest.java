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

import de.cuioss.http.security.database.ApacheCVEAttackDatabase;
import de.cuioss.http.security.database.AttackTestCase;
import de.cuioss.http.security.database.ModSecurityCRSAttackDatabase;
import de.cuioss.http.security.database.OWASPTop10AttackDatabase;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Drives the curated {@code http.security} attack corpora through the {@code post_logout_redirect_uri}
 * comparison and asserts it fails closed ({@code CLIENT-13}, {@code CLIENT-22}, {@code T-LOGOUT}) —
 * deliverable 9.
 * <p>
 * No adversarial payload — injection, traversal, encoding-evasion, or look-alike — ever equals a
 * registered URI, so {@link PostLogoutRedirectValidator} rejects every one and never treats it as a
 * valid post-logout destination.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("post_logout_redirect_uri fail-closed against http.security attack corpora")
class PostLogoutRedirectAttackDatabaseTest {

    private static final String REGISTERED = "https://rp.example.com/postlogout";

    private final PostLogoutRedirectValidator validator =
            new PostLogoutRedirectValidator(Set.of(REGISTERED));

    @ParameterizedTest
    @ArgumentsSource(OWASPTop10AttackDatabase.ArgumentsProvider.class)
    @DisplayName("Should reject an OWASP Top 10 attack payload as a post-logout redirect URI")
    void rejectsOwaspAttacks(AttackTestCase testCase) {
        assertRejected(testCase.attackString());
    }

    @ParameterizedTest
    @ArgumentsSource(ApacheCVEAttackDatabase.ArgumentsProvider.class)
    @DisplayName("Should reject an Apache CVE attack payload as a post-logout redirect URI")
    void rejectsApacheCveAttacks(AttackTestCase testCase) {
        assertRejected(testCase.attackString());
    }

    @ParameterizedTest
    @ArgumentsSource(ModSecurityCRSAttackDatabase.ArgumentsProvider.class)
    @DisplayName("Should reject a ModSecurity CRS attack payload as a post-logout redirect URI")
    void rejectsModSecurityAttacks(AttackTestCase testCase) {
        assertRejected(testCase.attackString());
    }

    private void assertRejected(String attackPayload) {
        assertFalse(validator.isRegistered(attackPayload),
                "an attack payload can never exactly match a registered post_logout_redirect_uri");
        // validate() must fail closed for every attack payload — no silent skip on a blank/null
        // payload: a blank is rejected with IllegalArgumentException, an unregistered non-blank with
        // IllegalStateException, and a null with NullPointerException. All are fail-closed rejections.
        assertThrows(RuntimeException.class, () -> validator.validate(attackPayload),
                "validating an attack-payload redirect URI must always fail closed");
    }
}
