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
package de.cuioss.sheriff.token.validation.test.dispatcher;

/**
 * Shared payload helpers for the adversarial dispatcher modes that back the commons
 * threat catalog (see {@code doc/commons/threat-model.adoc}).
 * <p>
 * Kept package-private so the adversarial payloads stay a test-double implementation detail
 * of the {@code generators} artifact rather than a published API.
 */
final class AdversarialResponses {

    /** Roughly 512 KiB of padding — large enough to trip a response-size limit (T-DOS). */
    private static final int OVERSIZED_PADDING = 512 * 1024;

    private AdversarialResponses() {
        // utility
    }

    /**
     * A syntactically valid JSON document padded to an oversized length, used to exercise
     * response-size limits without breaking JSON parsing before the limit is hit.
     *
     * @return an oversized JSON body
     */
    static String oversizedJson() {
        return "{\"padding\":\"" + "x".repeat(OVERSIZED_PADDING) + "\"}";
    }
}
