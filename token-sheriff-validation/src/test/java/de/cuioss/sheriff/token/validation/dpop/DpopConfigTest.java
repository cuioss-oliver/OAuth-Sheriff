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
package de.cuioss.sheriff.token.validation.dpop;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("DpopConfig Tests")
class DpopConfigTest {

    @Test
    void shouldBuildWithDefaults() {
        DpopConfig config = DpopConfig.builder().build();

        assertFalse(config.isRequired());
        assertEquals(DpopConfig.DEFAULT_PROOF_MAX_AGE_SECONDS, config.getProofMaxAgeSeconds());
        assertEquals(DpopConfig.DEFAULT_NONCE_CACHE_SIZE, config.getNonceCacheSize());
        assertEquals(DpopConfig.DEFAULT_NONCE_CACHE_TTL_SECONDS, config.getNonceCacheTtlSeconds());
    }

    @Test
    void shouldBuildWithCustomValues() {
        // TTL (1200) already covers the replay-window invariant proofMaxAge(600) + clockSkew(60),
        // so the custom value is preserved unchanged (M3). The derivation of a too-small TTL is
        // covered by DpopProofValidatorTest#shouldEnforceReplayWindowInvariantOnBuild.
        DpopConfig config = DpopConfig.builder()
                .required(true)
                .proofMaxAgeSeconds(600)
                .nonceCacheSize(5000)
                .nonceCacheTtlSeconds(1200)
                .build();

        assertTrue(config.isRequired());
        assertEquals(600, config.getProofMaxAgeSeconds());
        assertEquals(5000, config.getNonceCacheSize());
        assertEquals(1200, config.getNonceCacheTtlSeconds());
    }

    @Test
    void shouldRejectNonPositiveProofMaxAge() {
        var builder = DpopConfig.builder().proofMaxAgeSeconds(0);
        assertThrows(IllegalArgumentException.class, builder::build);

        var negativeBuilder = DpopConfig.builder().proofMaxAgeSeconds(-1);
        assertThrows(IllegalArgumentException.class, negativeBuilder::build);
    }

    @Test
    void shouldRejectNonPositiveNonceCacheSize() {
        var builder = DpopConfig.builder().nonceCacheSize(0);
        assertThrows(IllegalArgumentException.class, builder::build);

        var negativeBuilder = DpopConfig.builder().nonceCacheSize(-1);
        assertThrows(IllegalArgumentException.class, negativeBuilder::build);
    }

    @Test
    void shouldRejectNonPositiveNonceCacheTtl() {
        var builder = DpopConfig.builder().nonceCacheTtlSeconds(0);
        assertThrows(IllegalArgumentException.class, builder::build);

        var negativeBuilder = DpopConfig.builder().nonceCacheTtlSeconds(-1);
        assertThrows(IllegalArgumentException.class, negativeBuilder::build);
    }

    @Test
    void shouldRejectProofMaxAgeExceeding3600() {
        var builder = DpopConfig.builder().proofMaxAgeSeconds(3601);
        var exception = assertThrows(IllegalArgumentException.class, builder::build);
        assertTrue(exception.getMessage().contains("must not exceed 3600"));
    }

    @Test
    void shouldAcceptProofMaxAgeAtBoundary3600() {
        // Exactly 3600 should be accepted
        DpopConfig config = DpopConfig.builder().proofMaxAgeSeconds(3600).build();
        assertEquals(3600, config.getProofMaxAgeSeconds());
    }

    @Test
    void shouldRejectNonceCacheTtlExceeding86400() {
        var builder = DpopConfig.builder().nonceCacheTtlSeconds(86401);
        var exception = assertThrows(IllegalArgumentException.class, builder::build);
        assertTrue(exception.getMessage().contains("must not exceed 86400"));
    }

    @Test
    void shouldAcceptNonceCacheTtlAtBoundary86400() {
        // Exactly 86400 should be accepted
        DpopConfig config = DpopConfig.builder().nonceCacheTtlSeconds(86400).build();
        assertEquals(86400, config.getNonceCacheTtlSeconds());
    }

    @Test
    void shouldImplementEqualsAndHashCode() {
        DpopConfig config1 = DpopConfig.builder().build();
        DpopConfig config2 = DpopConfig.builder().build();
        DpopConfig config3 = DpopConfig.builder().required(true).build();

        assertEquals(config1, config2);
        assertEquals(config1.hashCode(), config2.hashCode());
        assertNotEquals(config1, config3);
    }

    @Test
    void shouldImplementToString() {
        DpopConfig config = DpopConfig.builder().build();
        String toString = config.toString();

        assertNotNull(toString);
        assertTrue(toString.contains("proofMaxAgeSeconds"));
        assertTrue(toString.contains("nonceCacheSize"));
    }
}
