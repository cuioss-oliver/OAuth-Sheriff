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
package de.cuioss.sheriff.token.client.discovery;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("ProviderMetadata capability flags")
class ProviderMetadataTest {

    @Test
    @DisplayName("Should report S256 support only when advertised")
    void shouldReportS256Support() {
        var withS256 = new ProviderMetadata();
        withS256.codeChallengeMethodsSupported = List.of("plain", "S256");

        var withoutS256 = new ProviderMetadata();
        withoutS256.codeChallengeMethodsSupported = List.of("plain");

        var absent = new ProviderMetadata();

        assertAll(
                () -> assertTrue(withS256.supportsS256()),
                () -> assertFalse(withoutS256.supportsS256()),
                () -> assertFalse(absent.supportsS256()));
    }

    @Test
    @DisplayName("Should report PAR support based on the endpoint presence")
    void shouldReportParSupport() {
        var withPar = new ProviderMetadata();
        withPar.pushedAuthorizationRequestEndpoint = "https://issuer.example.com/par";

        assertAll(
                () -> assertTrue(withPar.supportsPushedAuthorizationRequests()),
                () -> assertTrue(withPar.getPushedAuthorizationRequestEndpoint().isPresent()),
                () -> assertFalse(new ProviderMetadata().supportsPushedAuthorizationRequests()));
    }

    @Test
    @DisplayName("Should report DPoP support when a signing algorithm is advertised")
    void shouldReportDpopSupport() {
        var withDpop = new ProviderMetadata();
        withDpop.dpopSigningAlgValuesSupported = List.of("ES256");

        assertAll(
                () -> assertTrue(withDpop.supportsDpop()),
                () -> assertFalse(new ProviderMetadata().supportsDpop()));
    }

    @Test
    @DisplayName("Should report end-session support based on the endpoint presence")
    void shouldReportEndSessionSupport() {
        var withEndSession = new ProviderMetadata();
        withEndSession.endSessionEndpoint = "https://issuer.example.com/logout";

        assertAll(
                () -> assertTrue(withEndSession.supportsEndSession()),
                () -> assertTrue(withEndSession.getEndSessionEndpoint().isPresent()),
                () -> assertFalse(new ProviderMetadata().supportsEndSession()));
    }

    @Test
    @DisplayName("Should filter JSON null elements from advertised auth methods so Set.copyOf cannot NPE (L6)")
    void shouldFilterNullAuthMethodElements() {
        var metadata = new ProviderMetadata();
        // DSL-JSON maps a JSON null array element to a null list entry; Arrays.asList admits nulls.
        metadata.tokenEndpointAuthMethodsSupported =
                Arrays.asList("client_secret_basic", null, "private_key_jwt");

        List<String> methods = metadata.getTokenEndpointAuthMethods();

        assertAll("null-element-free advertised methods",
                () -> assertEquals(List.of("client_secret_basic", "private_key_jwt"), methods),
                () -> assertDoesNotThrow(() -> Set.copyOf(methods),
                        "the filtered list must be copyable into a Set without a NullPointerException"));
    }

    @Test
    @DisplayName("Should return an empty list when advertised auth methods are absent")
    void shouldReturnEmptyWhenAuthMethodsAbsent() {
        assertTrue(new ProviderMetadata().getTokenEndpointAuthMethods().isEmpty());
    }

    @Test
    @DisplayName("Should tolerate a JSON null element when checking S256 support (L6)")
    void shouldTolerateNullElementInS256Check() {
        var metadata = new ProviderMetadata();
        metadata.codeChallengeMethodsSupported = Arrays.asList("plain", null, "S256");

        assertTrue(assertDoesNotThrow(metadata::supportsS256),
                "S256 detection must not NPE on a null array element");
    }

    @Test
    @DisplayName("Should expose absent endpoints as empty Optionals")
    void shouldExposeAbsentEndpointsAsEmpty() {
        var empty = new ProviderMetadata();

        assertAll(
                () -> assertFalse(empty.getIssuer().isPresent()),
                () -> assertFalse(empty.getTokenEndpoint().isPresent()),
                () -> assertFalse(empty.getAuthorizationEndpoint().isPresent()),
                () -> assertFalse(empty.getUserinfoEndpoint().isPresent()),
                () -> assertFalse(empty.getJwksUri().isPresent()),
                () -> assertFalse(empty.getRevocationEndpoint().isPresent()),
                () -> assertFalse(empty.getIntrospectionEndpoint().isPresent()));
    }

    @Test
    @DisplayName("Should treat an advertised-but-empty capability as unsupported rather than supported")
    void shouldTreatEmptyAdvertisedCapabilityAsUnsupported() {
        // A discovery document may carry the key with an empty value; presence of the key alone must
        // not be read as a usable capability, or the flow would target an empty endpoint URL.
        var blankEndpoints = new ProviderMetadata();
        blankEndpoints.pushedAuthorizationRequestEndpoint = "   ";
        blankEndpoints.endSessionEndpoint = "";
        var emptyDpop = new ProviderMetadata();
        emptyDpop.dpopSigningAlgValuesSupported = List.of();

        assertAll("advertised-but-empty capabilities",
                () -> assertFalse(blankEndpoints.supportsPushedAuthorizationRequests(),
                        "a blank PAR endpoint is not a usable PAR capability"),
                () -> assertFalse(blankEndpoints.supportsEndSession(),
                        "an empty end-session endpoint is not a usable logout capability"),
                () -> assertFalse(emptyDpop.supportsDpop(),
                        "an empty dpop_signing_alg_values_supported advertises no usable algorithm"));
    }
}
