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
package de.cuioss.sheriff.token.commons.transport;

import de.cuioss.sheriff.token.commons.error.TransportException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("EgressPolicy SSRF egress guard")
class EgressPolicyTest {

    private static final String ATTACKER_URL = "https://attacker.example.com/.well-known/jwks.json";

    /**
     * A deterministic resolver that maps every host to a fixed set of literal IPs, so the
     * DNS-rebinding re-check can be exercised without touching real DNS.
     */
    private static EgressPolicy.HostResolver fixedResolver(String... ips) {
        return host -> {
            InetAddress[] addresses = new InetAddress[ips.length];
            for (int i = 0; i < ips.length; i++) {
                addresses[i] = InetAddress.getByName(ips[i]);
            }
            return addresses;
        };
    }

    @Nested
    @DisplayName("Blocked address ranges (default posture)")
    class BlockedRanges {

        @ParameterizedTest(name = "rejects {0}")
        @ValueSource(strings = {
                "127.0.0.1",        // IPv4 loopback
                "::1",              // IPv6 loopback
                "169.254.169.254",  // cloud metadata (IPv4 link-local)
                "169.254.0.1",      // IPv4 link-local
                "fe80::1",          // IPv6 link-local
                "10.0.0.1",         // site-local 10/8
                "172.16.0.1",       // site-local 172.16/12
                "192.168.1.1",      // site-local 192.168/16
                "fc00::1",          // IPv6 unique-local (ULA)
                "fd12:3456::1",     // IPv6 unique-local (ULA)
                "0.0.0.0"           // wildcard / any-local
        })
        @DisplayName("Should reject each internal/metadata address")
        @SuppressWarnings("java:S5778") // URI.create(ATTACKER_URL) is a fixed constant that never throws
        void shouldRejectBlockedAddress(String blockedIp) {
            EgressPolicy policy = EgressPolicy.builder()
                    .resolver(fixedResolver(blockedIp))
                    .build();

            TransportException exception = assertThrows(TransportException.class,
                    () -> policy.check(URI.create(ATTACKER_URL)),
                    "Egress to " + blockedIp + " must be blocked");
            assertTrue(exception.getMessage().contains("SSRF egress blocked"),
                    "Rejection must use the typed SSRF-blocked branch");
        }

        @Test
        @DisplayName("Should allow a public routable address")
        void shouldAllowPublicAddress() {
            EgressPolicy policy = EgressPolicy.builder()
                    .resolver(fixedResolver("93.184.216.34"))
                    .build();

            assertDoesNotThrow(() -> policy.check(URI.create(ATTACKER_URL)),
                    "Public addresses must be permitted");
        }
    }

    @Nested
    @DisplayName("Loopback opt-in")
    class LoopbackOptIn {

        @Test
        @DisplayName("Should permit loopback when allowLoopback(true)")
        void shouldPermitLoopbackWhenOptedIn() {
            EgressPolicy policy = EgressPolicy.builder()
                    .allowLoopback(true)
                    .resolver(fixedResolver("127.0.0.1"))
                    .build();

            assertDoesNotThrow(() -> policy.check(URI.create(ATTACKER_URL)),
                    "Loopback must be permitted under the explicit opt-in");
        }

        @Test
        @DisplayName("Should still block non-loopback internal ranges under loopback opt-in")
        @SuppressWarnings("java:S5778") // URI.create(ATTACKER_URL) is a fixed constant that never throws
        void shouldStillBlockSiteLocalUnderLoopbackOptIn() {
            EgressPolicy policy = EgressPolicy.builder()
                    .allowLoopback(true)
                    .resolver(fixedResolver("10.0.0.1"))
                    .build();

            assertThrows(TransportException.class,
                    () -> policy.check(URI.create(ATTACKER_URL)),
                    "Loopback opt-in must not relax site-local blocking");
        }
    }

    @Nested
    @DisplayName("Host allow-list")
    class HostAllowList {

        @Test
        @DisplayName("Should bypass address checks for an allow-listed host")
        void shouldBypassForAllowedHost() {
            EgressPolicy policy = EgressPolicy.builder()
                    .allowedHost("internal.example.com")
                    .resolver(fixedResolver("10.0.0.1"))
                    .build();

            assertDoesNotThrow(
                    () -> policy.check(URI.create("https://internal.example.com/jwks")),
                    "Allow-listed hosts must bypass address-range checks");
        }

        @Test
        @DisplayName("Should match allow-listed host case-insensitively")
        void shouldMatchAllowedHostCaseInsensitively() {
            EgressPolicy policy = EgressPolicy.builder()
                    .allowedHost("Internal.Example.Com")
                    .resolver(fixedResolver("10.0.0.1"))
                    .build();

            assertDoesNotThrow(
                    () -> policy.check(URI.create("https://INTERNAL.example.com/jwks")),
                    "Allow-list matching must be case-insensitive");
        }
    }

    @Nested
    @DisplayName("Post-DNS re-check (DNS-rebinding defense)")
    class PostDnsRecheck {

        @Test
        @DisplayName("Should reject when any resolved address is internal")
        @SuppressWarnings("java:S5778") // URI.create(ATTACKER_URL) is a fixed constant that never throws
        void shouldRejectWhenAnyResolvedAddressIsInternal() {
            EgressPolicy policy = EgressPolicy.builder()
                    .resolver(fixedResolver("93.184.216.34", "169.254.169.254"))
                    .build();

            assertThrows(TransportException.class,
                    () -> policy.check(URI.create(ATTACKER_URL)),
                    "A benign first record must not mask an internal second record");
        }
    }

    @Nested
    @DisplayName("Malformed / unresolvable inputs")
    class MalformedInputs {

        @Test
        @DisplayName("Should reject a URI without a host")
        @SuppressWarnings("java:S5778") // URI.create(...) is a fixed constant literal that never throws
        void shouldRejectUriWithoutHost() {
            EgressPolicy policy = EgressPolicy.secureDefault();

            assertThrows(TransportException.class,
                    () -> policy.check(URI.create("file:///etc/passwd")),
                    "A host-less URI cannot be egress-checked and must be rejected");
        }

        @Test
        @DisplayName("Should pass through an unresolvable host to the fetch path")
        void shouldPassThroughUnresolvableHost() {
            EgressPolicy policy = EgressPolicy.builder()
                    .resolver(host -> {
                        throw new UnknownHostException(host);
                    })
                    .build();

            assertDoesNotThrow(
                    () -> policy.check(URI.create(ATTACKER_URL)),
                    "An unresolvable host reaches no internal resource; the fetch path handles the failure");
        }
    }

    @Nested
    @DisplayName("Secure default posture")
    class SecureDefaultPosture {

        @Test
        @DisplayName("Should reject loopback with the production default resolver")
        @SuppressWarnings("java:S5778") // URI.create(...) is a fixed constant literal that never throws
        void secureDefaultRejectsLoopback() {
            EgressPolicy policy = EgressPolicy.secureDefault();

            assertThrows(TransportException.class,
                    () -> policy.check(URI.create("https://127.0.0.1/jwks")),
                    "secureDefault() must reject loopback egress");
        }
    }
}
