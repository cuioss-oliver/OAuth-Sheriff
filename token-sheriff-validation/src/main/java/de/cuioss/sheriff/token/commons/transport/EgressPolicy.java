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
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Server-Side Request Forgery (SSRF) egress guard for IdP-controlled URLs.
 * <p>
 * IdP-advertised endpoints (discovery {@code jwks_uri}, well-known documents) are
 * attacker-influenceable: a spoofed discovery document can advertise a {@code jwks_uri}
 * pointing at an internal, loopback, or cloud-metadata address
 * (e.g. {@code http://169.254.169.254/...}). This guard resolves a URL's host to its
 * {@link InetAddress}(es) immediately before the fetch and rejects any resolution that
 * lands in a disallowed range, closing the SSRF vector and — by resolving fresh at the
 * fetch site rather than trusting an earlier resolution — the DNS-rebinding vector.
 * <p>
 * The default posture is secure ({@link #secureDefault()}): loopback, link-local
 * (which covers the {@code 169.254.0.0/16} IPv4 cloud-metadata range and
 * {@code fe80::/10}), site-local ({@code 10/8}, {@code 172.16/12}, {@code 192.168/16}),
 * IPv6 unique-local ({@code fc00::/7}), wildcard, and multicast addresses are all
 * rejected. Both relaxations are explicit, discoverable inputs, never an implicit
 * test-mode:
 * <ul>
 *   <li>{@link EgressPolicyBuilder#allowLoopback(boolean) allowLoopback} — permit
 *       loopback resolutions (for local development and MockWebServer-based tests
 *       fetching from {@code localhost}); all other blocked ranges still apply.</li>
 *   <li>{@link EgressPolicyBuilder#allowedHost(String) allowedHost} — an explicit
 *       host allow-list whose entries bypass address-range checks entirely.</li>
 * </ul>
 * <p>
 * A rejection raises the typed {@link TransportException} SSRF-blocked branch.
 *
 * @since 1.0
 */
@ToString
@EqualsAndHashCode
public final class EgressPolicy {

    /**
     * Resolves a host name to its IP addresses. Abstracted so the DNS-rebinding
     * re-check can be exercised deterministically in tests; the production default is
     * {@link InetAddress#getAllByName(String)}.
     */
    @FunctionalInterface
    public interface HostResolver {

        /**
         * @param host the host name or literal IP to resolve
         * @return the resolved addresses, never empty
         * @throws UnknownHostException if the host cannot be resolved
         */
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    private static final HostResolver DEFAULT_RESOLVER = InetAddress::getAllByName;

    private final boolean allowLoopback;
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    private final Set<String> allowedHosts;
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    private final HostResolver resolver;

    private EgressPolicy(boolean allowLoopback, Set<String> allowedHosts, HostResolver resolver) {
        this.allowLoopback = allowLoopback;
        this.allowedHosts = allowedHosts;
        this.resolver = resolver;
    }

    /**
     * @return a secure-by-default policy: loopback and all internal ranges rejected,
     * empty host allow-list, production DNS resolver
     */
    public static EgressPolicy secureDefault() {
        return builder().build();
    }

    /**
     * @return a new builder pre-set to the secure default posture
     */
    public static EgressPolicyBuilder builder() {
        return new EgressPolicyBuilder();
    }

    /**
     * Resolves {@code uri}'s host and rejects the request if any resolved address falls
     * in a disallowed range. Resolving here — immediately before the fetch — is what
     * closes the DNS-rebinding window: the check runs against the same fresh resolution
     * the fetch will use rather than a cached earlier one.
     *
     * @param uri the IdP-advertised or configured URL about to be fetched
     * @throws TransportException if the URI has no host or resolves to a disallowed
     *                            address (the SSRF-blocked branch)
     */
    public void check(URI uri) {
        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            throw new TransportException("SSRF egress blocked: URL has no resolvable host: " + uri);
        }
        if (allowedHosts.contains(host.toLowerCase(Locale.ROOT))) {
            return;
        }
        InetAddress[] resolved;
        try {
            resolved = resolver.resolve(host);
        } catch (UnknownHostException e) {
            // An unresolvable host reaches no internal resource, so it is not an SSRF
            // condition. Pass it through to the fetch path, which fails closed with the
            // normal network-error semantics (rather than masking a DNS/connectivity
            // failure as an egress block).
            return;
        }
        for (InetAddress address : resolved) {
            rejectIfBlocked(uri, address);
        }
    }

    private void rejectIfBlocked(URI uri, InetAddress address) {
        if (allowLoopback && address.isLoopbackAddress()) {
            return;
        }
        if (address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress()
                || isUniqueLocalIpv6(address)) {
            throw new TransportException(
                    "SSRF egress blocked: URL %s resolves to disallowed address %s"
                            .formatted(uri, address.getHostAddress()));
        }
    }

    /**
     * IPv6 unique-local addresses ({@code fc00::/7}) are the IPv6 counterpart of the
     * IPv4 private ranges and are not covered by {@link InetAddress#isSiteLocalAddress()}
     * (which only matches the deprecated {@code fec0::/10} site-local prefix).
     */
    private static boolean isUniqueLocalIpv6(InetAddress address) {
        return address instanceof Inet6Address && (address.getAddress()[0] & 0xfe) == 0xfc;
    }

    /**
     * Builder for {@link EgressPolicy}, pre-set to the secure default posture.
     */
    public static final class EgressPolicyBuilder {

        private boolean allowLoopback;
        private final Set<String> allowedHosts = new HashSet<>();
        private HostResolver resolver = DEFAULT_RESOLVER;

        private EgressPolicyBuilder() {
        }

        /**
         * Permits resolutions to loopback addresses. Defaults to {@code false}. All other
         * blocked ranges (link-local, site-local, ULA, metadata) still apply.
         *
         * @param allowLoopback {@code true} to allow loopback egress (local dev / tests)
         * @return this builder instance
         */
        public EgressPolicyBuilder allowLoopback(boolean allowLoopback) {
            this.allowLoopback = allowLoopback;
            return this;
        }

        /**
         * Adds a host to the explicit allow-list. Allow-listed hosts bypass address-range
         * checks entirely. Matching is case-insensitive.
         *
         * @param host the host name to allow-list
         * @return this builder instance
         */
        public EgressPolicyBuilder allowedHost(String host) {
            this.allowedHosts.add(host.toLowerCase(Locale.ROOT));
            return this;
        }

        /**
         * Overrides the host resolver. Intended for deterministic DNS-rebinding tests;
         * production callers use the default {@link InetAddress#getAllByName(String)}.
         *
         * @param resolver the resolver to use
         * @return this builder instance
         */
        public EgressPolicyBuilder resolver(HostResolver resolver) {
            this.resolver = resolver;
            return this;
        }

        /**
         * @return a new immutable {@link EgressPolicy} with the configured posture
         */
        public EgressPolicy build() {
            return new EgressPolicy(allowLoopback, Set.copyOf(allowedHosts), resolver);
        }
    }
}
