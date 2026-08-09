/*
 * Copyright © 2022 CUI-OpenSource-Software (info@cuioss.de)
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
package de.cuioss.sheriff.token.quarkus.observability;

import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.quarkus.config.IssuerConfigResolver;
import de.cuioss.sheriff.token.quarkus.producer.TokenValidatorProducer;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Any;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.Config;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static de.cuioss.sheriff.token.quarkus.TokenSheriffQuarkusLogMessages.INFO;
import static de.cuioss.sheriff.token.quarkus.TokenSheriffQuarkusLogMessages.WARN;

/**
 * Resolves which {@link TokenValidator} the extension's observability beans should report against.
 * <p>
 * The extension's own {@link TokenValidatorProducer} initializes from the
 * {@code sheriff.token.issuers.*} property namespace and fails fast when that namespace yields no
 * enabled issuer. Observability beans must therefore not bind to that producer's by-products:
 * an embedder that supplies its own qualified {@code TokenValidator} and leaves the namespace
 * unpopulated would otherwise trigger the producer's failure on every health probe, metrics tick
 * and DevUI call.
 * </p>
 * <p>
 * This resolver answers "which validator is in use, and is anything configured at all?" without
 * eagerly instantiating the extension's producer:
 * </p>
 * <ol>
 *   <li>Probe {@link IssuerConfigResolver#hasEnabledIssuers(Config)} — a pure {@link Config} read
 *       that touches no CDI bean.</li>
 *   <li>Namespace populated &rarr; {@link Outcome#PROPERTY_CONFIGURED}: the extension's own
 *       produced validator, issuer configurations and parser configuration are the observation
 *       target.</li>
 *   <li>Namespace unpopulated &rarr; enumerate {@code @Any Instance<TokenValidator>} handles and
 *       skip the handle whose bean class is {@link TokenValidatorProducer}. Reading a handle's bean
 *       metadata does not instantiate it, so the failing producer is never initialized. Exactly one
 *       surviving handle &rarr; {@link Outcome#EXTERNAL_VALIDATOR}; several &rarr; a warning naming
 *       the candidates and {@link Outcome#NOT_CONFIGURED}.</li>
 *   <li>Nothing found &rarr; {@link Outcome#NOT_CONFIGURED}.</li>
 * </ol>
 * <p>
 * On the {@link Outcome#EXTERNAL_VALIDATOR} and {@link Outcome#NOT_CONFIGURED} outcomes
 * {@link #observedIssuerConfigs()} is empty and {@link #observedParserConfig()} is
 * {@link Optional#empty()}: the core {@code TokenValidator} exposes neither its issuer
 * configurations nor its parser configuration.
 * </p>
 * <p>
 * The resolution is memoized, but a {@link Outcome#NOT_CONFIGURED} outcome is re-resolved on every
 * call so a validator that becomes available later is still picked up.
 * </p>
 *
 * @since 1.0
 */
@ApplicationScoped
public class ObservedValidatorResolver {

    private static final CuiLogger LOGGER = new CuiLogger(ObservedValidatorResolver.class);

    /**
     * The resolution outcome.
     */
    public enum Outcome {
        /** The {@code sheriff.token.issuers.*} namespace is populated; the extension's own producer is observed. */
        PROPERTY_CONFIGURED,
        /** The namespace is empty and exactly one foreign {@link TokenValidator} bean is observable. */
        EXTERNAL_VALIDATOR,
        /** Neither a configured namespace nor an unambiguous foreign validator exists. */
        NOT_CONFIGURED
    }

    private record Resolution(Outcome outcome, @Nullable TokenValidator validator,
            List<IssuerConfig> issuerConfigs, @Nullable ParserConfig parserConfig) {
    }

    /**
     * The lazily-consulted CDI dependencies. {@code null} when this resolver was constructed with an
     * already-resolved outcome, in which case no resolution ever runs.
     */
    private record CdiHandles(Config config, Instance<TokenValidator> tokenValidators,
            Instance<List<IssuerConfig>> issuerConfigs, Instance<ParserConfig> parserConfig) {
    }

    private final @Nullable CdiHandles cdi;

    private volatile Resolution resolution;
    private volatile @Nullable Outcome lastLoggedOutcome;

    private static final Resolution UNRESOLVED =
            new Resolution(Outcome.NOT_CONFIGURED, null, List.of(), null);

    /**
     * CDI constructor. Every producer-sourced dependency is a lazy {@link Instance} handle, so
     * constructing this bean instantiates nothing.
     *
     * @param config              the MicroProfile configuration used for the property probe
     * @param tokenValidators     all {@link TokenValidator} beans, regardless of qualifier
     * @param issuerConfigsHandle lazy handle to the produced issuer configurations
     * @param parserConfigHandle  lazy handle to the produced parser configuration
     */
    @Inject
    public ObservedValidatorResolver(Config config, @Any Instance<TokenValidator> tokenValidators,
            Instance<List<IssuerConfig>> issuerConfigsHandle, Instance<ParserConfig> parserConfigHandle) {
        this.cdi = new CdiHandles(config, tokenValidators, issuerConfigsHandle, parserConfigHandle);
        this.resolution = UNRESOLVED;
    }

    /**
     * Creates a resolver pinned to an already-resolved outcome, so this bean and its consumers can be
     * exercised without a CDI container.
     *
     * @param outcome       the fixed resolution outcome
     * @param validator     the observed validator, or {@code null} when nothing is observable
     * @param issuerConfigs the observed issuer configurations
     * @param parserConfig  the observed parser configuration, or {@code null} when unavailable
     */
    public ObservedValidatorResolver(Outcome outcome, @Nullable TokenValidator validator,
            List<IssuerConfig> issuerConfigs, @Nullable ParserConfig parserConfig) {
        this.cdi = null;
        this.resolution = new Resolution(outcome, validator, List.copyOf(issuerConfigs), parserConfig);
    }

    /**
     * @return the current resolution outcome
     */
    public Outcome outcome() {
        return resolve().outcome();
    }

    /**
     * @return the observed validator, or {@link Optional#empty()} when nothing is observable
     */
    public Optional<TokenValidator> observedValidator() {
        return Optional.ofNullable(resolve().validator());
    }

    /**
     * @return the observed issuer configurations; empty unless the outcome is
     *         {@link Outcome#PROPERTY_CONFIGURED}
     */
    public List<IssuerConfig> observedIssuerConfigs() {
        return resolve().issuerConfigs();
    }

    /**
     * @return the observed parser configuration; empty unless the outcome is
     *         {@link Outcome#PROPERTY_CONFIGURED}
     */
    public Optional<ParserConfig> observedParserConfig() {
        return Optional.ofNullable(resolve().parserConfig());
    }

    private Resolution resolve() {
        CdiHandles handles = cdi;
        if (handles == null) {
            return resolution;
        }
        Resolution current = resolution;
        if (current.outcome() != Outcome.NOT_CONFIGURED) {
            return current;
        }
        Resolution resolved = doResolve(handles);
        resolution = resolved;
        return resolved;
    }

    private Resolution doResolve(CdiHandles handles) {
        Instance.Handle<TokenValidator> producerHandle = null;
        List<Instance.Handle<TokenValidator>> foreignHandles = new ArrayList<>();
        for (Instance.Handle<TokenValidator> handle : handles.tokenValidators().handles()) {
            if (TokenValidatorProducer.class.equals(handle.getBean().getBeanClass())) {
                producerHandle = handle;
            } else {
                foreignHandles.add(handle);
            }
        }

        if (producerHandle != null && IssuerConfigResolver.hasEnabledIssuers(handles.config())) {
            return logged(new Resolution(Outcome.PROPERTY_CONFIGURED, producerHandle.get(),
                    handles.issuerConfigs().get(), handles.parserConfig().get()), List.of());
        }

        if (foreignHandles.size() == 1) {
            return logged(new Resolution(Outcome.EXTERNAL_VALIDATOR, foreignHandles.getFirst().get(),
                    List.of(), null), List.of());
        }

        List<String> candidates = foreignHandles.stream()
                .map(handle -> handle.getBean().getBeanClass().getName())
                .toList();
        return logged(UNRESOLVED, candidates);
    }

    /**
     * Emits the resolution transition once per distinct outcome rather than on every probe.
     */
    private Resolution logged(Resolution resolved, List<String> ambiguousCandidates) {
        if (resolved.outcome() != lastLoggedOutcome) {
            if (ambiguousCandidates.size() > 1) {
                LOGGER.warn(WARN.AMBIGUOUS_EXTERNAL_VALIDATORS, String.join(", ", ambiguousCandidates));
            }
            LOGGER.info(INFO.OBSERVED_VALIDATOR_RESOLUTION, resolved.outcome());
            lastLoggedOutcome = resolved.outcome();
        }
        return resolved;
    }
}
