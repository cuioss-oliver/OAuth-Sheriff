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
package de.cuioss.sheriff.token.validation.benchmark.jfr.benchmarks;

import de.cuioss.sheriff.token.validation.benchmark.base.AbstractJfrBenchmark;
import de.cuioss.sheriff.token.validation.benchmark.delegates.CoreValidationDelegate;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import org.openjdk.jmh.annotations.*;

import java.util.concurrent.TimeUnit;

/**
 * Core JFR-instrumented benchmark for essential JWT validation performance.
 * Split from UnifiedJfrBenchmark to eliminate JMH threading contention.
 * Contains only core validation benchmarks (3 methods maximum).
 *
 * @author Oliver Wolff
 */
@State(Scope.Thread)
@SuppressWarnings("java:S112")
public class CoreJfrBenchmark extends AbstractJfrBenchmark {

    private static final String OPERATION_TYPE_VALIDATION = "validation";

    private CoreValidationDelegate coreValidationDelegate;

    @Setup(Level.Trial)
    public void setup() {
        // Use base class setup
        setupJfrBase();

        // Initialize delegates
        coreValidationDelegate = new CoreValidationDelegate(tokenValidator, tokenRepository);
    }

    // ========== Core Validation Benchmarks ==========

    /**
     * Measures average validation time for single-threaded token validation with JFR instrumentation using full token spectrum.
     */
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public AccessTokenContent measureAverageTimeWithJfr() {
        return performValidationWithJfr("measureAverageTimeWithJfr", "full_spectrum",
                () -> coreValidationDelegate.validateWithFullSpectrum());
    }

    /**
     * Measures token validation throughput under concurrent load with JFR instrumentation using full token spectrum.
     */
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public AccessTokenContent measureThroughputWithJfr() {
        return performValidationWithJfr("measureThroughputWithJfr", "full_spectrum",
                () -> coreValidationDelegate.validateWithFullSpectrum());
    }

    /**
     * Common method to perform validation with JFR instrumentation.
     *
     * @param operationName the name of the operation for JFR recording
     * @param tokenType the type of token to retrieve
     * @param validationSupplier the validation operation to perform
     * @return the validation result
     */
    private AccessTokenContent performValidationWithJfr(String operationName, String tokenType,
            ValidationSupplier validationSupplier) {
        String token = coreValidationDelegate.getCurrentToken(tokenType);

        try (var recorder = jfrInstrumentation.recordOperation(operationName, OPERATION_TYPE_VALIDATION)) {
            recorder.withPayloadSize(token.length())
                    .withMetadata("issuer", tokenRepository.getTokenIssuer(token).orElse(null));

            AccessTokenContent result = validationSupplier.validate();
            recorder.withSuccess(true);
            return result;
        }
    }

    /**
     * Functional interface for validation operations.
     */
    @FunctionalInterface
    private interface ValidationSupplier {
        AccessTokenContent validate();
    }
}