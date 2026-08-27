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
import de.cuioss.sheriff.token.validation.benchmark.delegates.ErrorLoadDelegate;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.util.concurrent.TimeUnit;

/**
 * Mixed error rate JFR-instrumented benchmarks for JWT validation.
 * Split from UnifiedJfrBenchmark to eliminate JMH threading contention.
 * Contains only mixed token validation benchmarks (2 methods maximum).
 *
 * @author Oliver Wolff
 */
@State(Scope.Thread)
@SuppressWarnings("java:S112")
public class MixedJfrBenchmark extends AbstractJfrBenchmark {

    private static final String MIXED_VALIDATION_OPERATION = "mixed-validation";

    private ErrorLoadDelegate errorLoadDelegate0;
    private ErrorLoadDelegate errorLoadDelegate50;

    @Override
    protected String getJfrPhase() {
        return "mixed-measurement";
    }

    @Setup(Level.Trial)
    public void setup() {
        // Use base class setup
        setupJfrBase();

        // Initialize delegates for different error rates
        errorLoadDelegate0 = new ErrorLoadDelegate(tokenValidator, tokenRepository, 0);
        errorLoadDelegate50 = new ErrorLoadDelegate(tokenValidator, tokenRepository, 50);
    }

    // ========== Mixed Error Rate Benchmarks ==========

    /**
     * Measures validation performance with mixed valid/invalid tokens (0% error rate) with JFR instrumentation.
     */
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public Object validateMixedTokens0WithJfr(Blackhole blackhole) {
        String token = errorLoadDelegate0.selectToken();
        String errorType = errorLoadDelegate0.getErrorType(token);
        boolean isValid = "valid".equals(errorType);

        try (var recorder = jfrInstrumentation.recordOperation("validateMixedTokens0WithJfr", MIXED_VALIDATION_OPERATION)) {
            recorder.withPayloadSize(token.length())
                    .withMetadata("issuer", isValid ? tokenRepository.getTokenIssuer(token).orElse(null) : "benchmark-issuer");

            if (!isValid) {
                recorder.withError(errorType);
            }

            Object result = errorLoadDelegate0.validateMixed(token, blackhole);
            recorder.withSuccess(isValid);
            return result;
        }
    }

    /**
     * Measures validation performance with mixed valid/invalid tokens (50% error rate) with JFR instrumentation.
     */
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public Object validateMixedTokens50WithJfr(Blackhole blackhole) {
        String token = errorLoadDelegate50.selectToken();
        String errorType = errorLoadDelegate50.getErrorType(token);
        boolean isValid = "valid".equals(errorType);

        try (var recorder = jfrInstrumentation.recordOperation("validateMixedTokens50WithJfr", MIXED_VALIDATION_OPERATION)) {
            recorder.withPayloadSize(token.length())
                    .withMetadata("issuer", isValid ? tokenRepository.getTokenIssuer(token).orElse(null) : "benchmark-issuer");

            if (!isValid) {
                recorder.withError(errorType);
            }

            Object result = errorLoadDelegate50.validateMixed(token, blackhole);
            recorder.withSuccess(isValid);
            return result;
        }
    }
}