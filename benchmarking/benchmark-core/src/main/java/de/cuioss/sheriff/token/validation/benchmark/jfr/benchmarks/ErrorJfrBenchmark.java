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
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import org.openjdk.jmh.annotations.*;

import java.util.concurrent.TimeUnit;

/**
 * Error handling JFR-instrumented benchmarks for JWT validation.
 * Split from UnifiedJfrBenchmark to eliminate JMH threading contention.
 * Contains only error scenario benchmarks (4 methods maximum).
 *
 * @author Oliver Wolff
 */
@State(Scope.Thread)
@SuppressWarnings("java:S112")
public class ErrorJfrBenchmark extends AbstractJfrBenchmark {

    private static final String ERROR_VALIDATION_OPERATION = "error-validation";
    public static final String ISSUER = "issuer";

    private ErrorLoadDelegate errorLoadDelegate;

    @Override
    protected String getJfrPhase() {
        return "error-measurement";
    }

    @Setup(Level.Trial)
    public void setup() {
        // Use base class setup
        setupJfrBase();

        // Initialize delegates (using 0% error rate for error scenario testing)
        errorLoadDelegate = new ErrorLoadDelegate(tokenValidator, tokenRepository, 0);
    }

    // ========== Error Load Benchmarks ==========

    /**
     * Measures validation performance for valid tokens with JFR instrumentation.
     */
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public AccessTokenContent validateValidTokenWithJfr() {
        // Select the token once so JFR metadata describes the token that is actually validated
        String token = errorLoadDelegate.nextValidToken();
        try (var recorder = jfrInstrumentation.recordOperation("validateValidTokenWithJfr", "validation")) {
            recorder.withPayloadSize(token.length())
                    .withMetadata(ISSUER, tokenRepository.getTokenIssuer(token).orElse(null));

            AccessTokenContent result = errorLoadDelegate.validateValid(token);
            recorder.withSuccess(true);
            return result;
        }
    }

    /**
     * Measures validation performance for expired tokens with JFR instrumentation.
     */
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public Object validateExpiredTokenWithJfr() {
        try (var recorder = jfrInstrumentation.recordOperation("validateExpiredTokenWithJfr", ERROR_VALIDATION_OPERATION)) {
            recorder.withPayloadSize(errorLoadDelegate.getExpiredToken().length())
                    .withMetadata(ISSUER, errorLoadDelegate.getExpiredTokenIssuer())
                    .withError("expired");

            Object result = errorLoadDelegate.validateExpired();
            recorder.withSuccess(false);
            return result;
        }
    }

    /**
     * Measures validation performance for malformed tokens with JFR instrumentation.
     */
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public Object validateMalformedTokenWithJfr() {
        try (var recorder = jfrInstrumentation.recordOperation("validateMalformedTokenWithJfr", ERROR_VALIDATION_OPERATION)) {
            recorder.withPayloadSize(25) // Length of malformed token
                    .withMetadata(ISSUER, "unknown")
                    .withError("malformed");

            Object result = errorLoadDelegate.validateMalformed();
            recorder.withSuccess(false);
            return result;
        }
    }

    /**
     * Measures validation performance for tokens with invalid signatures with JFR instrumentation.
     */
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public Object validateInvalidSignatureTokenWithJfr() {
        try (var recorder = jfrInstrumentation.recordOperation("validateInvalidSignatureTokenWithJfr", ERROR_VALIDATION_OPERATION)) {
            recorder.withPayloadSize(200) // Approximate size
                    .withMetadata(ISSUER, "benchmark-issuer")
                    .withError("invalid_signature");

            Object result = errorLoadDelegate.validateInvalidSignature();
            recorder.withSuccess(false);
            return result;
        }
    }
}