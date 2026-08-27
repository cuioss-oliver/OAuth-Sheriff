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
package de.cuioss.sheriff.token.validation.benchmark.standard;

import de.cuioss.sheriff.token.validation.benchmark.base.AbstractBenchmark;
import de.cuioss.sheriff.token.validation.benchmark.delegates.ErrorLoadDelegate;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.util.concurrent.TimeUnit;

/**
 * Simplified error load benchmark - split from ErrorLoadBenchmark.
 * Contains only mixed token validation benchmarks (2 methods maximum).
 * Designed to eliminate JMH threading contention by removing @Param annotations.
 *
 * @author Oliver Wolff
 */
@State(Scope.Thread)
@SuppressWarnings("java:S112")
public class SimpleErrorLoadBenchmark extends AbstractBenchmark {

    private ErrorLoadDelegate errorLoadDelegate0;
    private ErrorLoadDelegate errorLoadDelegate50;

    @Setup(Level.Trial)
    public void setup() {
        // Use base class setup
        setupBase();

        // Initialize error load delegates
        errorLoadDelegate0 = new ErrorLoadDelegate(tokenValidator, tokenRepository, 0);
        errorLoadDelegate50 = new ErrorLoadDelegate(tokenValidator, tokenRepository, 50);
    }

    // ========== Simple Error Load Benchmarks ==========

    /**
     * Benchmarks mixed error load scenarios with 0% error rate (baseline performance).
     */
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public Object validateMixedTokens0(Blackhole blackhole) {
        return errorLoadDelegate0.validateMixed(blackhole);
    }

    /**
     * Benchmarks mixed error load scenarios with 50% error rate (balanced mix).
     */
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public Object validateMixedTokens50(Blackhole blackhole) {
        return errorLoadDelegate50.validateMixed(blackhole);
    }

}