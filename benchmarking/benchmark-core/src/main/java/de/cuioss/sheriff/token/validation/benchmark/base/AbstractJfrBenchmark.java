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
package de.cuioss.sheriff.token.validation.benchmark.base;

import de.cuioss.benchmarking.common.jfr.JfrInstrumentation;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.TearDown;

/**
 * Abstract base class for JFR-instrumented benchmarks.
 * Extends AbstractBenchmark to add JFR-specific functionality.
 *
 * @author Oliver Wolff
 */
public abstract class AbstractJfrBenchmark extends AbstractBenchmark {

    protected JfrInstrumentation jfrInstrumentation;

    /**
     * Get the phase name for JFR recording.
     * Subclasses can override this to provide specific phase names.
     *
     * @return Phase name for JFR events
     */
    protected String getJfrPhase() {
        return "measurement";
    }

    /**
     * Setup method for JFR benchmark initialization.
     * Subclasses should call this from their @Setup method.
     */
    protected void setupJfrBase() {
        // Call parent setup
        setupBase();

        // Initialize JFR instrumentation
        jfrInstrumentation = new JfrInstrumentation();
    }

    /**
     * Records JFR phase information at the start of each iteration.
     */
    @Setup(Level.Iteration)
    public void setupIteration() {
        // Record benchmark phase event at iteration start
        String benchmarkName = this.getClass().getSimpleName();
        int threads = Thread.activeCount();

        jfrInstrumentation.recordPhase(benchmarkName, getJfrPhase(), 0, 0, 1, threads);
    }

    /**
     * Shuts down JFR instrumentation and exports metrics at the end of the trial.
     */
    @Override
    @TearDown(Level.Trial)
    public void exportBenchmarkMetrics() {
        // Shutdown JFR instrumentation
        if (jfrInstrumentation != null) {
            jfrInstrumentation.shutdown();
        }

        // Call parent's export method
        super.exportBenchmarkMetrics();
    }
}