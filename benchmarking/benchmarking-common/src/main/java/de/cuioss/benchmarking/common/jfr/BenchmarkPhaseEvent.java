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
package de.cuioss.benchmarking.common.jfr;

import jdk.jfr.*;

/**
 * JFR event to mark benchmark phases (warmup, measurement, etc).
 * Helps in separating analysis of different benchmark phases.
 */
@Name("de.cuioss.benchmark.BenchmarkPhase")
@Label("Benchmark Phase")
@Description("Marks the beginning and end of benchmark phases")
@Category({"Benchmark", "Lifecycle"})
@StackTrace(false)
public class BenchmarkPhaseEvent extends Event {

    @Label("Benchmark Name")
    @Description("Name of the benchmark")
    public String benchmarkName;

    @Label("Phase")
    @Description("Benchmark phase (warmup, measurement, etc)")
    public String phase;

    @Label("Iteration")
    @Description("Iteration number within the phase")
    public int iteration;

    @Label("Total Iterations")
    @Description("Total number of iterations in this phase")
    public int totalIterations;

    @Label("Fork")
    @Description("Fork number")
    public int fork;

    @Label("Thread Count")
    @Description("Number of threads used in this phase")
    public int threadCount;
}