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
/**
 * Java Flight Recorder (JFR) utilities for benchmark analysis.
 * <p>
 * This package provides common JFR functionality that can be reused across
 * different benchmark implementations:
 * </p>
 * <ul>
 *   <li>{@link de.cuioss.benchmarking.common.jfr.JfrInstrumentation} - Central management for JFR event recording</li>
 *   <li>{@link de.cuioss.benchmarking.common.jfr.JfrVarianceAnalyzer} - Analysis of JFR recordings for variance metrics</li>
 *   <li>{@link de.cuioss.benchmarking.common.jfr.JfrSupport} - Detection and validation of JFR availability</li>
 *   <li>Custom JFR Events:
 *     <ul>
 *       <li>{@link de.cuioss.benchmarking.common.jfr.OperationEvent} - Individual operation tracking</li>
 *       <li>{@link de.cuioss.benchmarking.common.jfr.OperationStatisticsEvent} - Periodic statistics</li>
 *       <li>{@link de.cuioss.benchmarking.common.jfr.BenchmarkPhaseEvent} - Benchmark lifecycle phases</li>
 *     </ul>
 *   </li>
 * </ul>
 * 
 * <p><b>Usage Example:</b></p>
 * <pre>{@code
 * // Check JFR support
 * if (!JfrSupport.isAvailable()) {
 *     System.out.println("JFR not available, skipping instrumentation");
 *     return;
 * }
 * 
 * // Start recording directly
 * Recording recording = new Recording();
 * recording.setDestination(Path.of("benchmark.jfr"));
 * recording.setName("My Benchmark");
 * recording.start();
 * 
 * // Use instrumentation
 * JfrInstrumentation instrumentation = new JfrInstrumentation();
 * try {
 *     // Record operations
 *     try (var recorder = instrumentation.recordOperation("MyBenchmark", "validation")) {
 *         // Perform operation
 *         recorder.withPayloadSize(1024)
 *                 .withSuccess(true);
 *     }
 * } finally {
 *     instrumentation.shutdown();
 *     recording.stop();
 *     recording.close();
 * }
 * 
 * // Analyze results
 * JfrVarianceAnalyzer analyzer = new JfrVarianceAnalyzer();
 * var report = analyzer.analyze(Path.of("benchmark.jfr"));
 * report.printSummary();
 * }</pre>
 */
package de.cuioss.benchmarking.common.jfr;