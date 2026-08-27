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
 * JWT benchmark JFR integration and testing.
 * <p>
 * This package contains JWT-specific JFR benchmark implementations and test utilities.
 * The core JFR functionality has been extracted to {@code de.cuioss.benchmarking.common.jfr} 
 * for reusability across all benchmark modules.
 * </p>
 * 
 * <h2>Package Structure</h2>
 * <ul>
 *   <li>{@code benchmarks/} - JWT-specific JFR-instrumented benchmark implementations</li>
 * </ul>
 * 
 * <h2>Usage</h2>
 * <p>
 * JWT benchmarks use the common JFR utilities from {@code de.cuioss.benchmarking.common.jfr}:
 * </p>
 * <ul>
 *   <li>{@code JfrInstrumentation} - Central instrumentation management</li>
 *   <li>{@code JfrVarianceAnalyzer} - Variance analysis from JFR recordings</li>
 *   <li>{@code JfrSupport} - JFR availability detection</li>
 * </ul>
 * 
 * <h3>Running Benchmarks with JFR</h3>
 * <pre>{@code
 * # Run benchmarks with JFR recording enabled
 * mvn verify -Pbenchmark-jfr
 * 
 * # JFR file will be saved to: target/benchmark-results/benchmark.jfr
 * }</pre>
 * 
 * <h3>Analyzing JFR Data</h3>
 * <pre>{@code
 * // Programmatic analysis
 * Path jfrFile = Path.of("target/benchmark-results/benchmark.jfr");
 * JfrVarianceAnalyzer analyzer = new JfrVarianceAnalyzer();
 * VarianceReport report = analyzer.analyze(jfrFile);
 * report.printSummary();
 * }</pre>
 * 
 */
package de.cuioss.sheriff.token.validation.benchmark.jfr;