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
 * Common benchmarking infrastructure for Token-Sheriff project.
 * <p>
 * This package provides a comprehensive benchmarking framework built on JMH
 * (Java Microbenchmark Harness) that automatically generates artifacts during
 * benchmark execution, including:
 * </p>
 * <ul>
 *   <li>Performance badges (shields.io compatible JSON)</li>
 *   <li>HTML reports with embedded CSS</li>
 *   <li>Structured metrics in JSON format</li>
 *   <li>GitHub Pages deployment structure</li>
 *   <li>CI/CD summary files</li>
 * </ul>
 * <p>
 * The infrastructure supports both micro-benchmarks and integration benchmarks,
 * with automatic detection based on package naming conventions.
 * </p>
 *
 * @author CUI-OpenSource-Software
 */
@NullMarked
package de.cuioss.benchmarking.common;

import org.jspecify.annotations.NullMarked;