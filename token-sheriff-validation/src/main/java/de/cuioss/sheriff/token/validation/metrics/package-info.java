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
 * High-metrics monitoring components for JWT validation pipeline metrics analysis.
 * <p>
 * This package provides thread-safe, low-overhead metrics monitoring capabilities
 * for JWT validation operations. The components are designed to have minimal runtime
 * impact while providing detailed insights into validation metrics.
 * <p>
 * Key features:
 * <ul>
 *   <li><strong>Lock-free operations:</strong> All measurements use atomic operations only</li>
 *   <li><strong>Microsecond precision:</strong> High-resolution timing for accurate analysis</li>
 *   <li><strong>Rolling window sampling:</strong> Configurable sample size for recent measurements</li>
 *   <li><strong>Pipeline-aware:</strong> Separate measurements for each validation step</li>
 *   <li><strong>Thread-safe:</strong> Optimized for high-concurrency environments</li>
 * </ul>
 * <p>
 * The monitoring system follows the same design principles as the security monitoring
 * components, providing a framework-agnostic foundation that can be integrated with
 * external monitoring systems like Micrometer/Prometheus in higher-level modules.
 *
 * @author Oliver Wolff
 */
package de.cuioss.sheriff.token.validation.metrics;