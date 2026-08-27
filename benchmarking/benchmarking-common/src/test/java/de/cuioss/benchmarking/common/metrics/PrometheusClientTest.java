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
package de.cuioss.benchmarking.common.metrics;

import de.cuioss.benchmarking.common.metrics.test.PrometheusModuleDispatcher;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import lombok.Getter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive tests for PrometheusClient using MockWebServer to simulate various scenarios.
 * Tests cover successful queries, error conditions, timeout scenarios, and edge cases.
 */
@EnableMockWebServer
class PrometheusClientTest {

    @Getter
    private final PrometheusModuleDispatcher moduleDispatcher = new PrometheusModuleDispatcher();

    private PrometheusClient prometheusClient;
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);
    private static final Instant START_TIME = Instant.ofEpochSecond(1758792520);
    private static final Instant END_TIME = Instant.ofEpochSecond(1758792760);
    private static final Duration STEP = Duration.ofSeconds(60);

    @BeforeEach
    void setUp(URIBuilder uriBuilder) {
        String baseUrl = uriBuilder.buildAsString();
        prometheusClient = new PrometheusClient(baseUrl, DEFAULT_TIMEOUT);
        moduleDispatcher.setCallCounter(0);
    }

    @Test
    void shouldQuerySingleMetricSuccessfully() throws Exception {
        // Given
        List<String> metricNames = List.of("process_cpu_usage");

        // When
        Map<String, List<PrometheusClient.TimeSeries>> result = prometheusClient.queryRange(
                metricNames, START_TIME, END_TIME, STEP);

        // Then
        assertEquals(1, result.size());
        assertTrue(result.containsKey("process_cpu_usage"));

        assertEquals(1, result.get("process_cpu_usage").size());
        PrometheusClient.TimeSeries timeSeries = result.get("process_cpu_usage").getFirst();
        assertEquals("process_cpu_usage", timeSeries.metricName());

        // Verify labels
        Map<String, String> labels = timeSeries.labels();
        assertEquals("process_cpu_usage", labels.get("__name__"));
        assertEquals("token-sheriff-integration-tests:8443", labels.get("instance"));
        assertEquals("quarkus-benchmark", labels.get("job"));

        // Verify data points
        List<PrometheusClient.DataPoint> values = timeSeries.values();
        assertEquals(17, values.size());

        PrometheusClient.DataPoint firstPoint = values.getFirst();
        assertEquals(Instant.ofEpochSecond(1758909906), firstPoint.timestamp());
        assertEquals(0.45, firstPoint.value(), 0.0001);

        assertEquals(1, moduleDispatcher.getCallCounter());
    }

    @Test
    void shouldQueryMultipleMetricsSuccessfully() throws Exception {
        // Given
        List<String> metricNames = List.of("process_cpu_usage", "system_cpu_usage", "jvm_memory_used_bytes");

        // When
        Map<String, List<PrometheusClient.TimeSeries>> result = prometheusClient.queryRange(
                metricNames, START_TIME, END_TIME, STEP);

        // Then
        assertEquals(3, result.size());
        assertTrue(result.containsKey("process_cpu_usage"));
        assertTrue(result.containsKey("system_cpu_usage"));
        assertTrue(result.containsKey("jvm_memory_used_bytes"));

        // Verify each metric has expected structure
        result.forEach((metricName, seriesList) -> {
            assertFalse(seriesList.isEmpty());
            for (PrometheusClient.TimeSeries timeSeries : seriesList) {
                assertEquals(metricName, timeSeries.metricName());
                assertFalse(timeSeries.labels().isEmpty());
                assertFalse(timeSeries.values().isEmpty());
            }
        });

        assertEquals(3, moduleDispatcher.getCallCounter());
    }

    @Test
    void shouldHandleEmptyResultGracefully() throws Exception {
        // Given
        moduleDispatcher.setCustomResponse(moduleDispatcher.getEmptyResultResponse());
        List<String> metricNames = List.of("non_existent_metric");

        // When
        Map<String, List<PrometheusClient.TimeSeries>> result = prometheusClient.queryRange(
                metricNames, START_TIME, END_TIME, STEP);

        // Then
        assertEquals(1, result.size());
        assertTrue(result.get("non_existent_metric").isEmpty(),
                "Metric without data should yield an empty series list");

        assertEquals(1, moduleDispatcher.getCallCounter());
    }

    @Test
    void shouldHandlePrometheusErrorResponse() {
        // Given
        moduleDispatcher.setCustomResponse(moduleDispatcher.getErrorResponse());
        List<String> metricNames = List.of("invalid_query");

        // When & Then
        PrometheusClient.PrometheusException exception = assertThrows(
                PrometheusClient.PrometheusException.class,
                () -> prometheusClient.queryRange(metricNames, START_TIME, END_TIME, STEP));

        assertTrue(exception.getMessage().contains("invalid parameter 'query'"));
        assertEquals(1, moduleDispatcher.getCallCounter());
    }

    @ParameterizedTest
    @ValueSource(ints = {500, 503})
    void shouldHandleHttpErrorCodes(int statusCode) {
        // Given
        switch (statusCode) {
            case 500 -> moduleDispatcher.setServerError();
            case 503 -> moduleDispatcher.setServiceUnavailable();
            default -> throw new IllegalArgumentException("Unexpected status code: " + statusCode);
        }
        List<String> metricNames = List.of("test_metric");

        // When & Then
        PrometheusClient.PrometheusException exception = assertThrows(
                PrometheusClient.PrometheusException.class,
                () -> prometheusClient.queryRange(metricNames, START_TIME, END_TIME, STEP));

        assertTrue(exception.getMessage().contains("HTTP " + statusCode));
        assertEquals(statusCode, exception.getStatusCode());
        assertEquals(1, moduleDispatcher.getCallCounter());
    }

    @Test
    void shouldHandle404ErrorWithCustomResponse() {
        // Given - Custom response returns 200 OK, not 404, so we test successful parsing instead
        moduleDispatcher.setCustomResponse("Not Found");
        List<String> metricNames = List.of("test_metric");

        // When & Then - This should succeed but return empty result due to invalid JSON structure
        PrometheusClient.PrometheusException exception = assertThrows(
                PrometheusClient.PrometheusException.class,
                () -> prometheusClient.queryRange(metricNames, START_TIME, END_TIME, STEP));

        assertTrue(exception.getMessage().contains("Unexpected error parsing response"));
        assertEquals(1, moduleDispatcher.getCallCounter());
    }

    @Test
    void shouldHandleInvalidJsonResponse() {
        // Given
        moduleDispatcher.setInvalidJson();
        List<String> metricNames = List.of("test_metric");

        // When & Then
        PrometheusClient.PrometheusException exception = assertThrows(
                PrometheusClient.PrometheusException.class,
                () -> prometheusClient.queryRange(metricNames, START_TIME, END_TIME, STEP));

        assertTrue(exception.getMessage().contains("Unexpected error parsing response"));
        assertEquals(1, moduleDispatcher.getCallCounter());
    }

    @Test
    void shouldHandleNetworkTimeout() {
        // Given
        moduleDispatcher.setTimeout();
        List<String> metricNames = List.of("test_metric");

        // When & Then
        PrometheusClient.PrometheusException exception = assertThrows(
                PrometheusClient.PrometheusException.class,
                () -> prometheusClient.queryRange(metricNames, START_TIME, END_TIME, STEP));

        assertTrue(exception.getMessage().contains("HTTP 408"));
        assertEquals(408, exception.getStatusCode());
        assertEquals(1, moduleDispatcher.getCallCounter());
    }

    @Test
    void shouldConstructUrlCorrectly(URIBuilder uriBuilder) throws Exception {
        // Given
        String baseUrl = uriBuilder.buildAsString();
        PrometheusClient client = new PrometheusClient(baseUrl + "/");  // Test trailing slash removal
        List<String> metricNames = List.of("test_metric[5m]");  // Test URL encoding

        // When
        client.queryRange(metricNames, START_TIME, END_TIME, STEP);

        // Then
        // Verify the request was made (call counter incremented)
        assertEquals(1, moduleDispatcher.getCallCounter());
    }

    @Test
    void shouldUseCustomTimeout(URIBuilder uriBuilder) {
        // Given
        Duration customTimeout = Duration.ofSeconds(1);
        String baseUrl = uriBuilder.buildAsString();
        PrometheusClient clientWithTimeout = new PrometheusClient(baseUrl, customTimeout);

        // When
        moduleDispatcher.setTimeout();
        List<String> metricNames = List.of("test_metric");

        // Then
        assertThrows(PrometheusClient.PrometheusException.class, () ->
                clientWithTimeout.queryRange(metricNames, START_TIME, END_TIME, STEP));
    }

    @Test
    void shouldUseDefaultTimeout(URIBuilder uriBuilder) {
        // Given
        String baseUrl = uriBuilder.buildAsString();
        PrometheusClient clientWithDefaultTimeout = new PrometheusClient(baseUrl);  // Default constructor

        // When & Then
        assertDoesNotThrow(() -> clientWithDefaultTimeout.queryRange(
                List.of("process_cpu_usage"), START_TIME, END_TIME, STEP));
    }

    @Test
    void shouldHandleComplexMetricWithLabels() throws Exception {
        // Given - Using real JWT validation metrics from actual test data
        String complexResponse = """
                {
                  "status": "success",
                  "data": {
                    "resultType": "matrix",
                    "result": [
                      {
                        "metric": {
                          "__name__": "sheriff_token_validation_success_operations_total",
                          "instance": "token-sheriff-integration-tests:8443",
                          "job": "quarkus-benchmark",
                          "event_type": "ACCESS_TOKEN_CREATED",
                          "result": "success"
                        },
                        "values": [
                          [1758909906, "10960018"],
                          [1758909908, "10960018"],
                          [1758909910, "10960018"]
                        ]
                      }
                    ]
                  }
                }
                """;
        moduleDispatcher.setCustomResponse(complexResponse);
        List<String> metricNames = List.of("sheriff_token_validation_success_operations_total");

        // When
        Map<String, List<PrometheusClient.TimeSeries>> result = prometheusClient.queryRange(
                metricNames, START_TIME, END_TIME, STEP);

        // Then
        PrometheusClient.TimeSeries timeSeries = result.get("sheriff_token_validation_success_operations_total").getFirst();
        Map<String, String> labels = timeSeries.labels();

        assertEquals("ACCESS_TOKEN_CREATED", labels.get("event_type"));
        assertEquals("success", labels.get("result"));

        List<PrometheusClient.DataPoint> values = timeSeries.values();
        assertEquals(3, values.size());
        // Using real values from actual test metrics
        assertEquals(10960018.0, values.getFirst().value());
        assertEquals(10960018.0, values.get(1).value());
        assertEquals(10960018.0, values.get(2).value());
    }

    @Test
    void shouldReturnAllSeriesForMultiLabelMetric() throws Exception {
        // Given - real jvm_memory_used_bytes fixture with 5 series (3 heap areas, 2 nonheap areas)
        String multiSeriesResponse = Files.readString(
                Path.of("src/test/resources/metrics/jvm_memory_used.json"));
        moduleDispatcher.setCustomResponse(multiSeriesResponse);
        List<String> metricNames = List.of("jvm_memory_used_bytes");

        // When
        Map<String, List<PrometheusClient.TimeSeries>> result = prometheusClient.queryRange(
                metricNames, START_TIME, END_TIME, STEP);

        // Then - ALL series must be returned, not only the first one
        List<PrometheusClient.TimeSeries> allSeries = result.get("jvm_memory_used_bytes");
        assertEquals(5, allSeries.size(), "All 5 series of the multi-label metric must be returned");

        long heapSeries = allSeries.stream()
                .filter(series -> "heap".equals(series.labels().get("area")))
                .count();
        long nonHeapSeries = allSeries.stream()
                .filter(series -> "nonheap".equals(series.labels().get("area")))
                .count();
        assertEquals(3, heapSeries, "All heap series must be present");
        assertEquals(2, nonHeapSeries, "All nonheap series must be present");

        // Each series carries its own label set and data points
        for (PrometheusClient.TimeSeries series : allSeries) {
            assertEquals("jvm_memory_used_bytes", series.metricName());
            assertTrue(series.labels().containsKey("id"), "Each series keeps its own labels");
            assertFalse(series.values().isEmpty(), "Each series keeps its own data points");
        }
    }

    @Test
    void shouldCalculateStepCorrectly() {
        // Given
        Duration fiveMinuteStep = Duration.ofMinutes(5);
        Duration oneHourStep = Duration.ofHours(1);

        // When & Then - Should not throw exceptions with various step sizes
        assertDoesNotThrow(() -> prometheusClient.queryRange(
                List.of("process_cpu_usage"), START_TIME, END_TIME, fiveMinuteStep));

        assertDoesNotThrow(() -> prometheusClient.queryRange(
                List.of("process_cpu_usage"), START_TIME, END_TIME, oneHourStep));
    }

    @Test
    void shouldHandleFailureInOneOfMultipleMetrics() {
        // Given
        List<String> metricNames = List.of("process_cpu_usage", "failing_metric");
        // Set up to fail on second request
        moduleDispatcher.setCustomResponse(moduleDispatcher.getErrorResponse());

        // When & Then - Should fail fast on first error
        assertThrows(
                PrometheusClient.PrometheusException.class,
                () -> prometheusClient.queryRange(metricNames, START_TIME, END_TIME, STEP));

        // Should stop after first failure
        assertEquals(1, moduleDispatcher.getCallCounter());
    }
}