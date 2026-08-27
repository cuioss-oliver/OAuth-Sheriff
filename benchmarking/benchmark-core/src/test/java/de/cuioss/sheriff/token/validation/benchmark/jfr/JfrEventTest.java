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
package de.cuioss.sheriff.token.validation.benchmark.jfr;

// cui-rewrite:disable CuiLogRecordPatternRecipe
// This is a test class that outputs diagnostic information for analysis

import de.cuioss.benchmarking.common.jfr.JfrInstrumentation;
import de.cuioss.tools.logging.CuiLogger;
import jdk.jfr.Recording;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JUnit 5 test to verify JFR events are working properly.
 */
@SuppressWarnings("java:S2245") // ThreadLocalRandom is appropriate for test scenarios
class JfrEventTest {

    private static final CuiLogger LOGGER = new CuiLogger(JfrEventTest.class);

    @TempDir
    Path tempDir;

    private Recording recording;

    private Path outputPath;

    @BeforeEach
    void setUp() throws IOException {
        outputPath = tempDir.resolve("test-jfr.jfr");
        recording = new Recording();
        recording.enable("de.cuioss.benchmark.Operation");
        recording.enable("de.cuioss.benchmark.OperationStatistics");
        recording.enable("de.cuioss.benchmark.BenchmarkPhase");
        recording.setDestination(outputPath);
        recording.start();
    }

    @AfterEach
    void tearDown() {
        if (recording != null) {
            recording.close();
        }
    }

    @Test
    void shouldRecordJfrEvents() throws Exception {

        LOGGER.debug("JFR Recording started...");

        // Create instrumentation
        JfrInstrumentation instrumentation = new JfrInstrumentation();
        try {
            // Record phase event
            instrumentation.recordPhase("TestBenchmark", "warmup", 1, 3, 1, 4);

            // Simulate some operations
            CountDownLatch latch = new CountDownLatch(100);
            @SuppressWarnings("java:S2095") // ExecutorService is properly closed in finally block
            ExecutorService executor = Executors.newFixedThreadPool(4);
            try {
                for (int i = 0; i < 100; i++) {
                    final int index = i;
                    executor.submit(() -> {
                        try {
                            try (var recorder =
                                         instrumentation.recordOperation("TestBenchmark", "validation")) {
                                recorder.withPayloadSize(ThreadLocalRandom.current().nextInt(100, 500))
                                        .withMetadata("issuer", "issuer-" + (index % 3))
                                        .withSuccess(index % 10 != 0);

                                Thread.sleep(ThreadLocalRandom.current().nextInt(1, 10));
                            }
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            LOGGER.error(e, "Test operation interrupted");
                        } catch (IllegalStateException | UnsupportedOperationException e) {
                            LOGGER.error(e, "Error during JFR event test operation");
                        } finally {
                            latch.countDown();
                        }
                    });
                }

                latch.await();
                Thread.sleep(2000); // Wait for periodic statistics
            } finally {
                executor.shutdown();
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            }
        } finally {
            instrumentation.shutdown();
        }

        recording.stop();

        // Analyze and assert
        LOGGER.debug("Analyzing JFR recording...");
        assertRecordingContainsEvents(outputPath);
    }

    private static void assertRecordingContainsEvents(Path jfrFile) throws IOException {
        int operationCount = 0;
        int statisticsCount = 0;
        int phaseCount = 0;

        try (RecordingFile recordingFile = new RecordingFile(jfrFile)) {
            while (recordingFile.hasMoreEvents()) {
                RecordedEvent event = recordingFile.readEvent();
                String eventName = event.getEventType().getName();

                switch (eventName) {
                    case "de.cuioss.benchmark.Operation":
                        operationCount++;
                        if (operationCount == 1) {
                            LOGGER.debug("First Operation Event:");
                            LOGGER.debug("  Operation Type: %s", event.getString("operationType"));
                            LOGGER.debug("  Benchmark: %s", event.getString("benchmarkName"));
                            LOGGER.debug("  Duration: %s ms", event.getDuration().toMillis());
                            LOGGER.debug("  Success: %s", event.getBoolean("success"));
                        }
                        break;
                    case "de.cuioss.benchmark.OperationStatistics":
                        statisticsCount++;
                        if (statisticsCount == 1) {
                            LOGGER.debug("First Statistics Event:");
                            LOGGER.debug("  Sample Count: %s", event.getLong("sampleCount"));
                            LOGGER.debug("  P50 Latency: %s ms", event.getDuration("p50Latency").toMillis());
                            LOGGER.debug("  CV: %s%%", event.getDouble("coefficientOfVariation"));
                        }
                        break;
                    case "de.cuioss.benchmark.BenchmarkPhase":
                        phaseCount++;
                        LOGGER.debug("Phase Event:");
                        LOGGER.debug("  Phase: %s", event.getString("phase"));
                        LOGGER.debug("  Benchmark: %s", event.getString("benchmarkName"));
                        break;
                    default:
                        break;
                }
            }
        }

        LOGGER.debug("Summary:");
        LOGGER.debug("  Operation Events: %s", operationCount);
        LOGGER.debug("  Statistics Events: %s", statisticsCount);
        LOGGER.debug("  Phase Events: %s", phaseCount);

        assertTrue(operationCount > 0, "Should have operation events");
    }
}
