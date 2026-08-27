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
package de.cuioss.sheriff.token.commons.transport;

import de.cuioss.test.generator.junit.EnableGeneratorController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit test for {@link LoadingStatusProvider} interface.
 * <p>
 * Tests the interface contract using concrete implementations.
 *
 * @author Oliver Wolff
 */
@EnableGeneratorController
class LoadingStatusProviderTest {

    @Test
    @DisplayName("Should return non-null status from healthy implementation")
    void shouldReturnNonNullStatusFromHealthyImplementation() {
        LoadingStatusProvider provider = new TestHealthyProvider();

        LoaderStatus status = provider.getLoaderStatus();
        assertNotNull(status, "Healthy provider should return non-null status");
        assertEquals(LoaderStatus.OK, status, "Healthy provider should return OK status");
    }

    @Test
    @DisplayName("Should return non-null status from error implementation")
    void shouldReturnNonNullStatusFromErrorImplementation() {
        LoadingStatusProvider provider = new TestErrorProvider();

        LoaderStatus status = provider.getLoaderStatus();
        assertNotNull(status, "Error provider should return non-null status");
        assertEquals(LoaderStatus.ERROR, status, "Error provider should return ERROR status");
    }

    @Test
    @DisplayName("Should return non-null status from undefined implementation")
    void shouldReturnNonNullStatusFromUndefinedImplementation() {
        LoadingStatusProvider provider = new TestUndefinedProvider();

        LoaderStatus status = provider.getLoaderStatus();
        assertNotNull(status, "Undefined provider should return non-null status");
        assertEquals(LoaderStatus.UNDEFINED, status, "Undefined provider should return UNDEFINED status");
    }

    @Test
    @DisplayName("Should be consistent across multiple calls")
    void shouldBeConsistentAcrossMultipleCalls() {
        LoadingStatusProvider provider = new TestHealthyProvider();

        LoaderStatus firstCall = provider.getLoaderStatus();
        LoaderStatus secondCall = provider.getLoaderStatus();

        assertEquals(firstCall, secondCall, "Status should be consistent across multiple calls");
    }

    @Test
    @DisplayName("Should handle thread safety")
    void shouldHandleThreadSafety() throws Exception {
        LoadingStatusProvider provider = new TestHealthyProvider();

        Thread[] threads = new Thread[10];
        LoaderStatus[] results = new LoaderStatus[10];

        for (int i = 0; i < threads.length; i++) {
            final int index = i;
            threads[i] = new Thread(() -> results[index] = provider.getLoaderStatus());
        }

        for (Thread thread : threads) {
            thread.start();
        }

        for (Thread thread : threads) {
            thread.join();
        }

        // All results should be the same and non-null
        for (LoaderStatus result : results) {
            assertNotNull(result, "Concurrent access should return non-null status");
            assertEquals(LoaderStatus.OK, result, "All concurrent calls should return same OK status");
        }
    }

    @Test
    @DisplayName("Should handle state transitions")
    void shouldHandleStateTransitions() {
        TestTransitionProvider provider = new TestTransitionProvider();

        // Initially undefined
        assertEquals(LoaderStatus.UNDEFINED, provider.getLoaderStatus(), "Provider should start in UNDEFINED state");

        // Transition to healthy
        provider.transitionToHealthy();
        assertEquals(LoaderStatus.OK, provider.getLoaderStatus(), "Provider should transition to OK state");

        // Transition to error
        provider.transitionToError();
        assertEquals(LoaderStatus.ERROR, provider.getLoaderStatus(), "Provider should transition to ERROR state");

        // Transition back to healthy
        provider.transitionToHealthy();
        assertEquals(LoaderStatus.OK, provider.getLoaderStatus(), "Provider should transition back to OK state");
    }

    @Test
    @DisplayName("Should correctly implement isLoaderStatusOK convenience method")
    void shouldCorrectlyImplementIsLoaderStatusOK() {
        // Test OK status
        LoadingStatusProvider okProvider = new TestHealthyProvider();
        assertTrue(okProvider.isLoaderStatusOK(), "Should return true for OK status");

        // Test ERROR status
        LoadingStatusProvider errorProvider = new TestErrorProvider();
        assertFalse(errorProvider.isLoaderStatusOK(), "Should return false for ERROR status");

        // Test UNDEFINED status
        LoadingStatusProvider undefinedProvider = new TestUndefinedProvider();
        assertFalse(undefinedProvider.isLoaderStatusOK(), "Should return false for UNDEFINED status");
    }

    // Test implementations for interface testing

    private static class TestHealthyProvider implements LoadingStatusProvider {
        @Override
        public LoaderStatus getLoaderStatus() {
            return LoaderStatus.OK;
        }
    }

    private static class TestErrorProvider implements LoadingStatusProvider {
        @Override
        public LoaderStatus getLoaderStatus() {
            return LoaderStatus.ERROR;
        }
    }

    private static class TestUndefinedProvider implements LoadingStatusProvider {
        @Override
        public LoaderStatus getLoaderStatus() {
            return LoaderStatus.UNDEFINED;
        }
    }

    private static class TestTransitionProvider implements LoadingStatusProvider {
        private LoaderStatus currentStatus = LoaderStatus.UNDEFINED;

        @Override
        public LoaderStatus getLoaderStatus() {
            return currentStatus;
        }

        public void transitionToHealthy() {
            this.currentStatus = LoaderStatus.OK;
        }

        public void transitionToError() {
            this.currentStatus = LoaderStatus.ERROR;
        }
    }
}
