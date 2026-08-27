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
package de.cuioss.benchmarking.common.http;

import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class HttpClientFactoryTest {

    @Test
    void getInsecureClient() {
        HttpClient client1 = HttpClientFactory.getInsecureClient();
        HttpClient client2 = HttpClientFactory.getInsecureClient();

        assertNotNull(client1);
        assertNotNull(client2);
        // Should return cached instance
        assertSame(client1, client2);

        // Verify HTTP version is configured
        assertNotNull(client1.version());

        // Verify connect timeout is configured (5 seconds)
        assertTrue(client1.connectTimeout().isPresent());
        assertEquals(Duration.ofSeconds(5), client1.connectTimeout().get());
    }

    @Test
    void concurrentAccess() throws Exception {
        // Test thread safety of factory
        Thread[] threads = new Thread[10];
        HttpClient[] clients = new HttpClient[10];

        for (int i = 0; i < threads.length; i++) {
            final int index = i;
            threads[i] = new Thread(() -> clients[index] = HttpClientFactory.getInsecureClient());
            threads[i].start();
        }

        for (Thread thread : threads) {
            thread.join();
        }

        // All threads should get the same cached instance
        HttpClient expected = clients[0];
        for (HttpClient client : clients) {
            assertSame(expected, client);
        }
    }

    @Test
    void clientConfiguration() {
        HttpClient client = HttpClientFactory.getInsecureClient();

        assertNotNull(client);

        // Verify SSL configuration is present
        assertNotNull(client.sslContext());

        // Verify executor is configured
        assertNotNull(client.executor());

        // Verify version is set
        assertNotNull(client.version());
    }
}