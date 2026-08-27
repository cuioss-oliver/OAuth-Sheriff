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

import de.cuioss.tools.logging.CuiLogger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.http.HttpClient;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;

import static de.cuioss.benchmarking.common.util.BenchmarkingLogMessages.INFO.*;

/**
 * Factory for creating Java HttpClient instances for benchmarking.
 * Uses singleton pattern for efficient resource usage.
 * <p>
 * <strong>Warning:</strong> The insecure client disables SSL certificate verification
 * and must only be used in benchmarking or testing contexts, never in production code.
 * </p>
 */
public class HttpClientFactory {

    private HttpClientFactory() {
        // Utility class
    }

    private static final CuiLogger LOGGER = new CuiLogger(HttpClientFactory.class);

    private static final int CONNECT_TIMEOUT_SECONDS = 5;

    /**
     * System property to configure HTTP protocol version.
     * Values: "http2" (default), "http1" (HTTP/1.1 only)
     * Set -Dbenchmark.http.protocol=http1 to force HTTP/1.1
     */
    private static final String HTTP_PROTOCOL_PROPERTY = "benchmark.http.protocol";
    private static final String DEFAULT_HTTP_PROTOCOL = "http2";

    private static final HttpClient CLIENT = createClient();

    public static HttpClient getInsecureClient() {
        return CLIENT;
    }

    @SuppressWarnings("java:S4830") // ok for testing purposes
    private static HttpClient createClient() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(X509Certificate[] chain, String authType) {
                            // Accept all client certificates for benchmark testing
                        }

                        @Override
                        public void checkServerTrusted(X509Certificate[] chain, String authType) {
                            // Accept all server certificates for benchmark testing with self-signed certs
                        }

                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }
                    }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());

            HttpClient.Version version = getHttpVersion();

            HttpClient client = HttpClient.newBuilder()
                    .version(version)
                    .connectTimeout(Duration.ofSeconds(CONNECT_TIMEOUT_SECONDS))
                    .sslContext(sslContext)
                    .build();

            LOGGER.info(HTTP_CLIENT_CREATED, version, CONNECT_TIMEOUT_SECONDS);
            return client;

        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IllegalStateException("Failed to create Java HttpClient", e);
        }
    }

    /**
     * Determines which HTTP protocol version to use based on system property configuration.
     * @return HTTP version to use (HTTP/2 by default, HTTP/1.1 if configured)
     */
    private static HttpClient.Version getHttpVersion() {
        String protocol = System.getProperty(HTTP_PROTOCOL_PROPERTY, DEFAULT_HTTP_PROTOCOL).toLowerCase();

        return switch (protocol) {
            case "http1" -> {
                LOGGER.info(USING_HTTP_1_1, HTTP_PROTOCOL_PROPERTY);
                yield HttpClient.Version.HTTP_1_1;
            }
            default -> {
                LOGGER.info(USING_HTTP_2, HTTP_PROTOCOL_PROPERTY);
                yield HttpClient.Version.HTTP_2;
            }
        };
    }
}