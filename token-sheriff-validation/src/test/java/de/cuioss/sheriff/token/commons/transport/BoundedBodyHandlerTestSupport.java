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

import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Flow;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Drives an {@link HttpResponse.BodyHandler} against synthetic streamed bytes so the bounded
 * body-handler behaviour ({@link BoundedBodyHandlers}) can be asserted without a live network:
 * the body is fed in small chunks to prove the ceiling is enforced <em>during</em> streaming, and
 * cancellation of the subscription is recorded as the observable proof that an over-limit body is
 * rejected before it is fully buffered.
 */
final class BoundedBodyHandlerTestSupport {

    private BoundedBodyHandlerTestSupport() {
    }

    /**
     * Outcome of driving a body handler.
     *
     * @param body      the assembled body String, or {@code null} when the body future failed
     * @param failure   the failure that completed the body future, or {@code null} on success
     * @param cancelled whether the subscription was cancelled (streaming-abort proof)
     */
    record DriveResult(String body, Throwable failure, boolean cancelled) {

        boolean succeeded() {
            return failure == null;
        }
    }

    /**
     * Feeds {@code body} to the handler in 256-byte chunks. When {@code advertisedContentLength} is
     * non-null it is presented as the response {@code Content-Length} header (exercising the
     * pre-check path); a {@code null} value presents no such header (exercising the streaming-cap
     * path against a body that under-declares or omits its length).
     */
    static DriveResult drive(HttpResponse.BodyHandler<?> handler, byte[] body, Long advertisedContentLength) {
        HttpResponse.ResponseInfo info = responseInfo(advertisedContentLength);
        HttpResponse.BodySubscriber<?> subscriber = handler.apply(info);
        AtomicBoolean cancelled = new AtomicBoolean(false);
        subscriber.onSubscribe(new RecordingSubscription(cancelled));

        int chunkSize = 256;
        for (int offset = 0; offset < body.length; offset += chunkSize) {
            int length = Math.min(chunkSize, body.length - offset);
            subscriber.onNext(List.of(ByteBuffer.wrap(body, offset, length).asReadOnlyBuffer()));
        }
        subscriber.onComplete();

        try {
            Object result = subscriber.getBody().toCompletableFuture().join();
            return new DriveResult((String) result, null, cancelled.get());
        } catch (CompletionException e) {
            return new DriveResult(null, e.getCause() != null ? e.getCause() : e, cancelled.get());
        }
    }

    /**
     * Builds a minimal {@link HttpResponse.ResponseInfo} for a 200 response, optionally advertising
     * {@code Content-Length}. Package-visible so other tests in this package (e.g. tests asserting a
     * bounded body handler produces a subscriber for a successful response) can reuse it instead of
     * duplicating the same anonymous implementation.
     *
     * @param advertisedContentLength the {@code Content-Length} to advertise, or {@code null} for none
     */
    static HttpResponse.ResponseInfo responseInfo(Long advertisedContentLength) {
        Map<String, List<String>> headerMap = advertisedContentLength == null
                ? Map.of()
                : Map.of("Content-Length", List.of(Long.toString(advertisedContentLength)));
        HttpHeaders headers = HttpHeaders.of(headerMap, (name, value) -> true);
        return new HttpResponse.ResponseInfo() {
            @Override
            public int statusCode() {
                return 200;
            }

            @Override
            public HttpHeaders headers() {
                return headers;
            }

            @Override
            public HttpClient.Version version() {
                return HttpClient.Version.HTTP_1_1;
            }
        };
    }

    private static final class RecordingSubscription implements Flow.Subscription {

        private final AtomicBoolean cancelled;

        RecordingSubscription(AtomicBoolean cancelled) {
            this.cancelled = cancelled;
        }

        @Override
        public void request(long n) {
            // No back-pressure modelling needed: the driver feeds all chunks synchronously.
        }

        @Override
        public void cancel() {
            cancelled.set(true);
        }
    }
}
