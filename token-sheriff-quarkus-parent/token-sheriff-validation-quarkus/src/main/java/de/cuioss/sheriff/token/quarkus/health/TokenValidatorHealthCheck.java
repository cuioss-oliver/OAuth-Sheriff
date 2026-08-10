/*
 * Copyright © 2022 CUI-OpenSource-Software (info@cuioss.de)
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
package de.cuioss.sheriff.token.quarkus.health;

import de.cuioss.sheriff.token.quarkus.observability.ObservedValidatorResolver;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Liveness;

/**
 * Health check for JWT validation configuration.
 * <p>
 * This class implements the SmallRye Health check interface to provide
 * liveness status for the JWT validation component. It consults
 * {@link ObservedValidatorResolver} to report on the validator actually in use, which may be an
 * externally-produced one rather than the extension's own.
 * </p>
 * <p>
 * Liveness is always {@code UP}: an unconfigured optional extension is not a dead application. The
 * {@code status} data key carries the real state.
 * </p>
 *
 * @since 1.0
 */
@ApplicationScoped
@Liveness
public class TokenValidatorHealthCheck implements HealthCheck {

    private static final String HEALTHCHECK_NAME = "jwt-validator";
    private static final String STATUS_EXTERNAL_VALIDATOR = "observing external validator";
    private static final String STATUS_NOT_CONFIGURED = "not configured";
    private static final String STATUS_CONFIGURED = "configured";

    private final ObservedValidatorResolver resolver;

    @Inject
    public TokenValidatorHealthCheck(ObservedValidatorResolver resolver) {
        this.resolver = resolver;
    }

    @Override
    public HealthCheckResponse call() {
        return HealthCheckResponse.named(HEALTHCHECK_NAME)
                .up()
                .withData("issuerCount", resolver.observedIssuerConfigs().size())
                .withData("status", statusFor(resolver.outcome()))
                .build();
    }

    private static String statusFor(ObservedValidatorResolver.Outcome outcome) {
        return switch (outcome) {
            case PROPERTY_CONFIGURED -> STATUS_CONFIGURED;
            case EXTERNAL_VALIDATOR -> STATUS_EXTERNAL_VALIDATOR;
            case NOT_CONFIGURED -> STATUS_NOT_CONFIGURED;
        };
    }
}
