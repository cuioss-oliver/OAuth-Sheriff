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
package de.cuioss.sheriff.token.quarkus.deployment;

import de.cuioss.sheriff.token.quarkus.config.AccessLogFilterConfigResolver;
import de.cuioss.sheriff.token.quarkus.interceptor.BearerTokenInterceptor;
import de.cuioss.sheriff.token.quarkus.logging.CustomAccessLogFilter;
import de.cuioss.sheriff.token.quarkus.mapper.ClaimMapperRegistry;
import de.cuioss.sheriff.token.quarkus.mapper.DiscoverableClaimMapper;
import de.cuioss.sheriff.token.quarkus.mapper.keycloak.KeycloakGroupsMapperBean;
import de.cuioss.sheriff.token.quarkus.mapper.keycloak.KeycloakRolesMapperBean;
import de.cuioss.sheriff.token.quarkus.metrics.JwtMetricsCollector;
import de.cuioss.sheriff.token.quarkus.producer.BearerTokenProducer;
import de.cuioss.sheriff.token.quarkus.producer.JsonWebTokenAdapter;
import de.cuioss.sheriff.token.quarkus.producer.TokenValidatorProducer;
import de.cuioss.sheriff.token.quarkus.runtime.TokenSheriffDevUIRuntimeService;
import de.cuioss.sheriff.token.quarkus.servlet.VertxServletObjectsResolver;
import de.cuioss.sheriff.token.quarkus.validation.DiscoverableTokenValidationRule;
import de.cuioss.sheriff.token.quarkus.validation.TokenValidationRuleRegistry;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.logging.LogRecord;
import de.cuioss.tools.logging.LogRecordModel;
import io.micrometer.core.instrument.MeterRegistry;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.UnremovableBeanBuildItem;
import io.quarkus.deployment.IsDevelopment;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ServiceProviderBuildItem;
import io.quarkus.devui.spi.JsonRPCProvidersBuildItem;
import io.quarkus.devui.spi.page.CardPageBuildItem;
import io.quarkus.devui.spi.page.Page;
import io.quarkus.resteasy.common.spi.ResteasyJaxrsProviderBuildItem;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.jandex.DotName;

/**
 * Processor for the Token-Sheriff Quarkus extension.
 * <p>
 * This class handles the build-time processing for the extension: registering the feature, the CDI
 * and JAX-RS wiring, the Quarkus-specific reflection registrations and the DevUI integration.
 * </p>
 * <p>
 * It does <em>not</em> declare the core library's reflection contract. {@code token-sheriff-validation}
 * ships its own GraalVM metadata under
 * {@code META-INF/native-image/de.cuioss.sheriff.token/token-sheriff-validation/}, which GraalVM
 * auto-detects from the jar — for Quarkus and non-Quarkus native builds alike. Core types therefore
 * belong in that metadata, never in this processor.
 * </p>
 */
public class TokenSheriffProcessor {

    /**
     * The feature name for the Token-Sheriff extension.
     */
    private static final String FEATURE = "token-sheriff";

    /**
     * Logger for build-time processing.
     */
    private static final CuiLogger LOGGER = new CuiLogger(TokenSheriffProcessor.class);

    /**
     * LogRecord for feature registration.
     */
    private static final LogRecord TOKEN_SHERIFF_FEATURE_REGISTERED = LogRecordModel.builder()
            .template("Token-Sheriff feature registered")
            .prefix("TokenSheriff_Q_D")
            .identifier(1)
            .build();

    /**
     * Register the Token-Sheriff feature.
     *
     * @return A {@link FeatureBuildItem} for the Token-Sheriff feature
     */
    @BuildStep
    public FeatureBuildItem feature() {
        LOGGER.info(TOKEN_SHERIFF_FEATURE_REGISTERED);
        return new FeatureBuildItem(FEATURE);
    }


    /**
     * Register the Quarkus-specific classes that need reflection.
     * <p>
     * Only types this extension owns or bridges are registered here. The core library's own
     * reflection contract ships with {@code token-sheriff-validation} under
     * {@code META-INF/native-image/de.cuioss.sheriff.token/token-sheriff-validation/} and is
     * auto-detected by GraalVM, so it must not be duplicated in this processor.
     *
     * @param reflectiveClasses producer for reflective class build items
     */
    @BuildStep
    public void registerQuarkusSpecificClassesForReflection(BuildProducer<ReflectiveClassBuildItem> reflectiveClasses) {
        // Micrometer registry for metrics
        reflectiveClasses.produce(ReflectiveClassBuildItem.builder(MeterRegistry.class)
                .methods(true)
                .fields(false)
                .constructors(true)
                .build());

        // MicroProfile JWT interface and adapter for CDI injection
        reflectiveClasses.produce(ReflectiveClassBuildItem.builder(
                        JsonWebToken.class,
                        JsonWebTokenAdapter.class)
                .methods(true)
                .fields(true)
                .constructors(true)
                .build());

        // CDI-discoverable claim mapper interface
        reflectiveClasses.produce(ReflectiveClassBuildItem.builder(DiscoverableClaimMapper.class)
                .methods(false)
                .fields(false)
                .constructors(true)
                .build());
    }

    /**
     * Register DSL-JSON service providers for native image.
     * This ensures DSL-JSON converters can be found via service loader at runtime.
     */
    @BuildStep
    public void registerDslJsonServiceProviders(BuildProducer<ServiceProviderBuildItem> serviceProvider) {
        // Register all DSL-JSON configurations from classpath
        serviceProvider.produce(ServiceProviderBuildItem.allProvidersFromClassPath("com.dslplatform.json.Configuration"));
    }


    /**
     * Register additional CDI beans for JWT validation.
     *
     * @return A {@link AdditionalBeanBuildItem} for CDI beans that need explicit registration
     */
    @BuildStep
    public AdditionalBeanBuildItem additionalBeans() {
        return AdditionalBeanBuildItem.builder()
                // Explicitly register the CDI producer classes to ensure they're discovered
                .addBeanClasses(
                        TokenValidatorProducer.class,
                        BearerTokenProducer.class,
                        VertxServletObjectsResolver.class,
                        JwtMetricsCollector.class,
                        // CDI-based claim mapper infrastructure
                        ClaimMapperRegistry.class,
                        KeycloakRolesMapperBean.class,
                        KeycloakGroupsMapperBean.class,
                        // CDI-based token validation rule infrastructure
                        TokenValidationRuleRegistry.class
                )
                // Register additional configuration producers using class references
                .addBeanClass(AccessLogFilterConfigResolver.class)
                .addBeanClass(CustomAccessLogFilter.class)
                // Register interceptor infrastructure
                .addBeanClass(BearerTokenInterceptor.class)
                .setUnremovable()
                .build();
    }

    /**
     * Register the CustomAccessLogFilter as a JAX-RS provider.
     * This is required for Quarkus extensions to properly register JAX-RS providers.
     *
     * @return A {@link ResteasyJaxrsProviderBuildItem} for the CustomAccessLogFilter
     */
    @BuildStep
    public ResteasyJaxrsProviderBuildItem registerCustomAccessLogFilter() {
        return new ResteasyJaxrsProviderBuildItem(CustomAccessLogFilter.class.getName());
    }

    /**
     * Register core JWT validation beans as unremovable to ensure they're available for injection.
     * This is critical for native image compilation where CDI discovery can be limited.
     *
     * @param unremovableBeans producer for unremovable bean build items
     */
    @BuildStep
    public void registerUnremovableBeans(BuildProducer<UnremovableBeanBuildItem> unremovableBeans) {
        // Ensure core library beans are never removed from the CDI container
        unremovableBeans.produce(UnremovableBeanBuildItem.beanTypes(
                DotName.createSimple(TokenValidator.class.getName()),
                DotName.createSimple(JwtMetricsCollector.class.getName()),
                DotName.createSimple(MeterRegistry.class.getName()),
                // Ensure user-provided DiscoverableClaimMapper implementations are discovered
                DotName.createSimple(DiscoverableClaimMapper.class.getName()),
                // Ensure user-provided DiscoverableTokenValidationRule implementations are discovered
                DotName.createSimple(DiscoverableTokenValidationRule.class.getName())
        ));
    }


    /**
     * Create DevUI card page for JWT validation monitoring and debugging.
     *
     * @return A {@link CardPageBuildItem} for the JWT DevUI card
     */
    @BuildStep(onlyIf = IsDevelopment.class)
    public CardPageBuildItem createJwtDevUICard() {
        CardPageBuildItem cardPageBuildItem = new CardPageBuildItem();

        // Status & Config page (merged view of validation status, JWKS endpoints, and configuration)
        cardPageBuildItem.addPage(Page.webComponentPageBuilder()
                .icon("font-awesome-solid:shield-halved")
                .title("Status & Config")
                .componentLink("qwc-jwt-status-config.js"));

        // Token Debugging Tools page
        cardPageBuildItem.addPage(Page.webComponentPageBuilder()
                .icon("font-awesome-solid:bug")
                .title("Token Debugger")
                .componentLink("qwc-jwt-debugger.js"));

        return cardPageBuildItem;
    }

    /**
     * Register JSON-RPC providers for DevUI runtime data access.
     *
     * @return A {@link JsonRPCProvidersBuildItem} for JWT DevUI JSON-RPC methods
     */
    @BuildStep(onlyIf = IsDevelopment.class)
    public JsonRPCProvidersBuildItem createJwtDevUIJsonRPCService() {
        return new JsonRPCProvidersBuildItem("TokenSheriffDevUI", TokenSheriffDevUIRuntimeService.class);
    }

}
