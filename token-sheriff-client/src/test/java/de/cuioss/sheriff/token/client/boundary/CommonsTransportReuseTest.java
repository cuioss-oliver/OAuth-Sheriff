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
package de.cuioss.sheriff.token.client.boundary;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import java.net.http.HttpClient;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Enforces that every outbound path in the client engine reuses the commons-blessed cui-http
 * {@code HttpHandler} transport and constructs no bespoke JDK HTTP client of its own
 * ({@code CLIENT-20} / {@code CLIENT-21}) — deliverable 10.
 * <p>
 * The engine composes {@code de.cuioss.http.client.handler.HttpHandler} for every back-channel call
 * (token / userinfo / revocation / PAR), obtaining its {@link HttpClient} from
 * {@code HttpHandler.createHttpClient()}. It never calls {@link HttpClient#newBuilder()} or
 * {@link HttpClient#newHttpClient()} directly, so all TLS/SSRF posture is inherited from the commons
 * transport rather than re-implemented. The no-bespoke-HTTP-library rule (OkHttp / Apache HttpClient)
 * lives in {@link ClientArchitectureTest}.
 */
@AnalyzeClasses(packages = "de.cuioss.sheriff.token.client", importOptions = ImportOption.DoNotIncludeTests.class)
class CommonsTransportReuseTest {

    @ArchTest
    static final ArchRule outbound_http_never_builds_a_bespoke_client = noClasses()
            .that().resideInAPackage("de.cuioss.sheriff.token.client..")
            .should().callMethod(HttpClient.class, "newBuilder")
            .orShould().callMethod(HttpClient.class, "newHttpClient")
            .because("outbound HTTP must be obtained from the commons HttpHandler.createHttpClient(),"
                    + " never a bespoke JDK HttpClient (CLIENT-20/CLIENT-21)");
}
