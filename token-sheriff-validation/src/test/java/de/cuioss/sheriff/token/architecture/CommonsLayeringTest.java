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
package de.cuioss.sheriff.token.architecture;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.library.dependencies.SlicesRuleDefinition.slices;

/**
 * Enforces the {@code commons} / {@code validation} layering boundary described in
 * {@code doc/commons/architecture.adoc} (Plan 03).
 * <p>
 * The {@code commons} base layer ({@code transport} / {@code error} / {@code events} /
 * {@code metrics}) may depend on the JDK, {@code cui-http} and {@code cui-tooling} — but
 * <strong>never</strong> on the {@code validation} packages. {@code validation} may depend on
 * {@code commons} (the allowed direction). These rules give the same guarantee a Maven module
 * boundary would, with one fewer artifact.
 */
@AnalyzeClasses(packages = "de.cuioss.sheriff.token", importOptions = ImportOption.DoNotIncludeTests.class)
class CommonsLayeringTest {

    @ArchTest
    static final ArchRule commons_must_not_depend_on_validation = noClasses()
            .that().resideInAPackage("..commons..")
            .should().dependOnClassesThat().resideInAPackage("..validation..")
            .because("the commons base layer must not depend 'up' on the validation packages "
                    + "(doc/commons/architecture.adoc)");

    @ArchTest
    static final ArchRule commons_slices_are_free_of_cycles = slices()
            .matching("de.cuioss.sheriff.token.commons.(*)..")
            .should().beFreeOfCycles();
}
