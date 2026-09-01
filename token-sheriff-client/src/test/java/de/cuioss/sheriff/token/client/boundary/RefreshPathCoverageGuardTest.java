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

import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaModifier;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Guards the hand-maintained {@code <includes>} list of the {@code refresh-path-coverage-check}
 * JaCoCo execution in {@code token-sheriff-client/pom.xml}.
 * <p>
 * The gate that list drives is <em>fail-silent</em>: JaCoCo's {@code BundleChecker} never evaluates a
 * limit for an include that matches no class, and {@code jacoco:check} then reports
 * "All coverage checks have been met." An edit to the list can therefore disable the gate while the
 * build stays green. This guard converts both drift directions into a build failure:
 * <ul>
 *   <li><strong>Leg (a) — non-vacuity.</strong> Every include entry resolves to a production type
 *       that carries executable code, so no entry can be inert.</li>
 *   <li><strong>Leg (b) — drift.</strong> Every production class that looks like a refresh-path
 *       class — it resides in one of the packages the list already names and its first camel-case
 *       word equals one the list already uses — is present in the list.</li>
 * </ul>
 * Leg (b)'s expected set is derived from the list's own shape, so it detects a sibling added beside
 * an already-guarded class. A refresh-path class named outside that shape <em>and</em> placed in a
 * package the list does not name is the accepted residual gap (see ADR-0003); leg (a) is unaffected
 * by it.
 */
@DisplayName("Refresh-path coverage gate: the include list is neither inert nor drifted")
class RefreshPathCoverageGuardTest {

    private static final String EXECUTION_ID = "refresh-path-coverage-check";
    private static final String PRODUCTION_ROOT_PACKAGE = "de.cuioss.sheriff.token.client";

    /** The {@code <include>} entries of the guarded execution, in pom order. */
    private static List<String> includeEntries;

    /** Every top-level production class, keyed by its dotted qualified name (JaCoCo's own form). */
    private static Map<String, JavaClass> productionTypes;

    @BeforeAll
    static void importPomAndProductionClasses() throws Exception {
        includeEntries = readIncludeEntries(moduleBaseDir().resolve("pom.xml"));
        JavaClasses imported = new ClassFileImporter()
                .withImportOption(new ImportOption.DoNotIncludeTests())
                .importPackages(PRODUCTION_ROOT_PACKAGE);
        productionTypes = new LinkedHashMap<>();
        for (JavaClass type : imported) {
            if (isTopLevelProductionType(type)) {
                productionTypes.put(dottedQualifiedName(type), type);
            }
        }
    }

    @Test
    @DisplayName("the guarded execution is found and contributes at least one include entry")
    void shouldExtractANonEmptyIncludeList() {
        assertFalse(includeEntries.isEmpty(),
                "no <include> entry was extracted for execution id '" + EXECUTION_ID + "' in "
                        + moduleBaseDir().resolve("pom.xml")
                        + " — a renamed or removed execution id would make this whole guard vacuous");
        assertFalse(productionTypes.isEmpty(),
                "no production classes were imported from " + PRODUCTION_ROOT_PACKAGE
                        + " — the guard cannot judge the include list against an empty universe");
    }

    @Test
    @DisplayName("leg (a): every include entry binds to a type that carries executable code")
    void shouldRejectAnInertIncludeEntry() {
        List<String> unresolved = new ArrayList<>();
        List<String> withoutExecutableCode = new ArrayList<>();
        for (String entry : includeEntries) {
            JavaClass type = productionTypes.get(entry);
            if (type == null) {
                unresolved.add(entry);
            } else if (!carriesExecutableCode(type)) {
                withoutExecutableCode.add(entry);
            }
        }
        assertTrue(unresolved.isEmpty(),
                "include entries of execution '" + EXECUTION_ID + "' that match no production class: "
                        + unresolved + ". JaCoCo evaluates no limit for such an entry and still reports"
                        + " \"All coverage checks have been met\", so the gate would silently stop"
                        + " covering it. Entries must be dotted FQCNs (Outer.Inner, never Outer$Inner).");
        assertTrue(withoutExecutableCode.isEmpty(),
                "include entries of execution '" + EXECUTION_ID + "' that carry no executable code: "
                        + withoutExecutableCode + ". A type with no constructor, no static initializer"
                        + " and no non-abstract method has zero JaCoCo INSTRUCTION and BRANCH counters,"
                        + " so a COVEREDRATIO limit can never bind it — the entry looks like coverage"
                        + " while measuring nothing.");
    }

    @Test
    @DisplayName("leg (b): no refresh-path sibling is missing from the include list")
    void shouldRejectARefreshPathClassMissingFromTheIncludeList() {
        Set<String> guardedPackages = new TreeSet<>();
        Set<String> guardedWords = new TreeSet<>();
        for (String entry : includeEntries) {
            JavaClass type = productionTypes.get(entry);
            if (type != null) {
                guardedPackages.add(type.getPackageName());
                guardedWords.add(firstCamelWord(type.getSimpleName()));
            }
        }

        Set<String> listed = new LinkedHashSet<>(includeEntries);
        List<String> missing = new ArrayList<>();
        for (Map.Entry<String, JavaClass> candidate : productionTypes.entrySet()) {
            JavaClass type = candidate.getValue();
            if (guardedPackages.contains(type.getPackageName())
                    && guardedWords.contains(firstCamelWord(type.getSimpleName()))
                    && carriesExecutableCode(type)
                    && !listed.contains(candidate.getKey())) {
                missing.add(candidate.getKey());
            }
        }

        assertTrue(missing.isEmpty(),
                "production classes on the refresh path that are absent from the <includes> list of"
                        + " execution '" + EXECUTION_ID + "': " + missing
                        + ". They reside in a guarded package " + guardedPackages
                        + " and their first camel-case word is one of " + guardedWords
                        + ", so they are siblings of already-guarded classes and must be added to the"
                        + " list — or the gate silently stops covering them.");
    }

    /**
     * @return the {@code <include>} texts of the {@link #EXECUTION_ID} execution, in document order
     */
    private static List<String> readIncludeEntries(Path pom) throws Exception {
        assertTrue(Files.isRegularFile(pom), "module pom not found at " + pom);
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);

        Document document = factory.newDocumentBuilder().parse(pom.toFile());
        NodeList executions = document.getElementsByTagName("execution");
        for (int i = 0; i < executions.getLength(); i++) {
            Element execution = (Element) executions.item(i);
            if (EXECUTION_ID.equals(firstChildText(execution, "id"))) {
                return textsOf(execution.getElementsByTagName("include"));
            }
        }
        return List.of();
    }

    private static String firstChildText(Element parent, String tagName) {
        NodeList matches = parent.getElementsByTagName(tagName);
        return matches.getLength() == 0 ? null : matches.item(0).getTextContent().trim();
    }

    private static List<String> textsOf(NodeList nodes) {
        List<String> texts = new ArrayList<>(nodes.getLength());
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            texts.add(node.getTextContent().trim());
        }
        return texts;
    }

    /**
     * @return the module base directory; Surefire exports it as {@code basedir}, and a plain JVM run
     *         falls back to the working directory
     */
    private static Path moduleBaseDir() {
        String basedir = System.getProperty("basedir");
        if (basedir == null || basedir.isBlank()) {
            basedir = System.getProperty("user.dir");
        }
        if (basedir == null || basedir.isBlank()) {
            return fail("neither the 'basedir' nor the 'user.dir' system property is set,"
                    + " so the module pom cannot be located");
        }
        return Paths.get(basedir).toAbsolutePath().normalize();
    }

    /**
     * Excludes nested and anonymous types (JaCoCo counts them under their own dotted names, but the
     * list is maintained at top-level granularity) as well as {@code package-info} synthetics.
     */
    private static boolean isTopLevelProductionType(JavaClass type) {
        String binaryName = type.getName();
        return !binaryName.contains("$")
                && !binaryName.endsWith(".package-info")
                && !binaryName.endsWith(".module-info")
                && binaryName.startsWith(PRODUCTION_ROOT_PACKAGE + ".");
    }

    /** @return the name JaCoCo's {@code JavaNames.getQualifiedClassName} would render for the type */
    private static String dottedQualifiedName(JavaClass type) {
        return type.getName().replace('$', '.');
    }

    /**
     * A type carries executable code when JaCoCo can measure at least one counter for it: any
     * constructor, a static initializer, or at least one non-abstract method.
     */
    private static boolean carriesExecutableCode(JavaClass type) {
        if (!type.getConstructors().isEmpty()) {
            return true;
        }
        Optional<?> staticInitializer = type.getStaticInitializer();
        if (staticInitializer.isPresent()) {
            return true;
        }
        return type.getMethods().stream()
                .anyMatch(method -> !method.getModifiers().contains(JavaModifier.ABSTRACT));
    }

    /**
     * @return the leading camel-case word of a simple name — {@code InMemoryTokenStore} yields
     *         {@code In}, {@code RotationResult} yields {@code Rotation}. Word equality, not prefix
     *         matching, is what keeps {@code IssValidator} ({@code Iss}) out of the {@code In} bucket
     */
    private static String firstCamelWord(String simpleName) {
        int end = 1;
        while (end < simpleName.length() && !Character.isUpperCase(simpleName.charAt(end))) {
            end++;
        }
        return simpleName.substring(0, end);
    }
}
