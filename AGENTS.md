# Token-Sheriff - AI Agent Guidance

Token-Sheriff is a high-performance OAuth 2.0 and OpenID Connect token validation library for Java/Quarkus applications. This document guides AI coding agents when working with the codebase.

## Dev Environment Tips

### Build System
- **Build tool**: Maven, via the wrapper (`./mvnw`) — never a locally installed `mvn`
- **Java version**: as declared by `maven.compiler.release` in the root `pom.xml`
- **Primary framework**: Quarkus, pinned by `version.quarkus` in the root `pom.xml`

Deliberately no version numbers here: this file is not a source of truth for them and
silently goes stale. Read the root `pom.xml` and `.mvn/wrapper/maven-wrapper.properties`
when a concrete version matters.

### Build-Configuration Verification

This project inherits its build configuration from `cui-java-parent`, so the `pom.xml` files in this
repository are not the effective configuration. A mechanism can be fully configured for this build
and appear nowhere in this tree. The authoritative resolution command is:

```bash
./mvnw help:effective-pom
```

- **Before agreeing that a mechanism is missing or unconfigured**, read the parent POM chain and the
  effective POM. A repo-scoped search alone proves nothing about inherited configuration: absence
  from this tree is not absence from the build.
- **Before adding a `<repositories>` or `<pluginRepositories>` declaration** — or any element Maven
  merges by id — walk the parent chain to its root and read the effective POM first. Maven merges
  same-id entries by replacement, not addition, so a local declaration displaces the inherited one
  instead of joining it. Never reuse a super-POM reserved id such as `central` for an additive
  channel.
- **Before adopting an unreleased snapshot version-property pin**, enumerate every artifact that
  property governs — the main jar and every classifier — and verify each one's actual contents from
  the remote repository rather than a possibly-warm `~/.m2`. Compare class counts against the last
  known-good release.

### Project Structure
Multi-module Maven project:
- `token-sheriff-validation/` - The core Token-Sheriff validation library
- `token-sheriff-quarkus-parent/` - Quarkus framework integration
- `benchmarking/` - Performance benchmarking modules
- `bom/` - Bill of Materials for dependency management

### Essential Build Commands
```bash
# Development build
./mvnw clean verify

# Full build with all tests
./mvnw clean install

# Build single module
./mvnw clean install -pl <module-name>

# Run single test
./mvnw test -Dtest=ClassName#methodName
```

### Code Standards
- **Indentation**: 4 spaces (configured in `.editorconfig`)
- **Line endings**: Unix-style (LF)
- **Encoding**: UTF-8
- **Java features**: Use the modern Java features the configured release level allows (records, sealed classes, pattern matching, text blocks)
- **Lombok**: Use `@Builder`, `@Value`, `@NonNull`, `@ToString`, `@EqualsAndHashCode` appropriately

### Logging Standards
This project uses CUI logging standards with Java Util Logging:
- Logger: `de.cuioss.tools.logging.CuiLogger` (private static final LOGGER)
- **Format specifier**: Always use `%s` for parameter substitution (NEVER `{}`, `%.2f`, `%d`)
- **Structured logging**: Use `de.cuioss.tools.logging.LogRecord` for INFO/WARN/ERROR messages
- **LogRecord ranges**: INFO (001-099), WARN (100-199), ERROR (200-299)
- **Documentation**: All log messages must be documented in `doc/LogMessages.adoc`
- **Exception logging**: Exception parameter always comes first

## Testing Instructions

### Testing Framework
- **Primary**: JUnit 5 (Jupiter)
- **Test patterns**: AAA pattern (Arrange-Act-Assert)
- **Coverage requirement**: two independent rules apply, at different granularities and on different lanes. The rule inherited from `cui-java-parent` is `element=BUNDLE` and gates **both** counters — `INSTRUCTION COVEREDRATIO >= 0.80` **and** `BRANCH COVEREDRATIO >= 0.80` — so it counts instructions and branches, never *lines*. It is declared inside the opt-in `coverage` profile, so a plain `./mvnw clean verify` never applies it. In `token-sheriff-client` the five refresh-path classes (`flow.RefreshFlow`, `token.RotationResult`, `token.RefreshTokenFamily`, `lifecycle.RefreshScheduler`, `lifecycle.InMemoryTokenStore`) carry a stricter per-class floor — `BRANCH >= 0.80` **and** `INSTRUCTION >= 0.90` — enforced on the **default** lane, so a plain `./mvnw clean verify` fails on a refresh-path coverage regression. See `doc/client/specification/test-strategy.adoc` § Coverage gates.
- **Coverage check**: `./mvnw clean verify -Pcoverage` for the module-wide bundle rule; the refresh-path per-class gate needs no profile flag and already runs under `./mvnw clean verify`.
- **Always measure with `clean`**: the JaCoCo agent writes `jacoco.exec` with its default `append=true`, so a coverage run without `clean` silently merges earlier runs and reports stale, inflated numbers.

### CUI Test Generator
This project has CUI Test Generator dependencies available for test data generation:
- Provides type-safe, consistent test data generation
- Use `@CsvSource` for simple data
- Use `@ValueSource` for single parameter variations
- Use `@MethodSource` for complex parameterization

### Parameterized Tests
Mandatory for 3+ similar test variants. Common annotations:
1. `@CsvSource`
2. `@ValueSource`
3. `@MethodSource`

### Test Execution Commands
```bash
# Run all tests
./mvnw test

# Run integration tests
./mvnw clean verify -Pintegration-tests -pl token-sheriff-quarkus-parent/token-sheriff-quarkus-integration-tests -am

# Run micro-benchmarks
./mvnw clean verify -pl benchmarking/benchmark-core -Pbenchmark

# Run integration benchmarks
./mvnw clean verify -Pbenchmark -pl benchmarking/benchmark-integration-wrk
```

### Pre-Commit Validation

**CRITICAL**: Execute this sequence before ANY commit:

1. **Quality verification**:
   ```bash
   ./mvnw -Ppre-commit clean verify
   ```
   - Fix ALL errors and warnings (mandatory)
   - Address OpenRewrite markers (see section below)

2. **Final verification**:
   ```bash
   ./mvnw clean install
   ```
   - Must complete without errors or warnings
   - All tests must pass

3. **Integration tests**:
   ```bash
   ./mvnw clean verify -Pintegration-tests -pl token-sheriff-quarkus-parent/token-sheriff-quarkus-integration-tests -am
   ```

Tasks are complete ONLY after all three steps succeed.

### OpenRewrite Markers - Critical Understanding

Pre-commit builds run OpenRewrite recipes that add markers to flag violations.

**Marker pattern**: `/*~~(TODO: INFO needs LogRecord)~~>*/` or `/*~~(TODO: [message])~~>*/`

**What markers indicate**:
Markers indicate ACTUAL BUGS:
- Placeholder/parameter count mismatches: `"value: %s"` with 0 parameters
- Wrong format specifiers: Using `%.2f`, `{:.2f}`, `{}`, `%d` instead of `%s`
- Missing LogRecord definitions for production INFO/WARN/ERROR logs
- Generic Exception usage instead of specific types
- RuntimeException catches that should be specific exceptions

#### Rewrite OUTPUT vs rewrite REQUEST-TO-ACT

A rewrite run produces two categorically different things, and conflating them is how markers end
up committed:

- A rewrite **output** is a transformation the recipe already applied — formatted whitespace,
  ordered imports, a removed unused import. It is finished work, and it is committed as-is.
- A rewrite **request-to-act** is an injected `/*~~(TODO: … Suppress: …)~~>*/` marker. The recipe
  could not fix the code itself, so it is asking a human to act. It is an open work item, never a
  result. Committing it verbatim ships the request instead of the response.

**Worked example.** Four markers were once committed to this repository verbatim — three
`InvalidExceptionUsageRecipe` markers in `token-sheriff-client` and one
`CuiLogRecordPatternRecipe` marker in `BearerTokenProducer`. Each was a request the author left
unanswered. Reading the whole rewritten tree as "the tool's result" is the mistake: the formatting
was a result, the markers were not.

Acting on a request-to-act does not always mean changing the flagged code — sometimes the correct
answer is that the recipe is wrong, and the act is to record that fact in the sanctioned
suppression form (see below).

**Never commit code with markers present.**

#### Handling strategy

Production code violations:
- Fix the actual bug (add missing placeholders, change format to %s)
- Create LogRecord constant for INFO/WARN/ERROR messages
- Replace generic Exception with specific types (IOException, IllegalStateException, etc.)
- Never catch or throw RuntimeException - use specific exception types

Test code violations:
- For diagnostic/performance logging: Add suppression comment at class level:
  ```java
  // cui-rewrite:disable CuiLogRecordPatternRecipe
  // This is a test/utility class that outputs diagnostic information for analysis
  ```
- For exception handling: Replace RuntimeException with AssertionError in test failures
- For format bugs: Fix placeholder mismatches even in tests (change to %s)

#### `InvalidExceptionUsageRecipe`: narrow the catch, do not suppress

Suppression is **not** a valid strategy for `InvalidExceptionUsageRecipe`. The standing remedy is
to narrow the caught exception type against the **throwers the callee actually declares** — except
where the caught failures come from an **open set of SPI implementations that declare no
`throws`**, in which case there is nothing to narrow against and suppression is legitimate.

That carve-out is the rule's single limit, and it is part of the rule rather than a footnote: the
tree already holds its one sanctioned instance at
`token-sheriff-validation/src/main/java/de/cuioss/sheriff/token/validation/pipeline/TokenBuilder.java:143`,
where custom SPI claim mappers are translated into `TokenValidationException`. Everywhere else,
narrow.

Two practical notes from the sites already narrowed:

- Narrow against the **declared** throwers, not against what a test double happens to throw. When a
  test double throws a type the API does not declare, the double is what is wrong.
- Where a `catch` was load-bearing for an invariant — completing a future, releasing a latch —
  make the `finally` block satisfy that invariant unconditionally **before** narrowing the catch.
  Narrowing first opens a window in which an unnamed throwable escapes with the invariant broken.

#### `CuiLogRecordPatternRecipe`: demonstrated false positives are suppressible in production code

The class-level suppression form above is sanctioned in **production** code too, not only in test
and utility classes — but only for a *demonstrated* recipe mis-fire on a call that is already
correct, and only when the suppression is accompanied by a comment recording the specific mis-fire.
The demonstration is required: this sanction is for proven false positives, never for silencing an
inconvenient finding.

**Worked instance.** `BearerTokenProducer` calls
`LOGGER.warn(e, BEARER_TOKEN_VALIDATION_FAILED, e.getMessage(), e.getEventType())`. The recipe
mis-fires on the `warn(Throwable, LogRecord, Object...)` overload, mistaking the leading
`Throwable` for the format argument; the `LogRecord` template carries exactly two matching `%s`
placeholders and the call is correct. The remedy was a class-level
`// cui-rewrite:disable CuiLogRecordPatternRecipe` plus that explanation.

**Corollary: never contort a correct logging call to satisfy a buggy recipe.**

#### `CuiLoggerStandardsRecipe` rewriting `%n` to `%s` is semantic damage

`CuiLoggerStandardsRecipe` misreads the argument-less `%n` line-separator conversion as a value
placeholder and rewrites it to `%s`, adding a format placeholder with no matching argument and
corrupting the format string. This is semantic damage, not cosmetic churn.

The sanctioned remedy is a `// cui-rewrite:disable CuiLoggerStandardsRecipe` at the affected site
with a comment citing the upstream defect `cuioss/cui-open-rewrite#135` — the form both live sites
already use (`JfrVarianceAnalyzer.printSummary()` and `TokenValidatorMetricsTest`). A format string
carrying `%n` must **never** be "fixed" by accepting the rewrite.

#### What is known about suppression placement, and what is not

The failure that produced the narrow-not-suppress rule was observed for a `// cui-rewrite:disable`
comment placed at the **closing-brace / `catch`** position, and only there. Class-level and
method-level suppression of `InvalidExceptionUsageRecipe` were never tested, so they are
**untested, not refuted**. Treat that as a known gap for a future investigation, not as a finding.

Adjacent evidence exists but must not be over-read: this tree relies on **method-level**
suppression of a *different* recipe (`CuiLoggerStandardsRecipe`, at the two `%n` sites), and a
`rewrite:dryRun` against the clean tree confirmed those suppressions do take effect at that
placement. That result speaks to the **placement mechanism** only. It says nothing about whether
`InvalidExceptionUsageRecipe` honours the same placements.

#### The gate now fails loud

`-Ppre-commit` no longer exits `0` after rewriting your files. Two non-mutating post-conditions run
in the `verify` phase, after the mutating executions and in the same reactor pass:
`license:check` (`assert-license-headers-unchanged`) and `rewrite:dryRun` with
`failOnDryRunResults=true` (`assert-no-rewrite-changes`). If the gate would still change a file,
the build fails and names it.

So a green `-Ppre-commit` run is now a genuine clean-tree signal, and manually grepping for markers
afterwards is a second line of defence rather than the only one. A red assertion is reporting a
real mutation: fix the source, suppress at the site with a recorded rationale, or — only when
neither is possible — add an `<exclusions>` entry to the local `pre-commit` profile in the root
`pom.xml`. Never relax the assertions, and never redeclare `activeRecipes` locally: the parent's
recipe list is the single source of truth.

## Pre-1.0 Project Rules

This project is PRE-1.0 (see the root `pom.xml` for the current version). Therefore:
- **Never deprecate code** - Remove it directly if not needed
- **Never add transitional comments** like "TODO: Remove in v2.0"
- **Never enforce backward compatibility** - Make breaking changes freely
- **Never add @Deprecated annotations** - Delete unnecessary code immediately
- **Clean APIs aggressively** - Remove unused methods, classes, and patterns
- **Focus on final API design** - Design for post-1.0 stability

## Custom Commands

This project includes custom commands for common workflows:

### verifyCuiLoggingGuidelines
Comprehensive logging standards audit:
1. Analyze CUI logging standards from `/Users/oliver/git/cui-llm-rules/standards/logging`
2. Scan for logging violations in token-sheriff-validation module
3. Check LogRecord compliance
4. Validate documentation in `doc/LogMessages.adoc`
5. Run logging-related tests
6. Generate compliance report

### fixOpenRewriteMarkers <module-path>
Fix all OpenRewrite TODO markers in a module:
1. Locate all markers with grep
2. Analyze and fix each marker (production vs test code)
3. Remove markers after fixing
4. Verify fixes with pre-commit build
5. Final validation with full test suite

### verifyAndCommit <module-name>
Execute comprehensive quality verification and commit workflow for a specific module:
1. Quality verification build (pre-commit profile)
2. Final verification build (full integration)
3. Error resolution loop
4. Artifact cleanup verification
5. Git commit

## Skills

The project includes custom skills in `.claude/skills/`:

- `run-benchmark-suite` - Run full benchmark suite with ablation sweep, connection sweep, JFR profiling, and doc updates

## Documentation Standards

- **Format**: AsciiDoc with `.adoc` extension
- **Key documents**:
  - `README.adoc` - Project overview
  - `doc/README.adoc` - Documentation hub
  - `doc/validation/requirements.adoc` - Functional requirements
  - `doc/validation/architecture.adoc` - Architecture reference
  - `doc/LogMessages.adoc` - Logging reference
- **Cross-references**: Use `xref:` syntax (not `<<>>`)
- **Blank lines**: Required before all lists
- **Header**: Include TOC and section numbering
- **Source highlighting**: Use `:source-highlighter: highlight.js`

### Javadoc Standards
- Every public and protected class/interface must be documented
- Include clear purpose statement in class documentation
- Document all public methods with parameters, returns, and exceptions
- Include `@since` tag with version information
- Document thread-safety considerations
- Include usage examples for complex classes and methods
- Every package must have package-info.java
- Use `{@link}` for references to classes, methods, and fields

## CDI and Quarkus Standards

- Use constructor injection (mandatory over field injection)
- Single constructor rule: No `@Inject` needed for single constructors
- Use `final` fields for injected dependencies
- Use `@ApplicationScoped` for stateless services
- Use `@QuarkusTest` for CDI context testing
- Use `@QuarkusIntegrationTest` for packaged app testing
- HTTPS required for all integration tests

## General Process Rules

1. **Use `.plan/temp/` for ALL temporary files** - Covered by `Write(.plan/**)` permission (avoids permission prompts)
2. **If in doubt, ask the user** - Never make assumptions
3. **Always research topics** - Use available tools (WebSearch, WebFetch, etc.) to find recent best practices
4. **Never guess or be creative** - If you cannot find best practices, ask the user
5. **Do not proliferate documents** - Always use context-relevant documents, never create without user approval
6. **Never add dependencies without approval** - Always ask before adding any dependency

## Important Files

Key reference files for development:
- `doc/LogMessages.adoc` - Complete logging reference
- `doc/README.adoc` - Documentation hub
- `doc/validation/requirements.adoc` - Functional requirements
- `doc/validation/architecture.adoc` - Architecture reference
- `.editorconfig` - Code formatting configuration
- `lombok.config` - Lombok configuration
