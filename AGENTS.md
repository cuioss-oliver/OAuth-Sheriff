# Token-Sheriff - AI Agent Guidance

Token-Sheriff is a high-performance OAuth 2.0 and OpenID Connect token validation library for Java/Quarkus applications. This document guides AI coding agents when working with the codebase.

## Dev Environment Tips

### Build System
- **Build tool**: Maven 3.9.6 (via wrapper: `./mvnw`)
- **Java version**: Java 21 (LTS)
- **Primary framework**: Quarkus 3.34.0

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
- **Java features**: Use modern Java 21 features (records, sealed classes, pattern matching, text blocks)
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
- **Coverage requirement**: Minimum 80% line and branch coverage
- **Coverage check**: `./mvnw clean verify -Pcoverage`

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

**Handling strategy**:

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

**Never commit code with markers present.**

## Pre-1.0 Project Rules

This project is PRE-1.0 (current version: 1.0.0-SNAPSHOT). Therefore:
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
