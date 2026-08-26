---
name: release
description: Cut a Token-Sheriff release — bump .github/project.yml version, open and merge the release PR, wait for the automated Release workflow, then reformat the generated GitHub release notes
user-invocable: true
allowed-tools: Bash, Read, Edit, AskUserQuestion
---

# Release Skill

Cuts a new Token-Sheriff release end-to-end: determine the version, open the version-bump PR
that triggers the release, merge it, wait for the automated Release workflow, verify the
release landed, and reformat the auto-generated GitHub release notes.

The GitHub repository is **`cuioss/TokenSheriff`** (the local working-directory name is
`OAuthSheriff`, pre-rebrand — always pass `--repo cuioss/TokenSheriff` to `gh`).

## How the release is wired (read first)

The release is **fully automated by GitHub Actions**. `.github/workflows/release.yml`
triggers on a **merged pull request that changes `.github/project.yml`**:

```yaml
on:
  pull_request:
    types: [closed]
    paths:
      - '.github/project.yml'
```

So this skill never runs Maven release goals by hand. Its job is to produce and merge the
correct `project.yml` change; the reusable `cuioss-organization` release workflow
(`reusable-maven-release.yml`) does the tagging, Maven Central deploy, and GitHub release
creation.

Observed timings (use these as the basis for the waits below):
- PR gating checks: **Maven Build** is the primary gate; **Integration Tests** (multi-IDP:
  Keycloak + Dex + Zitadel) and **End-to-End Tests** (Playwright Dev-UI, `timeout-minutes: 30`)
  also run. End-to-end is the long pole, so a full green PR takes **~15–20 min**.
- Release workflow itself: **~6 min**, but Maven Central propagation, the GitHub Pages deploy
  (`pages.deploy-at-release: true`), and the GitHub release publish can lag → allow **up to
  ~30 min** before treating it as stuck.

## Workflow

### Step 1 — Determine the version number

Read the current release block. `.github/project.yml` holds both numbers under `release`:
- `release.current-version` (e.g. `0.9.0`)
- `release.next-version` (e.g. `1.0.0-SNAPSHOT`)

**Default rule:** the release version is `next-version` with `-SNAPSHOT` stripped (e.g.
`1.0.0-SNAPSHOT` → `1.0.0`). The new `next-version` is the next bump plus `-SNAPSHOT`
(e.g. `1.1.0-SNAPSHOT`).

**Ask the user** (AskUserQuestion) only if in doubt — e.g. the numbers don't follow the
expected pattern, a patch/major release is plausible, or `current-version` and `next-version`
are inconsistent. Otherwise state the determined version and proceed.

### Step 2 — Determine current status (clean to release?)

```bash
gh pr list --repo cuioss/TokenSheriff --state open --json number,title,isDraft
```
- **No open PRs** → good, proceed.
- **Open PRs exist** → these would normally be merged before a release. Surface the list and
  **ask the user** whether to proceed anyway or wait. Do not silently ignore them.

Also confirm the working tree is clean (`git status --porcelain`) before branching.

### Step 2b — Gate on smallrye/Quarkus alignment (do NOT skip)

```bash
python3 .claude/skills/release/check-quarkus-alignment.py --repo . --check-resolved
```

| exit | meaning |
|------|---------|
| 0 | aligned — proceed |
| 1 | **misaligned** — stop, fix, restart |
| 2 | **could not determine** — also a stop. An unresolvable check is never a pass. |

`version.quarkus` here is a **project-owned pin, not an override**: the parent chain declares
no Quarkus version at all, and it cannot — Maven does not propagate properties from
*imported* BOMs, and `quarkus-maven-plugin` needs the value as a build extension. This
project's Quarkus therefore moves independently of `cuioss-parent-pom`, and nothing upstream
validates it.

Quarkus' deployment classes are compiled against one specific smallrye-config release, so a
newer version — even an internally coherent one — fails augmentation with
`failed to access io.smallrye.config.ConfigMappingLoader$ConfigMappingImplementation`. That
shipped twice through `cuioss-parent-pom` and cost five weeks of red builds the first time.
The `requireSameVersions` enforcer guard cannot catch it: nothing is split, so it stays
correctly silent.

`--check-resolved` asserts every `io.smallrye.config` artifact actually resolves to what
**this** project's Quarkus was built against, catching a split family as well as a wrong one.

Keep the script in sync with `cuioss-parent-pom`'s copy; there is no shared parent to inherit
it from.

### Step 3 — Pull current main

```bash
git checkout main && git pull --ff-only origin main
```

### Step 4 — Create the release branch

Branch name uses the `chore/` prefix (required — the Maven CI workflow only triggers on
`main`, `feature/*`, `fix/*`, `chore/*`, `release/*`, `dependabot/**`; other prefixes skip the
`build` check and block auto-merge):

```bash
git checkout -b chore/release_<version>   # e.g. chore/release_1.0.0
```

### Step 5 — Update `.github/project.yml`

Edit the `release` block:
- `current-version:` → the version determined in Step 1 (e.g. `1.0.0`)
- `next-version:` → next bump + `-SNAPSHOT` (e.g. `1.1.0-SNAPSHOT`)

Leave everything else untouched.

### Step 6 — Badges in README.md (normally no action)

The README badges are **dynamic shields.io endpoints** (Maven Central, Sonar, last-commit,
benchmark) that update automatically — there is **no hand-maintained version badge** to bump,
so normally leave `README.md` alone. Only touch it if a release note explicitly calls for a
README change.

### Step 7 — Commit, push, open PR

```bash
git add .github/project.yml
git commit -m "chore(release): prepare release <version>" --trailer "Co-Authored-By: Claude <noreply@anthropic.com>"
git push -u origin chore/release_<version>
gh label create skip-bot-review --repo cuioss/TokenSheriff --description "Skip automated bot review" --color ededed 2>/dev/null || true
gh pr create --repo cuioss/TokenSheriff --base main \
  --title "chore(release): prepare release <version>" \
  --label "skip-bot-review" \
  --body "Bump current-version to <version>, next-version to <next>-SNAPSHOT. Triggers the automated Release workflow on merge."
```

The mechanical release PR carries the `skip-bot-review` label so automated bot review is
skipped, matching the other cuioss release skills (the preceding `gh label create` ensures the
label exists first).

Use the project commit convention: `Co-Authored-By: Claude <noreply@anthropic.com>` (no model
name / no "Generated with Claude Code" footer).

### Step 8 — Wait for PR checks (~15–20 min)

Watch the checks rather than blindly sleeping; the end-to-end suite is the long pole:

```bash
gh pr checks <pr#> --repo cuioss/TokenSheriff --watch
```
If using a scheduled/loop wait, poll roughly every few minutes up to ~20 min.

### Step 9 — Handle PR comments / failures (if any)

- If a check fails, read the failing run's log (`gh run view <id> --log-failed`), fix the cause
  on the branch, push, and re-wait. **Never** merge a red PR.
- If reviewers (Gemini/CI) leave comments
  (`gh api repos/cuioss/TokenSheriff/pulls/<pr#>/comments`), address each: fix valid ones and
  reply, or reply explaining why not — every comment gets a reply and is resolved.
- Re-run Step 8 after any push.

### Step 10 — Merge → release starts automatically

Once checks are green and comments resolved:

```bash
gh pr merge <pr#> --repo cuioss/TokenSheriff --squash
```
`main` uses the org-managed merge queue (`main-merge-queue`), so the merge **enqueues** (it is
not immediate) and `--delete-branch` is rejected (the queue auto-deletes the branch on merge).
After `gh pr merge ... --squash`, poll
`gh pr view <pr#> --repo cuioss/TokenSheriff --json state --jq .state` until it reports `MERGED`
before expecting the Release workflow. The release workflow is unaffected because
`cuioss-release-bot` is a bypass actor on the queue.

Merging this PR (it touches `.github/project.yml`) fires `release.yml` automatically — do
**not** dispatch the release manually unless the auto-trigger demonstrably did not fire.

### Step 11 — Wait for the Release workflow (~30 min)

```bash
# Pick the newest in-progress Release run explicitly (a bare --limit 3 can surface
# older Release runs alongside the active one):
RUN_ID=$(gh run list --repo cuioss/TokenSheriff --workflow "Release" --limit 10 \
  --json databaseId,status --jq 'map(select(.status=="in_progress")) | first | .databaseId')
# Fallback if the run hasn't registered yet, or to target this release by the merged
# commit: gh run list ... --json databaseId,headSha --jq 'map(select(.headSha=="<sha>")) | first | .databaseId'
gh run watch "$RUN_ID" --repo cuioss/TokenSheriff
```
The workflow itself runs ~6 min; allow up to ~30 min for tag + Maven Central propagation +
Pages deploy + GitHub release publish before treating it as stuck.

### Step 12 — Verify the release landed

```bash
gh release view <version> --repo cuioss/TokenSheriff \
  --json tagName,name,createdAt,body
git fetch --tags && git tag --list <version>
```
Confirm the tag exists and a GitHub release for `<version>` was created. If it did not appear,
inspect the Release workflow run log before proceeding.

### Step 13 — Reformat the generated release notes

The Release workflow creates the GitHub release with **auto-generated** notes (a flat
`## What's Changed` list). Rewrite them in place using the **house format below**, then push
the update:

```bash
mkdir -p .plan/temp
gh release view <version> --repo cuioss/TokenSheriff --json body --jq .body > .plan/temp/release-<version>-orig.md
# ...build the reformatted body in .plan/temp/release-<version>.md...
gh release edit <version> --repo cuioss/TokenSheriff --notes-file .plan/temp/release-<version>.md
```

After building the reformatted file, **cross-check coverage** before editing the release:
extract the `pull/<n>` numbers from both files and confirm every original PR is either kept,
collapsed into a chain, or intentionally dropped (only the mechanical version-bump PR and
OpenRewrite bumps should be dropped outright), and that no PR appears in the new file that was
not in the original.

#### House format rules (apply exactly)

1. **Two top-level groups:** `## Features & Enhancements` and `## Dependency Updates`.
2. **Features & Enhancements** — group functional PRs by theme with `###` subheadings, e.g.:
   - `### API & Code Quality` — also the home for refactor/standards/cleanup recipes
     (e.g. `refactor-to-profile-standards`, requirement-ID renames), **not** under build/tooling
   - `### Security`
   - `### Testing & Standards`
   - `### Documentation`
   - `### Build & CI` — manually-authored CI/build improvements (e.g. adopting a new
     cuioss-organization workflow behaviour); **not** mechanical dependency bumps
   Add release-specific themes when the cycle has a dominant thread (e.g. a
   `### Rebrand: OAuth-Sheriff → Token-Sheriff` group). Adapt headings to the actual PRs;
   omit empty sections.
3. **Dependency Updates** — group by type with `###` subheadings:
   - `### Java` — Java libraries (e.g. Quarkus, gson, commons-io, microprofile-jwt-auth-api)
   - `### JavaScript` — npm deps under
     `token-sheriff-quarkus-parent/token-sheriff-validation-quarkus-deployment` and
     `token-sheriff-quarkus-parent/e-2-e-playwright` (eslint, prettier, stylelint, jest, babel,
     lit, …). Note older PR titles may still carry the pre-rebrand `oauth-sheriff-quarkus-*`
     path — keep the path verbatim from each PR title.
   - `### Infra` — platform/build/CI: build plugins (e.g. frontend-maven-plugin), GitHub Action
     bumps (claude-code-action, harden-runner, actions/*), cui-java-parent, and
     cuioss-organization workflow bumps
4. **Collapse version chains** — when the same artifact is bumped multiple times (`A → B → C`),
   keep only the **latest** entry spanning the full range, using the latest PR's URL/author
   (e.g. `version.quarkus 3.34.2 → 3.35.0 → 3.37.0` becomes a single `3.34.2 to 3.37.0`).
   This matters a lot here — `anthropics/claude-code-action` and `step-security/harden-runner`
   are bumped dozens of times per cycle; collapse each to one Infra line.
5. **Remove all OpenRewrite bumps and friends** — drop every `rewrite-maven-plugin`,
   `rewrite-migrate-java`, `rewrite-testing-frameworks`, and related OpenRewrite dependency PR.
6. **Remove internal tooling churn** — drop PRs that only touch dev/build orchestration with no
   user-facing effect: `marshal.json`/plan-marshall config migrations, plan-marshall build
   wiring, internal dev-skill changes, and **the mechanical version-bump PR itself**
   (`chore(release): prepare release <version>` / `release: cut … <version>`).
7. Preserve each kept PR line verbatim (`* <title> by @author in <url>`); when two PRs share an
   identical title, merge them onto one line with both URLs. For collapsed chains, keep the
   latest PR's line and adjust only the version span.
8. Keep the trailing `**Full Changelog**: ...compare/<prev>...<version>` line.

### Step 14 — Done

Report: released version, release URL, the PR number, and a short summary of how many
dependency PRs were collapsed/removed during note reformatting.

## Critical rules

- The release is triggered by **merging a `.github/project.yml` change** — never hand-run
  Maven release goals.
- Always pass `--repo cuioss/TokenSheriff` to `gh` (the local checkout is named `OAuthSheriff`).
- Branch prefix **must** be `chore/` (or another CI-accepted prefix) or the build check skips
  and auto-merge is blocked.
- Never merge a red PR; fix and re-wait.
- Temporary files go under `.plan/temp/`.
- Commit trailer: `Co-Authored-By: Claude <noreply@anthropic.com>`; no PR footer line.
