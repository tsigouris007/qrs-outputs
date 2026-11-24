# E4: IRIS with Claude Sonnet 4.6 (same-model control), started 2026-11-18

Self-contained experiment folder. Plan and design: `../memory/COMPARISON_PLAN.md` §3. Only the model changes:
IRIS's code, prompts, batch sizes (30 external / 20 internal), threads (3), seed (1234) and evaluation stay as in v1.

## Layout
| Path | What |
|---|---|
| `src/` | IRIS, branch v1 @ `67140e84e6a0` (2025-06-21; the v1 line that holds the published per-project results). Only change: the adapter (below). `.gitmodules` is empty in the working tree (sandbox keeps it read-only); the data submodule is cloned separately |
| `cwe-bench-java/` | benchmark repo, shallow clone @ `afe0ebd` (2026-11-18). The IRIS Dockerfile clones it unpinned; we will use this copy instead |
| `adapter/claude.py` | Claude adapter (official `anthropic` SDK), sibling of IRIS `src/models/gpt.py` |
| `adapter/apply.py` | embeds it: copies `claude.py` to `src/src/models/` and adds one `startswith("claude")` branch to `LLM.get_llm` |
| `adapter/test_offline.py` | offline test against a fake Messages endpoint (no cost) |
| `jdk/` | **user drops the three Oracle JDK archives here** (see below) |

## Adapter settings vs IRIS's GPT-4 setting (`src/src/models/gpt.py`)
| | GPT-4 (published) | Claude adapter |
|---|---|---|
| model | gpt-4-0125-preview | claude-sonnet-4-6 (as QRS C3) |
| temperature | 0 | 0 |
| max tokens | 4096 | 4096 |
| seed | 345 | none (no API equivalent) |
| JSON mode | `response_format=json_object` only in contextual filtering, and only for `GPTModel` instances | none (IRIS calls non-GPT models without it); `json_parse_ok` logged per call |
| thinking | n/a | not requested |
| retries | OpenAI client default (2) | Anthropic SDK default (2) |
| prompt caching | none | none |

Per call: `$E4_LLM_LOG` JSONL (stage from IRIS's system prompt, project/CVE/CWE from env, usage, cost, stop reason, ids,
latency, error, json_parse_ok). Hard budget `$E4_BUDGET_USD` (default 15), restart-safe.
Price: Sonnet 4.6 $3 / $15 per MTok (list, checked 2026-11-18; reconfirm on the run day).

## JDKs (Oracle account required; cannot be automated, cwe-bench-java README L105–120)
Put exactly these files in `jdk/` (Linux x64 .tar.gz):
- `jdk-7u80-linux-x64.tar.gz`: https://www.oracle.com/java/technologies/javase/javase7-archive-downloads.html
- `jdk-8u202-linux-x64.tar.gz`: https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html
- `jdk-17_linux-x64_bin.tar.gz` (JDK 17 GA, extracts to `jdk-17/`): https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html

## Running under the proxy (2026-11-20)
a TLS-intercepting network proxy intercepts TLS (Gateway CA) and serves DNS on 127.0.2.2/127.0.2.3, so every run needs:
- `--network host`: a bridged container cannot reach the proxy's local DNS ("Could not resolve host").
- `iris/e4_entry.sh` as entry point plus the CA bundle mounted read-only at `/certs/ca.pem`
  (`e1_nov2026/certs/ca-bundle-proxy.pem`). At start, inside the throwaway container, it adds the 2 proxy CA certs
  to the system store (git, wget, curl), to both JDKs' `cacerts` (Maven/Gradle: `build_one.py` runs them with
  env={PATH, JAVA_HOME} only, so JAVA_TOOL_OPTIONS would not reach them) and sets SSL_CERT_FILE (conda Python, httpx). It
  activates the conda env, runs the command, then chowns `$E4_CHOWN_PATHS` back to `$E4_HOST_UID:$E4_HOST_GID`.
  Network-only change; IRIS code, prompts and settings are untouched. Image unchanged (`iris-e4:v1`).
- Only `CLAUDE_API_KEY` is passed (`-e CLAUDE_API_KEY`, exported from `.env` without printing).

Checks (`iris/smoke/`):
- `tls_check.sh` (free): git/github.com, wget/archive.apache.org + services.gradle.org, curl + Python urllib/repo.maven.apache.org,
  httpx/api.anthropic.com (401), JVM 8 + 17/repo.maven.apache.org, JVM 8/plugins.gradle.org.
  Without the CA: 9/10 fail with certificate-verification errors (javac is local). With it: **10/10 pass**.
- `smoke_test.py` under the proxy: 1 call, PASS, identical to the pre-proxy call (436/201 tokens, $0.0043, json_parse_ok).
  Smoke spend total: $0.0086 (`smoke/e4_llm_calls.jsonl`).

Results stay in `iris/` (user, 2026-11-20). Layout of the full run (`iris/runs/full/`, runner `iris/run_one.sh`):
| Host | Container | What |
|---|---|---|
| `iris/runs/full/output` | `/iris/output` | IRIS results |
| `iris/runs/full/codeql-dbs` | `/iris/data/codeql-dbs` | CodeQL DBs |
| `iris/runs/full/project-sources` | `/iris/data/cwe-bench-java/project-sources` | fetched projects |
| `iris/runs/full/m2` | `/root/.m2` | Maven cache (reused across projects) |
| `iris/runs/full/build-info` | `/iris/data/cwe-bench-java/build-info` | successful build attempt per project |
| `iris/runs/full/logs` | `/e4` | `e4_llm_calls.jsonl` (per call; the budget guard sums it), `runs.jsonl` (stage timings, rc), `<slug>/<stage>.log`, `e4-iris-NN.console.log` |
Disk (user, 2026-11-20): +30 GB added; completed projects' CodeQL DBs may be deleted when free space runs low (< 60 GB, updated 17:50 UTC),
logged in `runs/full/logs/pruned_dbs.jsonl`; sources and outputs are kept. DBs are reproducible from the sources.

Maven/Gradle distributions are downloaded into the image's `java-env/` by setup_mvn/setup_gradle; run all pilot projects
in one container session so they are fetched once (todo before the full run).

Queue runner (2026-11-20): `run_queue.py` (one project at a time; per-project metrics in `runs/full/logs/projects/<slug>.json` and `e4_projects.jsonl`; queue file `runs/full/logs/queue.txt`). Earlier single-project runner:
Run one project (host, repo root; see log.md 2026-11-20 for the full `docker run` line):
`docker run --rm --name e4-iris-NN --network host -e CLAUDE_API_KEY -e E4_LLM_LOG=/e4/e4_llm_calls.jsonl -e E4_BUDGET_USD=<cap> ... iris-e4:v1 /e4_entry.sh bash /run_one.sh <slug> <CWE-0XX> <CVE>`

## Deviations from the original IRIS v1 setup (complete list, for the paper; keep updated)
IRIS code, prompts and settings (seed 1234, batches 30/20, 3 threads, evaluation) are unchanged; only the model and the
environment differ.
| # | Deviation | Why | Effect |
|---|---|---|---|
| 1 | Model: Claude Sonnet 4.6 via `adapter/claude.py` (T0, max_tokens 4096, no seed, no JSON mode, no thinking, no caching) instead of gpt-4-0125-preview | E4's purpose (same-model control) | GPT-4 used JSON mode in contextual filtering (expect_json only for GPTModel); Claude sometimes writes analysis before the JSON — IRIS's regex extracts it (0 failures from this) |
| 2 | cwe-bench-java pinned copy (afe0ebd) instead of an unpinned clone | reproducibility | none |
| 3 | No JDK 7u80 (empty dir → build attempt 5 fails as for every project) | Oracle login-gated | none (0 projects need it) |
| 4 | JDK 17.0.12 instead of 17 GA | archive available | minor |
| 5 | Miniforge instead of Miniconda | Anaconda ToS | none (same environment.yml) |
| 6 | Runtime: `--network host`, the proxy CA added to system store, JDK cacerts, SSL_CERT_FILE and (from 2026-11-20 20:30 UTC, after keycloak #33 failed on npm) /root/.npmrc + /root/.yarnrc `cafile`; from 2026-11-21 `git safe.directory '*'` (kept sources are host-owned) and a `/usr/local/bin/java` shim → `$JAVA_HOME/bin/java` (no system java in IRIS's image) (`e4_entry.sh`) | the proxy TLS interception + local DNS | network only |
| 7 | Runtime: `/iris/codeql` exported on PATH in `e4_entry.sh` | IRIS sets it only via ~/.bashrc (interactive shells) | none (same patched CodeQL 2.15.5) |
| 8 | **Second pass for build/DB failures (user OK 2026-11-20), after all 90 have run once:** build with `-Dmaven.test.skip=true` (Maven) or a CodeQL `--command` compiling main code only (Gradle, e.g. `./gradlew compileJava -x test`) (test sources not compiled) and remove a false Gradle build-info (cwe-bench-java's Gradle attempt "succeeds" as a no-op on Maven-only projects, so the DB step gets no Maven) | dependency rot since the benchmark was built (e.g. camel-jira tests: `org.codehaus.jettison.json` no longer resolves) | test code absent from those projects' CodeQL DBs; every affected project is listed below and reported |
| 10 | Not a deviation, a measured adapter effect: IRIS's greedy `\{[\s\S]*\}` grabs from the first brace, and Claude's analysis text before the JSON can contain braces (code snippets) → invalid → path dropped | no JSON mode for non-GPT models in IRIS (GPT-4 got `response_format=json_object`) | quantified as "mode 2" by the same script; first case #28 goomph (vanilla found → posthoc missed; GPT-4 found) |
| 11 | (Explained by #13) `package-names/<slug>.txt` "missing" for 5 projects — they exist under the 698fb72 slugs; (#35 hapifhir, #69/#70 keycloak 20.0.3, #71 xwiki-commons, #73 xwiki-rendering) | pinned cwe-bench-java copy lacks them; IRIS Stage 1 needs them | generated with IRIS's own documented `scripts/get_packages_codeql.py <slug>` (copies in `runs/full/logs/package-names-generated/`); published GPT-4 row for #35 is 0/0, consistent with the same gap |
| 12 | CodeQL memory: `/iris/codeql/codeql` wrapped in the container to add `--ram=20000` (→ -Xmx8308M) for `database analyze`/`query run` (effective from restart 8, 2026-11-21 ~12:40 UTC; the 05:30 `-J-Xmx10g` attempt was ignored by CodeQL — JVM stayed at -Xmx4404M) | OOM compiling IRIS's generated query on nifi and spring-framework; IRIS passes no `--ram`; 2.15.5 ignores config/env | resource only; earlier projects ran with CodeQL's default sizing |
| 13 | **Benchmark commit**: E4 pinned cwe-bench-java afe0ebd (2026-11-18) but IRIS v1 pins 698fb72; 4 in-scope CVEs were re-pinned in between (keycloak 20.0.4→20.0.3 ×2, xwiki 14.6→14.5 ×2). Published GPT-4 and QRS use the 698fb72 versions. (Correction 2026-11-21: #35 hapifhir's rows are identical in both commits; only its package-names file is misnamed, see #11.) | my pinning error (found 2026-11-21) | **user decision 2026-11-21: rerun the 4 with the 698fb72 rows** (`runs/full/logs/second_pass/698fb72_*.rows.csv`, appended to the container-local benchmark CSVs; 698fb72 slugs; the benchmark's own package-names files); the afe0ebd attempts (#69/#70 20.0.3) stay as logged attempts, not in the comparison; other 86 identical |
| 14 | **Second-pass build fixes** (user decisions 2026-11-21; per project in `runs/full/logs/second_pass/plan.json`): (a) camel #5/#9: cached stub pom of `com.sun.jersey:jersey-json:1.5` (served today by atlassian-public, no dependencies → jettison missing from camel-jira's test classpath) replaced by Maven Central's pom (sha1-checked), and `http://maven.restlet.org` (repository id `maven-restlet`, camel-restlet), which now serves one HTML page for every artifact, mirrored to Restlet's new https://maven.restlet.talend.com via `/root/.m2/settings.xml` + the 12 cached HTML pages deleted (`second_pass/fix_restlet_repo.sh`); result: camel CVE-2019-0194 builds with the benchmark's own JDK 8u202 + Maven 3.5.0 on the first attempt; (b) testng #31: Gradle init script drops only `-Werror` (JDK 17 `[removal]` warning in a test file), CodeQL runs autobuild's own `./gradlew … testClasses`; (c) uima #32: `.mvn/maven.config -pl` excludes 6 documentation modules, all with 0 .java files, and `-P !process-docbook` turns off parent-pom-14's documentation profile (it unpacks the same vanished SNAPSHOT in PearPackagingMavenPlugin, which has a docbook user guide); (d) xstream #46: same, excludes `xstream-distribution` (0 .java files); (e) fresh clones and no stale/false build-info for retried projects | dependency/repository rot and JDK drift since the benchmark was built; user asked for full DBs (test code included: 67 benchmark projects have test methods in fix_info) | no source-code change; the CodeQL DBs contain the same Java code as a clean build (excluded modules have no Java) |
| 15 | **xstream ground-truth alias**: fix_info lists CVE-2020-26217 under `x-stream__xstream_CVE-2020-26217_1.4.14` while the project is `…_1.4.14-java7` (both commits) → IRIS's evaluator finds no ground truth (recall 0 by construction; the published GPT-4 row is 0 recall / 0 TP paths). User 2026-11-21: same version → the 4 rows are aliased to the -java7 slug | benchmark naming bug | footnote in the paper; the as-is value is 0 for every system |
| 9 | Not a deviation, a measured IRIS bug: posthoc JSON preprocessing `re.sub("//.*")` truncates strings containing `//` → path dropped | IRIS v1 code (applies to GPT-4 too) | quantified per project by `assets/metrics_scripts/e4_posthoc_parse_sensitivity.py`; IRIS left unchanged (user). Flipped at least one detection: #17 one-java-agent CVE-2022-25842 (Claude's correct Zip Slip verdict unparsed → path dropped); bug-corrected re-evaluation after the run |

Projects affected by #8 (first-pass status → second-pass outcome):
- #5 `apache__camel_CVE-2018-8041_2.20.3`: db_failed (Maven testCompile dependency rot in camel-jira; false Gradle success) → pending second pass.
- #9 `apache__camel_CVE-2019-0194_2.21.4`: same camel-jira testCompile rot; db_failed (67 min, $0) → pending second pass.
- #31 `testng-team__testng_CVE-2022-4065_7.5`: db_failed — Gradle project; CodeQL autobuild compiles tests, `EmailableReporterTest.java:141` `[removal] SecurityManager` warning + `-Werror` → pending second pass with the Gradle variant (CodeQL `--command` building main code only, e.g. `./gradlew compileJava -x test`).
- #32 `apache__uima-uimaj_CVE-2022-32287_3.3.0`: db_failed — docs module `uima-docbook-overview-and-setup` needs a vanished Apache SNAPSHOT (`uima-docbook-olink:1-SNAPSHOT`); false Gradle success → no mvn for CodeQL. Candidate fix (**new deviation type, user OK needed**): exclude the 4 Java-free `uima-docbook-*` modules (0 .java files) from the build.
- #33 `keycloak__keycloak_CVE-2022-3782_20.0.1`: attempt 1 npm SELF_SIGNED_CERT (the proxy; fixed in e4_entry.sh), attempt 2 `npm: Permission denied` (attempt 1's leftover Node in the kept sources), **attempt 3 on a fresh clone: OK** (toolchain reruns, no deviation).
- #35 `hapifhir__org.hl7.fhir.core_CVE-2023-28465_5.6.105`: attempt 1 no package-names file (deviation #11); attempt 2 git "dubious ownership" on kept sources (our chown; fixed by `safe.directory` in e4_entry.sh) → second pass.
- #41 `yamcs__yamcs_CVE-2023-45278_5.8.6`: benchmark config fails at exec-maven-plugin `Cannot run program "java"` (no system java; build_one passes PATH/JAVA_HOME only) → second pass with the `java` shim (e4_entry.sh) + false Gradle build-info removed.
- #42 `yamcs__yamcs_CVE-2023-45277_5.8.6`: same as #41 → second pass with the `java` shim.
- #46 `x-stream__xstream_CVE-2020-26217_1.4.14-java7`: benchmark itself records a false Gradle build (mvn n/a); Maven fails (JDK 8 `--release`; JDK 17 distribution module needs SNAPSHOT javadoc jars); CodeQL autobuild finds no mvn. Candidate (**module-exclusion type, user OK needed with #32**): fallback mvn on PATH + build only module `xstream` with JDK 17.
- #49 `jenkinsci__workflow-cps-plugin_CVE-2022-25173_2646.v6ed3b5b01ff1`: attempt 1 hung 52 min in a TLS handshake (killed); benchmark config fails at the project's Yarn v0.23.0 (`self signed certificate`, ignores `cafile`) → second pass: `.yarnrc` inline `ca`, else `strict-ssl false` for yarn only (disclose).
- #55 `apache__nifi_CVE-2022-33140_1.16.2`: IRIS stage 6 CodeQL OutOfMemoryError (heap) compiling the generated query, after $9.52 of labelling → second pass with the CodeQL heap wrapper (cached labels reused).
- #82 `spring-projects__spring-framework_CVE-2022-22965_5.2.19.RELEASE`: IRIS stage 6 CodeQL OOM (heap 4.4 GB; the first wrapper was ineffective) after $9.21 → second pass with `--ram=20000` (labels cached).
- #69 `keycloak__keycloak_CVE-2022-4137_20.0.3` (and #70, same source): `keycloak-dependencies-admin-ui-wrapper` needs `keycloak-admin-ui:999-SNAPSHOT`, gone from Sonatype snapshots → candidate (**module-exclusion type, user OK needed with #32/#46**): exclude the packaging-only wrapper module; package-names generated.

## Run status (2026-11-22 14:28 UTC): COMPLETE
**90/90 ok** (`runs/full`): 75 first pass, 7 second pass, 8 follow-ups (Deviations #13–#15 + follow-up fixes: `-J-Xss64m`
via `E4_CODEQL_JOPTS`, `E4_CODEQL_RAM=32000` for spring/nifi, hapifhir `--internal-package org.hl7.fhir`, uima
`-P !process-docbook`, restlet mirror + jersey-json Central pom). **Recall@Method 39/90** (posthoc), @File 52/90, vanilla
(before posthoc) 55/90; **$216.24** (guard $300). Parse-bug sensitivity with IRIS's own Stage 8+9 replayed offline
(`assets/metrics_scripts/e4_posthoc_reeval.py`, `runs/full/logs/posthoc_reeval.json`): 39 → **40/90** (only one-java-agent
flips); IRIS itself unchanged. Published IRIS+GPT-4 on the same 90: 45/90.
(Earlier snapshot, 2026-11-21 08:50 UTC: 61/90 ok, 12 failed, 2 held back.)

## Status
- [x] 2026-11-18 clone + pin, code read (LLM layer, Dockerfile, setup, prompts, CLI defaults)
- [x] 2026-11-18 adapter + embed + offline test 9/9
- [x] 2026-11-18 JDKs (user): 8u202 + 17.0.12 in `jdk/` (hashes `jdk/SHA256SUMS`). **7u80 unavailable** (Oracle login; no account possible): not needed — `data/build_info.csv` has 92 × 8u202, 28 × 17, 0 × 7u80; it is only build attempt 5 of 10. `Dockerfile.e4` leaves an empty `jdk1.7.0_80/` so that attempt fails and the next runs. 17.0.12 instead of 17 GA: disclosed deviation.
- [x] 2026-11-18 `Dockerfile.e4` (our own; IRIS's `src/Dockerfile` untouched): pinned cwe-bench-java copy, adapter embedded, anthropic==0.72.0
- [x] 2026-11-19 00:10 Docker image `iris-e4:v1` (sha256:24cd123cab46, 15.1 GB). Attempt 1 (2026-11-18 21:28) failed: Miniconda requires accepting Anaconda's ToS (`build_attempt1_conda_tos.log`); user chose **Miniforge** (Dockerfile.e4 item 5). Attempt 2 OK (`build.log`). Verified offline: conda 26.9.4, env `iris`, CodeQL 2.15.5, java 1.8.0_202 + 17.0.12, adapter + get_llm branch, anthropic 0.72.0, real `models.llm` import; offline test 9/9 inside the image.
- [x] 2026-11-20 **live smoke test PASSED** (1 call, $0.0043, `iris/smoke/`: `smoke_test.py`, `e4_llm_calls.jsonl`): LLM.get_llm → ClaudeModel; IRIS API-labelling system prompt → stage `external_api_labelling`; T0, max_tokens 4096; 436 in / 201 out tokens, end_turn, 2.6 s; correct labels (File sink, getParameter source, toLowerCase propagator). Claude wraps the JSON in a ```json fence; IRIS's parsers extract the first [...] / {...} by regex (neusym_vul.parse_json L465, contextual_analysis_pipeline L297), so no effect. Run setup: only CLAUDE_API_KEY passed (-e, from .env, not printed), --user host uid, the proxy CA bundle mounted as SSL_CERT_FILE (TLS check 401 OK), conda env activated via /opt/conda/etc/profile.d/conda.sh (a login shell does not activate it)
- [x] 2026-11-20 the proxy: `e4_entry.sh` + `--network host`; TLS check 10/10 with CA (9/10 fail without); smoke call under the proxy PASS ($0.0043; smoke total $0.0086)
- [ ] ~~pilot: 5 projects~~ → 2026-11-20 user: **entire dataset (90 CVEs / 84 packages)**; project 1 first for a cost/runtime estimate. Runner `run_one.sh`, outputs `runs/full/` (see log.md 2026-11-20)
