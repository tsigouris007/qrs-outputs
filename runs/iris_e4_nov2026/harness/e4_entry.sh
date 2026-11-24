#!/bin/bash
# E4 container entry (2026-11-20). Network-only environment change for a TLS-intercepting network proxy (TLS interception); IRIS code,
# prompts and settings untouched. Runs as root inside the --rm container, then hands mounted outputs back to the host user.
#
# Mounts/env expected (see iris/README.md "Running under the proxy"):
#   /certs/ca.pem        full CA bundle incl. the the proxy CA (e1_nov2026/certs/ca-bundle-proxy.pem), read-only
#   E4_HOST_UID/GID      host user to chown the writable mounts to at exit
#   E4_CHOWN_PATHS       space-separated container paths to chown (the host mounts)
# Trust is added in three places, because IRIS / CWE-Bench-Java use three TLS stacks:
#   1. system store (update-ca-certificates): git clone (fetch_one.py), wget (setup_mvn.py / setup_gradle.py), curl
#   2. SSL_CERT_FILE / REQUESTS_CA_BUNDLE: conda Python (anthropic/httpx, requests, urllib)
#   3. each JDK's cacerts: Maven/Gradle builds. build_one.py runs them with env={PATH, JAVA_HOME} only, so
#      JAVA_TOOL_OPTIONS/MAVEN_OPTS would not reach them.
set -uo pipefail
# 2026-11-21: body wrapped in main(), called on the last line: bash parses the whole function before running it, so
# editing this bind-mounted file while a container runs can no longer change the running script (incident 05:31 UTC).
main() {
CA=/certs/ca.pem
JAVA_ENV=/iris/data/cwe-bench-java/java-env

if [ -f "$CA" ]; then
  tmp=$(mktemp -d)
  awk -v d="$tmp" '/BEGIN CERTIFICATE/{n++} n{print > (d "/c" n ".pem")}' "$CA"
  i=0
  for f in "$tmp"/c*.pem; do
    if openssl x509 -in "$f" -noout -subject 2>/dev/null | grep -q "Gateway CA - Cloudflare"; then
      i=$((i + 1))
      cp "$f" "/usr/local/share/ca-certificates/e4-proxy-$i.crt"
      for jdk in jdk1.8.0_202:jre/lib/security/cacerts jdk-17.0.12:lib/security/cacerts; do
        home="$JAVA_ENV/${jdk%%:*}"; store="$home/${jdk#*:}"
        "$home/bin/keytool" -importcert -noprompt -storepass changeit -alias "e4-proxy-$i" -file "$f" \
          -keystore "$store" >/dev/null 2>&1 || echo "[e4_entry] WARN keytool import failed for $store"
      done
    fi
  done
  update-ca-certificates >/dev/null 2>&1
  export SSL_CERT_FILE="$CA" REQUESTS_CA_BUNDLE="$CA" CURL_CA_BUNDLE="$CA" GIT_SSL_CAINFO="$CA" NODE_EXTRA_CA_CERTS="$CA"
  # 2026-11-20 (keycloak): frontend-maven-plugin downloads Node and runs npm/yarn inside the Maven build, which
  # build_one.py starts with env={PATH, JAVA_HOME} only, so NODE_EXTRA_CA_CERTS cannot reach it. npm/yarn read their
  # user config from the home directory regardless of env, so the CA goes there.
  printf 'cafile=%s\n' "$CA" > /root/.npmrc
  printf 'cafile "%s"\n' "$CA" > /root/.yarnrc
  echo "[e4_entry] the proxy CA: $i the proxy cert(s) added (system store, JDK 8 + 17 cacerts, SSL_CERT_FILE)"
  rm -rf "$tmp"
else
  echo "[e4_entry] no /certs/ca.pem mounted: default trust only"
fi

# 2026-11-21 (#35 hapifhir rerun): sources kept across containers are chowned to the host user at exit, so git (run as
# root here, e.g. by buildnumber-maven-plugin) refuses them ("dubious ownership"). Trust all repos in this container.
git config --global --add safe.directory '*'
# 2026-11-21 (#41 yamcs): build_one.py runs builds with env={PATH, JAVA_HOME}, and neither IRIS's image nor ours has a
# system java, so plugins that exec a bare `java` (exec-maven-plugin) fail. Shim: run the build attempt's own JDK.
printf '#!/bin/sh\nexec "${JAVA_HOME:?JAVA_HOME not set}/bin/java" "$@"\n' > /usr/local/bin/java && chmod 755 /usr/local/bin/java

# 2026-11-21 (#55 nifi): CodeQL ran out of heap compiling IRIS's generated query (default -J-Xmx ≈ 3.5 GB on this
# host). IRIS calls /iris/codeql/codeql by absolute path and passes no --ram; config files/env vars are not honoured by
# 2.15.5. Wrap the binary in this throwaway container: +heap for database analyze / query run, everything else unchanged.
# 2026-11-21 12:30 UTC: -J-Xmx was NOT honoured (CodeQL computes -Xmx itself; JVM ran with -Xmx4404M) → use --ram
# (20000 → -J-Xmx8308M + off-heap 11692 per `codeql resolve ram`).
if [ ! -e /iris/codeql/codeql.real ]; then
  mv /iris/codeql/codeql /iris/codeql/codeql.real
  cat > /iris/codeql/codeql <<'WRAP'
#!/bin/sh
case "$1 $2" in
  "database analyze"|"query run"|"database run-queries")
    # 2026-11-22 follow-ups: E4_CODEQL_JOPTS (e.g. -J-Xss64m) for the query-planner StackOverflowError on the
    # largest generated queries (keycloak 20.0.4, camel); unset = unchanged. Verified with ps when first used.
    a=$1; b=$2; shift 2; exec /iris/codeql/codeql.real "$a" "$b" "--ram=${E4_CODEQL_RAM:-20000}" ${E4_CODEQL_JOPTS:-} "$@" ;;
  "database create")
    # 2026-11-21 second pass: per-project build command (run_queue.py plan "env": E4_CODEQL_COMMAND), e.g. Gradle
    # with test sources compiled but warnings-as-errors off. Unset = CodeQL autobuild, as IRIS does.
    if [ -n "${E4_CODEQL_COMMAND:-}" ]; then
      a=$1; b=$2; shift 2; exec /iris/codeql/codeql.real "$a" "$b" "--command=$E4_CODEQL_COMMAND" "$@"
    fi ;;
esac
exec /iris/codeql/codeql.real "$@"
WRAP
  chmod 755 /iris/codeql/codeql
fi

set +u   # conda's activate.d hooks (libblas_mkl_activate.sh) reference unset variables
source /opt/conda/etc/profile.d/conda.sh
conda activate iris
# IRIS's setup_environment.sh puts its patched CodeQL on PATH only via ~/.bashrc (interactive shells); same line here.
export PATH="/iris/codeql:$PATH"
"$@"
rc=$?
if [ -n "${E4_HOST_UID:-}" ] && [ -n "${E4_CHOWN_PATHS:-}" ]; then
  for p in $E4_CHOWN_PATHS; do [ -e "$p" ] && chown -R "$E4_HOST_UID:${E4_HOST_GID:-$E4_HOST_UID}" "$p"; done
fi
return $rc
}
main "$@"; exit $?
