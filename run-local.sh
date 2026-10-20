#!/usr/bin/env bash
# Run the whole pipeline locally, exactly as CI runs it.
#
#   ./run-local.sh
#
# Every tool writes into reports/ and the gate reads that directory. A tool you
# do not have installed is skipped with a notice rather than failing the run,
# so you can start with just Semgrep and add the rest as you go.
#
# Expected outcome: the gate FAILS. The targets are deliberately vulnerable
# APIs. A green gate here would mean the gate is broken. See the README.

set -uo pipefail

REPORTS="${REPORTS:-reports}"
TARGET_URL="${TARGET_URL:-http://127.0.0.1:5000}"
IMAGE="${IMAGE:-vampi-lab:local}"

# Semgrep writes its SARIF using the system codepage. On Windows that is
# cp1252, and a registry rule's message contains an emoji it cannot encode, so
# the file comes out empty and every downstream step reads zero findings.
export PYTHONUTF8=1

have() { command -v "$1" >/dev/null 2>&1; }
skip() { printf '  SKIP  %-12s %s\n' "$1" "$2"; }
step() { printf '\n=== %s ===\n' "$1"; }

rm -rf "$REPORTS"
mkdir -p "$REPORTS"

step "fetch targets"
bash target/fetch.sh

step "self-test: rules and gate"
if have semgrep; then
  semgrep test semgrep/rules/python
  semgrep test semgrep/rules/javascript
else
  skip semgrep "pip install semgrep"
fi
python -m pytest -q

step "benchmark: measured precision and recall"
# Floors are the values committed in the README. A rule edit that loses
# accuracy fails here instead of quietly shipping.
if have semgrep; then
  python benchmark/benchmark.py \
    --target target/vampi --labels benchmark/labels/vampi.yml \
    --rules semgrep/rules/python \
    --min-precision 0.83 --min-recall 0.71 \
    --json-out benchmark-results/vampi.json || exit 1
  echo
  python benchmark/benchmark.py \
    --target target/dvna --labels benchmark/labels/dvna.yml \
    --rules semgrep/rules/javascript \
    --min-precision 0.375 --min-recall 1.0 \
    --json-out benchmark-results/dvna.json || exit 1
else
  skip benchmark "needs semgrep"
fi

step "semgrep: custom rules + registry baseline"
if have semgrep; then
  semgrep --config semgrep/rules --config p/security-audit \
          --metrics off --sarif -o "$REPORTS/semgrep.sarif" \
          target/vampi/api_views target/vampi/models \
          target/vampi/app.py target/vampi/config.py \
          target/dvna/core target/dvna/routes target/dvna/models
else
  skip semgrep "pip install semgrep"
fi

step "gitleaks"
if have gitleaks; then
  # Full history of this repo, not just the working tree.
  gitleaks detect --redact --exit-code 0 \
           --report-format sarif --report-path "$REPORTS/gitleaks.sarif"
else
  skip gitleaks "https://github.com/gitleaks/gitleaks"
fi

step "trivy"
if have trivy; then
  trivy fs --scanners vuln --quiet --format sarif \
        -o "$REPORTS/trivy-fs.sarif" target/vampi
  trivy config --quiet --format sarif \
        -o "$REPORTS/trivy-config.sarif" target/vampi
  if have docker && docker info >/dev/null 2>&1; then
    docker build -q -t "$IMAGE" target/vampi >/dev/null
    trivy image --scanners vuln --quiet --format sarif \
          -o "$REPORTS/trivy-image.sarif" "$IMAGE"
  else
    skip trivy-image "docker daemon not reachable"
  fi
else
  skip trivy "https://github.com/aquasecurity/trivy"
fi

step "syft + grype"
if have syft && have grype; then
  syft "dir:target/vampi" -o cyclonedx-json="$REPORTS/sbom.cdx.json" -q
  grype "sbom:$REPORTS/sbom.cdx.json" -o sarif > "$REPORTS/grype.sarif" 2>/dev/null
else
  skip syft/grype "https://github.com/anchore"
fi

step "zap baseline"
if have docker && docker info >/dev/null 2>&1; then
  docker rm -f vampi-lab >/dev/null 2>&1 || true
  docker build -q -t "$IMAGE" target/vampi >/dev/null
  docker run -d --rm --name vampi-lab -p 5000:5000 "$IMAGE" >/dev/null
  for _ in $(seq 1 30); do
    curl -sf "$TARGET_URL/" >/dev/null 2>&1 && break
    sleep 1
  done
  curl -sf "$TARGET_URL/createdb" >/dev/null 2>&1 || true
  chmod 777 "$REPORTS"
  docker run --rm --network host -v "$PWD/$REPORTS:/zap/wrk/:rw" \
    ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
    -t "$TARGET_URL" -J zap.json -I || true
  docker rm -f vampi-lab >/dev/null 2>&1 || true
else
  skip zap "docker daemon not reachable"
fi

step "gate"
# Benchmark output goes to benchmark-results/, never into $REPORTS. The gate
# globs its input directory recursively, so a measurement left in there would
# be read as a report.
python gate/gate.py --reports "$REPORTS" --suppressions gate/suppressions.yml
rc=$?

echo
if [ "$rc" -eq 0 ]; then
  echo "gate passed. Against these targets that means the gate is broken."
else
  echo "gate blocked the release (exit $rc). That is the expected result here."
fi
exit "$rc"
