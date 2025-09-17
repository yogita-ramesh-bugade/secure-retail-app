#!/usr/bin/env bash
set -euo pipefail

mkdir -p reports

# 1) SAST - SonarQube
sonar-scanner \
  -Dsonar.projectKey=secure-retail-app \
  -Dsonar.sources=. \
  -Dsonar.host.url=${SONAR_HOST_URL:-http://localhost:9000} \
  -Dsonar.login=${SONAR_LOGIN:-admin} \
  -Dsonar.report.export.path=reports/sonar-report.json || true

# 2) SCA - Snyk
snyk test --all-projects --json > reports/snyk-report.json || true

# 3) DAST - OWASP ZAP
zap-cli start
zap-cli open-url http://localhost:5000
zap-cli spider http://localhost:5000
zap-cli active-scan http://localhost:5000
zap-cli report -o reports/zap-report.html -f html
zap-cli shutdown

# 4) Secrets Detection - Gitleaks
gitleaks detect --source . --report-path reports/gitleaks-report.json || true

# 5) SBOM - Syft
syft packages dir:. -o json > reports/sbom.json || true

echo "All scans completed. Reports in ./reports"
