#!/usr/bin/env bash
# Semgrep 1.186.0, правила: локальная копия https://github.com/semgrep/semgrep-rules + кастомные правила
set -e
git clone --depth 1 https://github.com/semgrep/semgrep-rules.git /tmp/semgrep-rules 2>/dev/null || true
semgrep --metrics=off \
  --config /tmp/semgrep-rules/python \
  --config /tmp/semgrep-rules/yaml/docker-compose \
  --config /tmp/semgrep-rules/generic/secrets \
  --config sast/custom-rules.yml \
  --json -o sast/semgrep_raw.json microservice
# semgrep_results.json = semgrep_raw.json + ручные находки IDOR + поле triage
