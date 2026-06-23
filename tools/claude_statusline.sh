#!/usr/bin/env bash
# Status line for Claude Code: objdiff match progress.
# Shows total fuzzy match %, perfect (exact) match %, and linked (complete) match %.
# Cached on report.json mtime so we only re-run jq when the build refreshed it.

set -u

# Drain stdin (Claude Code pipes session JSON in; we don't need it).
cat >/dev/null

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
REPORT="$PROJECT_DIR/build/GSAE01/report.json"
CACHE="${TMPDIR:-/tmp}/sfa_claude_statusline.cache"

if [ ! -f "$REPORT" ]; then
  echo "objdiff: no build/GSAE01/report.json — run ninja"
  exit 0
fi

if mtime=$(stat -f %m "$REPORT" 2>/dev/null); then :; else mtime=$(stat -c %Y "$REPORT"); fi

if [ -f "$CACHE" ]; then
  read -r cached_mtime < "$CACHE" || cached_mtime=
  if [ "$cached_mtime" = "$mtime" ]; then
    tail -n +2 "$CACHE"
    exit 0
  fi
fi

line=$(jq -r '
  def r2(n): (n * 100 | round) / 100;
  .measures
  | "fuzzy \(r2(.fuzzy_match_percent))% │ perfect \(r2(.matched_code_percent))% │ linked \(r2(.complete_code_percent))%"
' "$REPORT")

if [ -z "$line" ]; then
  echo "objdiff: failed to parse report.json"
  exit 0
fi

printf '%s\n%s\n' "$mtime" "$line" > "$CACHE"
printf '%s\n' "$line"
