#!/usr/bin/env bash
# Status line for Claude Code: SDK vs Game match progress from objdiff report.
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
  def pct(b; t): if t == 0 then 0 else (b * 1000 / t | round) / 10 end;
  def kb(n):     (n / 1024 | round);
  def cat(id):   (.categories[] | select(.id == id) | .measures);

  cat("sdk")  as $s
  | cat("game") as $g
  | ($s.total_code   // "0" | tonumber) as $sT
  | ($s.matched_code // "0" | tonumber) as $sM
  | ($g.total_code   // "0" | tonumber) as $gT
  | ($g.matched_code // "0" | tonumber) as $gM
  | "SDK \(pct($sM;$sT))% (fuzzy \(($s.fuzzy_match_percent * 10 | round) / 10)%, \(kb($sM))/\(kb($sT)) KB) │ Game \(pct($gM;$gT))% (fuzzy \(($g.fuzzy_match_percent * 10 | round) / 10)%, \(kb($gM))/\(kb($gT)) KB) │ overall \((.measures.matched_code_percent * 100 | round) / 100)%"
' "$REPORT")

if [ -z "$line" ]; then
  echo "objdiff: failed to parse report.json"
  exit 0
fi

printf '%s\n%s\n' "$mtime" "$line" > "$CACHE"
printf '%s\n' "$line"
