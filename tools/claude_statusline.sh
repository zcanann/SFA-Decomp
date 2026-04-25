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
  def isSDK:  startswith("main/dolphin/") or startswith("main/Runtime.PPCEABI.H") or startswith("main/track");
  def isAuto: startswith("main/auto_");
  def code(u):    (u.measures.total_code   // "0" | tonumber);
  def matched(u): (u.measures.matched_code // "0" | tonumber);
  def fuzzy(u):   code(u) * ((u.measures.fuzzy_match_percent // 0) / 100);
  def pct(b; t): if t == 0 then 0 else (b * 1000 / t | round) / 10 end;
  def kb(n):     (n / 1024 | round);

  [.units[] | select(.name | isSDK)] as $sdk
  | [.units[] | select((.name | isSDK | not) and (.name | isAuto | not))] as $game
  | ([$sdk[]  | code(.)]    | add // 0) as $sT
  | ([$sdk[]  | matched(.)] | add // 0) as $sM
  | ([$sdk[]  | fuzzy(.)]   | add // 0) as $sF
  | ([$game[] | code(.)]    | add // 0) as $gT
  | ([$game[] | matched(.)] | add // 0) as $gM
  | ([$game[] | fuzzy(.)]   | add // 0) as $gF
  | "SDK \(pct($sM;$sT))% (fuzzy \(pct($sF;$sT))%, \(kb($sM))/\(kb($sT)) KB) │ Game \(pct($gM;$gT))% (fuzzy \(pct($gF;$gT))%, \(kb($gM))/\(kb($gT)) KB) │ overall \((.measures.matched_code_percent * 100 | round) / 100)%"
' "$REPORT")

if [ -z "$line" ]; then
  echo "objdiff: failed to parse report.json"
  exit 0
fi

printf '%s\n%s\n' "$mtime" "$line" > "$CACHE"
printf '%s\n' "$line"
