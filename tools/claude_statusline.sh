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

# Game-side bucketing: every non-auto, non-SDK unit name maps to exactly one
# bucket below, and the bucket totals sum to the existing "game" category's
# total_code — so no retagging of the report is needed.
#   Engine  — main loop + object system (objlib/objanim/objhits/...)
#   Render  — graphics (shader, lightmap, tex/track/rcp/pi_dolphin, ...)
#   Audio   — main/main/audio/synth_*
#   Track   — main/track/intersect (collision)
#   Modes   — minigames / world setpieces (worldplanet, spellstone, ...)
#   DLL     — everything under main/main/dll/ (most of the game)
#   Unsplit — main/main/unknown/autos/placeholder_* (not yet split into TUs)
line=$(jq -r '
  def pct(b; t): if t == 0 then 0 else (b * 1000 / t | round) / 10 end;
  def kb(n):     (n / 1024 | round);
  def cat(id):   (.categories[] | select(.id == id) | .measures);
  def bucket(n):
    if   (n | startswith("main/main/dll/"))     then "DLL"
    elif (n | startswith("main/main/audio/"))   then "Audio"
    elif (n | startswith("main/main/unknown/")) then "Unsplit"
    elif (n | startswith("main/track/"))        then "Track"
    elif (n | test("^main/main/(crcloudrace|crfueltank|dfplightni|dfppowersl|platform1|proximitymine|proximitymine_init|spellstone|worldasteroids|worldplanet)$")) then "Modes"
    elif (n | test("^main/main/(expgfx|light|lightmap|newshadows|rcp_dolphin|shader|tex_dolphin|track_dolphin|pi_dolphin|maketex)$"))                              then "Render"
    elif (n | test("^main/main/(main|objanim|objhits|objHitReact|objlib|objprint|objprint_dolphin|expr|timer|textblock)$"))                                       then "Engine"
    else "Other" end;

  cat("sdk")  as $s
  | cat("game") as $g
  | ($s.total_code   // "0" | tonumber) as $sT
  | ($s.matched_code // "0" | tonumber) as $sM
  | ($g.total_code   // "0" | tonumber) as $gT
  | ($g.matched_code // "0" | tonumber) as $gM
  | ([.units[]
      | select(.metadata.auto_generated != true)
      | select(.name | startswith("main/dolphin/") or startswith("main/Runtime") | not)
      | {b: bucket(.name),
         t: (.measures.total_code   // "0" | tonumber),
         m: (.measures.matched_code // "0" | tonumber)}]
     | group_by(.b)
     | map({b: .[0].b, t: (map(.t) | add), m: (map(.m) | add)})) as $bs
  | (["Engine","Render","Audio","Track","Modes","DLL","Unsplit","Other"]
     | map(. as $name | ($bs[] | select(.b == $name)) // empty
                      | "\(.b) \(pct(.m;.t))%")
     | join(" · ")) as $game_breakdown
  | "SDK \(pct($sM;$sT))% (fuzzy \(($s.fuzzy_match_percent * 10 | round) / 10)%, \(kb($sM))/\(kb($sT)) KB) │ Game \(pct($gM;$gT))% [\($game_breakdown)] │ overall \((.measures.matched_code_percent * 100 | round) / 100)%"
' "$REPORT")

if [ -z "$line" ]; then
  echo "objdiff: failed to parse report.json"
  exit 0
fi

printf '%s\n%s\n' "$mtime" "$line" > "$CACHE"
printf '%s\n' "$line"
