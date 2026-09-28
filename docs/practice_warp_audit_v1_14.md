# Practice v1.14 warp capture audit

The sweep covered all 107 catalog presets across 61 maps, using isolated
Dolphin D3D profiles and the exact ISO packaged as V1.14. A captured image is
available for every case. Dragon Rock Bottom's latest fresh-boot repeat
produced no image; its earlier black capture is retained and labeled.

The local review gallery is `build/practice/warp-audit-report/index.html`.
Its `results.json` retains previous attempts, final map/fade/frame observations,
capture locations and visual notes. Six contact sheets provide a quick overview.
Raw captures live in `build/practice/warp-screenshots-v14`, the `-high` sibling
and the `-rechecks` sibling. Diagnostic profiles did not use the user's saves.

## What the test establishes

The harness starts from a minimal Fox setup, queues the retail transition and
practice reload, waits for the requested map and fade completion, then captures
rendered frames. Presets share state within a serial run. A stall restarts the
emulator before proceeding; cases blocked by a preceding stall were retried.
Andross, DIM Top, Dragon Rock Bottom, LinkD, LinkF and LinkH were also checked
from independent fresh boots.

This bypasses menu interaction and its unavailable-state checks. It does not
establish that every forced serial transition is permitted by the real menu,
nor that every room's progression, collision, exits or objects work. Captures
show that cutscene/camera state can carry between forced serial warps. The
latest arrival metadata passes for 102 cases; this is **not** a count of 102
fully working warps. Visual failures can pass the map/fade check.

## Findings

- All nine Magic Cave entrance contexts render with Fox's proper model after
  retaining the source area's resource bank. The preceding build rendered Fox
  as fallback colored geometry. Return IDs, acts, reward selection and resource
  banks are also covered by compiled-PPC checks; cave exit interactions have
  not all been playtested.
- Andross flight still renders the Arwing as fallback colored geometry,
  including on a fresh boot. Other flight courses show their Arwing model.
- Dragon Rock Bottom stalls during the black fade, including on a fresh boot.
- DIM Top's preset does not stay at its intended arrival in the minimal fixture:
  the fresh run ends with map -1; the serial run ended at MazeTest. Its capture
  shows fallback geometry. It needs further entry/preset investigation.
- LinkD, LinkF and LinkH render from fresh boots. They stalled on forced serial
  transitions from LinkC, LinkE and LinkG respectively. This does not establish
  that the menu can issue those same transitions; the original LinkD report
  remains incompletely resolved.
- Unused Duster Cave, unused LinkK and Great Fox stall on black in this fixture.
- Dragon Rock Top, VFP spawn 2, Walled City spawn 1 and LightFoot spawn 3 show
  little or no world geometry. Other captures show displaced or carried-over
  cameras. These remain follow-ups, not clean passes.
- LinkA shows large fallback colored geometry. Unused maps often show only Fox
  against an empty background.

The five latest map/fade failures are DIM Top (19), Dragon Rock Bottom (52),
Duster Cave (55), LinkK (64), and Great Fox (65). Prior serial failures remain
in the report even when a fresh-boot retry passes.

## Rebuilding the gallery

```powershell
python tools/practice/warp_screenshot_report.py `
  build/practice/warp-screenshots-v14 `
  build/practice/warp-screenshots-v14-high `
  build/practice/warp-screenshots-v14-rechecks `
  --output build/practice/warp-audit-report
```

The report tool uses Pillow. `visual-notes.json` in the output directory keeps
manual observations separate from the automatic arrival and image-darkness
checks. Dark-image detection is only a review aid, not a correctness test.
