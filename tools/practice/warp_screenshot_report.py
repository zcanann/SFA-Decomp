"""Collect isolated Dolphin warp captures into a reviewable local gallery.

Arrival-state checks and dark-image flags are smoke-test signals, not evidence
that a room's objects, progression or exits work correctly.
"""
import argparse
import html
import json
import os
from pathlib import Path

from PIL import Image, ImageDraw


def generate(inputs, output):
    output.mkdir(parents=True, exist_ok=True)
    notes_path = output / "visual-notes.json"
    notes = json.loads(notes_path.read_text()) if notes_path.exists() else {}
    cases = {}
    for folder in inputs:
        path = folder / "results.json"
        if not path.exists():
            continue
        for case in json.loads(path.read_text()):
            case = dict(case, capture_folder=str(folder.resolve()))
            key = case["map"], case["spawn"]
            previous = cases.get(key)
            case["previous_attempts"] = (previous["previous_attempts"] +
                                         [{k: v for k, v in previous.items() if k != "previous_attempts"}]
                                         if previous else [])
            cases[key] = case
    rows = []
    for case in cases.values():
        image_path = None
        case["capture_note"] = ""
        for attempt in [case] + list(reversed(case["previous_attempts"])):
            if attempt["screenshot"]:
                image_path = Path(attempt["capture_folder"]) / attempt["screenshot"]
                if image_path.exists():
                    if attempt is not case:
                        case["capture_note"] = "Latest attempt produced no image; showing the preceding capture."
                    break
        case["image_path"] = str(image_path) if image_path else None
        case["arrival_check"] = (case["settled"] and case["state"]["map"] == case["map"]
                                 and case["state"]["fade"] <= 0 and case["frames_advanced"] > 0)
        case["mostly_dark"] = None
        case["visual_note"] = notes.get(f'{case["map"]}/{case["spawn"]}', "")
        if image_path and image_path.exists():
            with Image.open(image_path) as im:
                pixels = list(im.crop((0, 70, im.width, im.height - 40)).convert("L").getdata())
                case["mostly_dark"] = sum(p < 8 for p in pixels) / len(pixels) > .985
        rows.append(case)
    rows.sort(key=lambda c: (c["map"], c["spawn"]))
    (output / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
    cards = []
    for case in rows:
        title = f'{case["map"]:03d}/{case["spawn"]:02d}: {case["name"]}'
        if case["label"]:
            title += " — " + case["label"]
        image_path = Path(case["image_path"]) if case["image_path"] else None
        src = html.escape(Path(os.path.relpath(image_path, output)).as_posix(), quote=True) if image_path else ""
        status = "Load/fade completed; playability unverified" if case["arrival_check"] else "Load/fade failed"
        if case["visual_note"]:
            status += "; see visual finding below"
        if case["mostly_dark"]:
            status += "; image mostly dark"
        cards.append(f'<article><h2>{html.escape(title)}</h2><p>{status}</p>'
                     + (f'<p>{html.escape(case["visual_note"])}</p>' if case["visual_note"] else '')
                     + (f'<p>{case["capture_note"]}</p>' if case["capture_note"] else '')
                     + (f'<a href="{src}"><img loading="lazy" src="{src}"></a>' if src else '<p>No capture</p>')
                     + f'<details><summary>Recorded state</summary><pre>{html.escape(json.dumps(case["state"], indent=2))}</pre></details></article>')
    document = '''<!doctype html><meta charset="utf-8"><title>Practice v1.14 warp captures</title>
<style>body{background:#111827;color:#e5e7eb;font:16px system-ui;margin:24px}main{display:grid;grid-template-columns:repeat(auto-fit,minmax(360px,1fr));gap:20px}article{background:#1f2937;padding:12px}h2{font-size:17px}img{width:100%}pre{white-space:pre-wrap}input{padding:10px;margin-bottom:20px;width:300px}</style>
<h1>Practice v1.14 warp captures</h1>
<p>Isolated Dolphin D3D capture sweep. The harness queues the retail reload after minimal Fox setup; cases share save state within each run. Load/fade completion is NOT a passing warp: empty voids and fallback models can satisfy it. Usability requires visual and movement/exit testing. Collision overlays retain their release defaults.</p>
<p>Click an image for the full capture. Empty/unused maps, missing room groups, wrong character assets, black screens and invalid arrivals need separate review.</p>
<input placeholder="Filter map or spawn" oninput="document.querySelectorAll('article').forEach(a=>a.hidden=!a.textContent.toLowerCase().includes(this.value.toLowerCase()))">
<main>''' + "\n".join(cards) + "</main>"
    (output / "index.html").write_text(document, encoding="utf-8")
    for start in range(0, len(rows), 20):
        sheet = Image.new("RGB", (1200, 1040), "#111827")
        draw = ImageDraw.Draw(sheet)
        for i, case in enumerate(rows[start:start + 20]):
            x, y = (i % 4) * 300, (i // 4) * 208
            path = Path(case["image_path"]) if case["image_path"] else None
            if path and path.exists():
                with Image.open(path) as im:
                    im.thumbnail((300, 185))
                    sheet.paste(im, (x, y))
            label = f'{case["map"]}/{case["spawn"]} {case["label"] or case["name"]}'
            draw.text((x + 3, y + 188), label[:43], fill="white")
        sheet.save(output / f"contact-{start // 20 + 1:02d}.jpg")
    print(f"{len(rows)} cases; {sum(bool(c['image_path']) for c in rows)} screenshots; "
          f"{sum(c['arrival_check'] for c in rows)} loads/fades completed (not playable-warp passes); "
          f"{sum(bool(c['mostly_dark']) for c in rows)} mostly-dark flags")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate(args.inputs, args.output)
