# `source_layout.py`

This pass closes the workflow gap between `source_worklist.py`, `source_gap_windows.py`, and `source_blueprints.py`.

Those tools already told us:

- which retail-backed anchors are worth splitting now
- which short anchor-to-anchor gaps can be decomposed into per-file EN windows
- which anchors belong in one local neighborhood

What they did not give directly was one address-ordered file list that interleaves both anchor files and estimated short-gap files into a first-pass source skeleton.

## Tool

- `python tools/orig/source_layout.py`
  - starts from the same retail EN source anchors as `source_worklist.py`
  - reuses `source_gap_windows.py` for per-file sizing inside short gap packets
  - flattens both into one ordered per-file layout per local neighborhood
  - keeps coverage warnings explicit when the windows leave a gap or overlap

## Why It Helps

- It gives a worker one concrete file order to walk instead of switching between anchor reports and gap reports.
- It makes it obvious when a retail-backed neighborhood already tiles cleanly in current EN text.
- It leaves unresolved packets visible as placeholders instead of pretending the whole neighborhood is solved.

## Output Shape

Each block is one local EN neighborhood. Inside the block:

- `anchor` rows come from retail-backed source tags and the current best planned window.
- `gap-window` rows come from `source_gap_windows.py` and represent missing files between two anchors.
- `gap-packet` rows are unresolved placeholders when a packet exists but does not yet have stable per-file windows.

## Typical Usage

- `python tools/orig/source_layout.py`
- `python tools/orig/source_layout.py --search expgfx modgfx curves`
- `python tools/orig/source_layout.py --search objanim objhits`
- `python tools/orig/source_layout.py --format csv`
- `python tools/orig/source_layout.py --format json`

## Reading The Result

- Start with blocks that report coverage `tiled`; those are the cleanest first-pass skeletons.
- Use `anchor` rows to claim or resize retail-backed files.
- Use the interleaved `gap-window` rows to sketch the missing files between those anchors.
- Treat `gap-packet` rows as unresolved neighborhoods that still need better naming or sizing evidence.

## Relationship To Other Tools

- Use `source_worklist.py` when you want ranked anchor actions.
- Use `source_gap_windows.py` when you want the per-file estimates for one short gap packet.
- Use `source_blueprints.py` when you want neighborhood blocks and packet context.
- Use `source_layout.py` when you want one ordered file skeleton that merges those answers into the next split plan.
