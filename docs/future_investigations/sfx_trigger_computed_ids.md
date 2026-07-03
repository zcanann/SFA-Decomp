# Computed / data-driven SFX trigger IDs (not statically nameable)

**Status:** deferred — not blocked by game progress. These are the call sites the
`SFXTRIG_*` naming pass (`include/main/audio/sfx_trigger_ids.h`) deliberately left
as raw values, because the trigger id is **computed at runtime** (read from object
state, level data, or a lookup table) rather than being a literal. Each needs
either (a) naming the underlying **table** entries, or (b) a live-debugger read to
confirm which trigger fires.

> Count note: earlier summaries said "~36"; the accurate figure from the id-argument
> parser is **20 sites**. (The 36 was a loose grep that also matched `*(`/`[` in
> *other* arguments, e.g. `(u32)obj` casts and position args.)

## Why this is interesting
These are exactly the **data-driven SFX systems** — the sound isn't hard-coded at
the call, it comes from level/trigger data, object placement fields, or an id
table. Naming the *source* (the table or the field) is more valuable than the call
site, and reveals how each subsystem picks its sound.

## The sites

### A. Lookup tables (resolve by naming the table's entries)
The id indexes a table of trigger ids. Find the table's data (it's `SFXTRIG_*`
values), then define the table with named constants — that names every call through it.

| file:line | function | expression | table |
|---|---|---|---|
| `src/main/dll/dll_000F_unk.c:96` | PlayFromObject | `(u16)sfxTable[idx]` | `sfxTable` |
| `src/main/dll/dll_000F_unk.c:109` | PlayFromObject | `(u16)sfxTable[idx]` | `sfxTable` |
| `src/main/dll/dll_00E2_staff.c:1212` | PlayAtPositionFromObject | `(u16)((s16*)lbl_803208A0)[idx]` | `lbl_803208A0` |
| `src/main/dll/dll_0138_groundanimator.c:553` | PlayFromObject | `(&lbl_803DBDF0)[placement->sfxIndex]` | `lbl_803DBDF0` |
| `src/main/dll/dll_0272_hightop.c:352` | PlayFromObject | `(u16)(&gHighTopMovementSfxIds)[idx]` | `gHighTopMovementSfxIds` |
| `src/main/dll/dll_0242_dbstealerworm.c:1224` | PlayFromObject | `lbl_80329640[1]` | `lbl_80329640` |

### B. Object / placement state fields (id stored per-object)
The id is a field on the object's runtime/placement struct. Trace where the field
is written (level data load, or a setter) to name it; or read live in-game.

| file:line | function | expression |
|---|---|---|
| `src/main/dll/CF/dll_012A_cfcrate.c:315` | PlayFromObject | `*(u16*)(tbl + r)` |
| `src/main/dll/dll_00DA_pollenfragment.c:111` | PlayFromObjectLimited | `(int)*(short*)state[7] & 0xffff` |
| `src/main/dll/dll_0132_waterfallspray.c:100` | KeepAliveLoopedObjectSound | `state[0] & 0xffff` |
| `src/main/dll/dll_0132_waterfallspray.c:101` | KeepAliveLoopedObjectSound | `state[1] & 0xffff` |
| `src/main/dll/drcloudcage.c:457` | PlayFromObject | `*(u16*)(state + 0x440)` |
| `src/main/dll/player.c:16084` | PlayFromObject | `*(u16*)((char*)*(int*)((char*)inner + 0x40c) + 0x2a)` |
| `src/main/objprint.c:1887` | PlayFromObjectChannel | `*(u16*)((char*)p2 + 0x14)` |
| `src/main/objseq.c:1743` | IsPlayingFromObject | `(u16)((ObjSeqState*)seq)->sfxId[3]` |
| `src/main/objseq.c:1745` | SetObjectSfxVolume | `(u16)((ObjSeqState*)seq)->sfxId[3]` |

### C. Big-endian u16 unpacked from level/command data
The id is assembled from bytes in level trigger data or ObjSeq commands — the value
lives in the map/sequence data, not the code. Confirm by reading that data live.

| file:line | function | expression |
|---|---|---|
| `src/main/dll/dll_0126_trigger.c:179` | StopFromObject | `(u16)((entry[2] << 8) \| entry[3])` |
| `src/main/dll/dll_0126_trigger.c:356` | PlayFromObject | `(u16)((p[2] << 8) \| p[3])` |
| `src/main/dll/dll_0126_trigger.c:360` | StopFromObject | `(u16)((p[2] << 8) \| p[3])` |
| `src/main/objseq.c:2464` | PlayFromObject | `(u16)(*(s16*)(cmd + 2) & 0xfff)` |
| `src/main/objseq.c:2468` | PlayFromObject | `(u16)(*(s16*)(cmd + 2) & 0xfff)` |

## How to resolve
- **Category A (tables):** dump each table's data (from `orig/` DOL/DLL data via
  `dtk`, or read live RAM with the Dolphin MCP), convert each entry to its
  `SFXTRIG_*` name (values are the same trigger-id namespace), and redefine the
  table with named initializers. That names all A-sites at once.
- **Category B/C (fields & level data):** these are genuinely data-driven; the
  "name" depends on the object instance / map. Best handled with the **live Dolphin
  debugger** — breakpoint the call, read the resolved id, and cross-reference
  `sfx_trigger_ids.h` to confirm the sound in that context. Useful for verifying the
  data path, not for a static rename.

## Reference
- Trigger-id namespace + names: `include/main/audio/sfx_trigger_ids.h`
- Underlying sounds: `include/main/audio/sfx_ids.h` (complete 828 MusyX SFX)
- Trigger table source: `orig/GSAE01/files/audio/data/Sfx.bin` (32-byte records)
