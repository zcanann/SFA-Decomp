# Glitch candidates in shared game code

Code audit, started 27 September 2026; streaming/unload audit updated 9 October
2026. The original findings retain their numbers. Later entries concentrate on
the Thorntail Hollow reload leak and ways that failed cleanup can cross a fixed
capacity into memory corruption.

These are **code findings and proposed tests, not emulator-confirmed glitches**.
“Retail checked” means the relevant instructions were inspected in the original
DOL. Other findings follow the current decompilation. None is a claim of novelty
relative to the speedrunning scene.

The focus is behavior shared between versions. The known respawn-gamebit and
quit-to-title persistence tricks are omitted, as are the findings already covered
in [the version-specific catalog](version_specific_glitches.md). Map placement
checks use the available **JP v1.0 assets**; addresses below are **EN v1.0** unless
stated otherwise. A map having enough objects does not prove they can all be
loaded or moved into the required arrangement.

## S01 — Too many carryables on one object corrupt its collision state

**Confirmed unchecked write; gameplay setup still needed.**

A resting carryable adds itself to the object it is standing on. That object's
contact list holds three pointers. The carryable code ignores the limit: a fourth
entry overwrites the platform's collision bookkeeping, including the count used
for the next entry. Further writes can consequently land much farther away.

**Test:** put four resting barrels or other carryables on the **same object-backed
floor or platform**. Ordinary map terrain does not meet the condition. Watch the
supporting object's contact count while adding the fourth object. The list resets
during updates, so this needs simultaneous contacts, not four separate visits.

Dragon Rock (`dragrock`) has eleven gunpowder-barrel placements; Warlock Mountain
(`warlock`) has six. These are places to scout for a suitable shared support,
not established repro locations. Moon Mountain Pass (`moonpass`) also has three
moon rocks and a gunpowder barrel, though moving all four onto one support may be
impractical.

The first overwrite is solid. A crash, bad collision, or further corruption depends
on update order and the overwritten pointer bytes. [Code and watches](#code-s01).

## S02 — Collecting a buried item clears a pointer in an unrelated audio table

**Confirmed wrong-address write; likely ordinary gameplay trigger.**

When the game removes a saved object position, it clears a word roughly 128 KiB
beyond the save buffer. In EN v1.0 that word belongs to the audio system. This is
an in-memory write; it does not itself overwrite a memory-card file.

**Test:** dig up and collect a gold bar at **Cape Claw** (`capeclaw`), with a write
breakpoint on `0x803C3400`. The dig-spot code saves the buried item's position,
and collection removes that saved position. The four gold bars have nearby
dig-spot objects in the JP placement data. Buried Alpine Roots in DarkIce Mines
and SnowHorn Wastes are other candidates.

There may be no visible effect: the target is a high-numbered audio-curve slot,
and clearing an unused slot does nothing noticeable. Check whether it contains a
live pointer before treating this as an audio-crash route. The write also needs
the item's ID to be present in the saved-position table; simply collecting an
arbitrary item will usually miss it. [Code and watches](#code-s02).

## S03 — A cutscene may finish mounting Fox without finishing the vehicle

**Interruption lead; the full sequence still needs validation.**

Mounting has two separate pieces of state. Fox tells the vehicle “mounting” at
the start of the animation and “mounted” only at its end. Separately, the player
sequence code has paths that put Fox directly into riding while his vehicle
pointer is still present. Those paths do not perform the vehicle's mount-completion call.

The proposed result is Fox in riding control while a SnowBike remains in its
mounting state. That state does not run normal riding movement, and the bike's
mount-completion gamebit would not be set by the skipped call.

**Test to investigate:** start a pickup cutscene during the mount animation. A
first-time Energy Egg, apple, or Moon Seed sends a pickup-sequence request; the
proximity check uses the vehicle's position when Fox has a vehicle focus. The
CloudRunner Fortress bike is a candidate to scout, not a verified setup.

The sequence must start before mounting completes, leave the vehicle pointer
intact, and take a path that resumes riding. Cleanup itself keeps that pointer,
but other sequence paths return Fox to idle or explicitly dismount him. The
pickup sequence has not yet been shown to take the required riding path.
[Code and watches](#code-s03).

## S04 — Two pickup cutscenes can compete for one pending item

**Concrete state-overwrite lead; an overlapping pickup setup is unconfirmed.**

Fox drains his message queue and stores only one pending pickup object. Each new
pickup request replaces it. The cutscene's collection event later acknowledges
whichever object is currently stored. An earlier item can therefore lose its
acknowledgment after already marking itself as being picked up.

**Test:** arrange to enter the pickup ranges of two *different first-time pickup
types* in one update, such as an apple and an Energy Egg. Watch both request
messages arrive before either collection event. If only the second receives a
reply, check whether the first remains visible but refuses collection until it
unloads.

Two apples are a poor test: the first sets the global “seen apple” bit immediately,
so the second normally takes the direct-pickup path. Ordinary key items also have
button/interaction gates that may serialize requests. The cancellation cleanup
clears the pending pointer without sending a collection reply; it does not repair
the lost acknowledgment. This still needs an overlapping pickup setup in-game.
[Code and watches](#code-s04).

## S05 — Unloading a parent with more than forty attached objects overflows a stack list

**Unchecked write confirmed in EN retail; no qualifying parent established.**

When a collision-bearing parent unloads during play, the engine gathers its
placed child objects into a temporary list of forty pointers. It scans the whole
object list without stopping at forty. A forty-first qualifying child writes
outside that list, on the stack.

**Test to investigate:** count objects parented to a moving map or ship, then
unload that parent while those children are still present. The relevant relation
is the objects' transform parent, not the small accessory/held-object list.

This needs more than a busy room: all forty-one objects must share the same
parent and have placement records. Full object-system resets can skip this
cleanup path, so quitting to title is not an established trigger. The galleon
objects are worth inspecting for ownership, but no ship is claimed to satisfy
the count. [Code and watches](#code-s05).

## S06 — Model caches can exceed their tables or free data still in use

**Unchecked cache append confirmed in EN retail; no practical setup established.**

There are three separate thresholds worth watching when trying to keep unusual
numbers of objects loaded:

| Condition | What goes wrong |
| --- | --- |
| More than 140 distinct cached models | New cache entries exceed the model table. |
| More than 196 distinct cached animations | New cache entries exceed the animation table. |
| 257 live references to one model, followed by a release | Its byte-sized reference count can reach zero while other users remain. |

There is also a signed-count problem for shared animations: with 129 references,
releasing one leaves 128, which the release check treats as negative and frees.
These references come from model animation loading, not simply from spawning
129 instances of one already-cached model.

**Test to investigate:** watch cache occupancy and reference counts during an
object-duplication or streaming-retention setup. There is no evidence here that
ordinary backtracking alone grows either cache indefinitely: freed entries are
reused. The thresholds establish failure conditions, not a normal-play repro.
[Code and watches](#code-s06).

## S07 — Contact callbacks can survive removal of their object

**Faulty removal confirmed in EN retail; ordinary gameplay reachability is weak.**

Removing an object's contact callbacks swaps the last callback into a vacated
slot, then advances past that slot without checking it. With multiple callbacks
involving the same object, one can remain registered after that object is freed.
Later cleanup can then touch the old object pointer.

**Test conditions:** remove an object with two registered callbacks, or fill all
sixteen callback slots and remove an object whose callback is not the last entry.
The full-table case has a separate mistake that skips the replacement copy.
Confirm a remaining callback still names the destroyed object before looking for
heap-reuse effects.

The source caller found during this pass registers a surface-crawling enemy
against the player. Its DLL has confusing inherited names, and I did not establish
a placed retail instance or a player-replacement route that leaves those enemies
alive. This is a real cleanup defect to keep on record, not a ready gameplay
glitch. [Code and watches](#code-s07).

## S08 — A light-effect copy changes the first byte of a neighboring global

**Out-of-bounds byte copy confirmed in EN retail; visible effect may be absent.**

The light-effect emitter copies one byte beyond its 40-byte action record.
When the destination is the global cache, that byte belongs to the next global:
the first pointer in the CloudRunner prison target list.

Two `LFXEmitter` placements exist in the **RedEye King arena** (`trexboss`) in
the JP assets. That gives a place to inspect the emitter, but does not establish
that the prison target list is active at the same time. With that list unused,
the stray write may have no gameplay effect. [Code and watches](#code-s08).

## S09 — Vambats cannot take one intended attack-abort path

**Dead condition in the source; lower-impact AI behavior.**

The Vambat attack code includes a line-of-sight check that would abort an attack
when the route back toward its path point is obstructed. A precedence mistake
makes the condition guarding that check always false.

**Test:** lure an attacking Vambat around an obstruction and see whether it keeps
trying to pursue until contact or its attack timeout. This does not establish
that it can pass through walls: other collision checks remain. The bug is also
already noted in a source comment, so this entry records it rather than claiming
a new discovery. [Code](#code-s09).

## S10 - The deferred-free list silently abandons every object after entry 399

**Source- and runtime-confirmed cleanup failure; the observed Thorntail Hollow
growth is this bug.**

During the object-capture phase, `Obj_FreeObject` removes an object from the live
and update lists and marks it freed before putting it on a 400-pointer deferred
list. When insertion makes the count equal 400, the code immediately decrements
the count back to 399. Slot 399 is therefore outside the later cleanup loop.
Every additional free overwrites that same excluded slot and is likewise never
destroyed.

The abandoned object loses much more than its object allocation. Its DLL free
callback, model and texture releases, message queue, effects, type-group removal,
sequence cleanup, and hosted-map cleanup are all in the destructor that never
runs. This fits both observations in Thorntail Hollow: a visibly duplicated mana
crystal is one retained object, while the near-full heap reflects all of the
unreleased subsidiary allocations and resources behind many such objects.

An EN v1.0 Dolphin snapshot taken after approximately seven camera reload cycles
confirmed **342 complete `GameObject` allocations** that had the `0x40` freed bit
set, were absent from the 453-entry live object list, and were nevertheless still
allocated. Their object records alone occupied `0x61C40` bytes (400,448 bytes),
before counting any resources whose releases were skipped. The total is almost
exactly seven losses of about 49 objects. Since an overflowing flush retains only
399 entries, that is consistent with reload batches of roughly 448 objects.

The leaked set was not plant-specific. Its largest repeated cohorts included 52
`BlueFlowerP`, 43 `MagicDustMi`, 30 `LongGrassCl`, 21 `MagicDustLa`, 17
`SH_BeaconTw`, 15 `AppleOnTree`, 13 `BullRushClu`, 13 `MCLightning`, and many
others. Three leaked `MagicPlant` records remained registered, but they were only
three of the 342 abandoned objects. Thirty-one abandoned objects in total still
occupied object-type groups; most object classes do not join those groups and
therefore cannot be seen through the visible registry stacking alone.

The same snapshot establishes why the reported heap loss can look enormous.
Normal `mmAlloc` calls use regions 0-2, and all three had reached the allocator's
descriptor refusal threshold: `249/250`, `849/850`, and `849/850` slots. The
allocator rejects a region when `slotsUsed + 1 == numSlots` *before* searching
for a fitting free block. It therefore rejected every ordinary allocation even
though those regions still contained `0x2FEEF0` bytes (about 3.0 MiB) free in
total. Region 3 was separately at 98.53% byte usage (`529/580` slots). This is
primarily allocation-record exhaustion plus retained resource data, not a single
plant or a conventional contiguous-byte heap fill.

A clean EN v1.0 savestate gave a controlled per-direction measurement. The
first camera reload abandoned 53 objects (`0x10740` bytes of object records),
and the return reload abandoned another 44 (`0x15640` bytes), for 97 retained
objects and `0x25D80` bytes of object records after one round trip. Net used
bytes across normal regions 0-2 rose by `0x1F300` (127,744), while descriptor
use rose by 6, 55 and 22 slots respectively. The difference between object-byte
growth and net heap growth is expected because the reload also frees unrelated
ordinary allocations. The dropped tail is direction-dependent: the first leg
contained the three Magic Plants and one Fuel Cell, while the return leg
contained the unusually large `0x93C0`-byte Thorntail NPC plus two
StaffActivated objects. This also explains why alternating both directions is
materially worse than repeatedly measuring only one edge.

**Test:** a normal memory watch on `gObjDeferredFreeCount` at EN `0x803DCB94`
will commonly show zero: `Obj_FlushDeferredFreeList` clears it after the batch.
Break or log inside `Obj_FreeObject` to catch the same-frame attempted transition
from 399 to 400 and immediate return to 399. Alternatively, after a reload scan
allocated object records for `objectFlags & 0x40` and exclude pointers still in
`gObjList`; those freed-but-allocated records are persistent proof of dropped
destruction. [Code and watches](#code-s10).

## S11 - A ninth simultaneously retained romlist page overwrites map-layer state

**Unchecked fixed-table append; directly aligned with camera-driven map reloads.**

The ordinary streaming path records active romlist pages in eight
`ShaderRomListSlot` entries. It reuses a null entry, but if all current entries
are occupied it increments the count and writes the next entry without checking
the eight-entry capacity. A ninth page writes eight bytes immediately beyond the
table, over the first two `gMapBlockCellStateTables` pointers.

This threshold is more promising than general heap exhaustion because the
corruption target is deterministic and belongs to the system being manipulated.
It could change which layer/cell state table receives later writes, although a
bad pointer is more likely to crash than produce stable movement tech.

**Test:** during the Thorntail camera loop, watch `gShaderRomListSlotCount` and
the eight entries at EN `0x8038224C`. Record the distinct page slots rather than
only the count. Break before the store when all eight entries are non-null; the
next write targets `0x8038228C`. [Code and watches](#code-s11).

## S12 - A forty-first hosted sub-map performs several deterministic overwrites

**Unchecked hosted-map allocation; Thorntail Hollow has a concrete carrier.**

Some placed objects load a second map page through a model field. Hosted pages
have forty reserved slots, 80 through 119. If all are occupied,
`mapLoadForObject` continues with slot 120 instead of failing. It first writes
the hosted map ID one byte past `gExtendedMapActLookup`, into
`saveData.optionsValid`. It then builds romlist index 120 beyond the
120-element index table. That destination aliases the beginning of
`gLoadedRomListPages`, so the new page's index data overwrites live page
pointers. It finally updates object groups using the invalid slot.

The JP retail placements give Thorntail a specific route: `hollow2` contains an
`SH_boulder` whose model hosts map 93, `dimpushblock`. The hosted page is tiny,
so repeated failure to run that carrier's destructor is a plausible way to fill
the forty slots without the earlier allocations alone exhausting the heap.
Wall City, the temple, Cape Claw, the fortress and the wastes also contain many
hosted-map carriers, but simultaneous reachability has not been established.

**Test:** watch `gLoadedRomListPages[80..119]` (EN
`0x803865A8..0x80386647`) and each carrier's `anim.hostedMapSlot`. First prove
that a boulder reload consumes a second hosted slot after the previous instance
is abandoned. On the forty-first retained load, break at `mapLoadForObject` with
slot 120. The one-byte save-options write occurs before the larger index-table
smash. [Code and watches](#code-s12).

## S13 - A sixty-fifth resident map block writes beyond three heap arrays

**Unchecked resident-block append; plausible secondary threshold in an OOB
camera reload.**

The map system allocates arrays for exactly 64 resident block pointers, IDs and
reference counts. Loading a new distinct block scans for a free ID slot. If none
exists it increments the byte-sized count and unconditionally writes index 64.
The warning is also off by one for practical purposes: it is printed when the
count becomes 64, while index 63 is still valid, then execution continues.

**Test:** watch `gMapBlockCount` at EN `0x803DCE98`, plus the three allocated
array bases. Distinguish 64 loaded references from 64 distinct occupied slots.
The corrupting case is the next new block when no `gMapBlockIds` entry is `-1`.
[Code and watches](#code-s13).

## S14 - CloudRunner Fortress has a cross-layer stale main-crystal pointer

**Concrete use-after-free design; camera/unload setup still needs runtime proof.**

The main-crystal DLL has two instances at almost the same X/Z position but in
different retail romlist records. The layer-4 instance is the position source;
the layer-5 instance is the beam controller. Each source update publishes its
object through `gCfMainCrystalPositionObject`. Its free callback releases
particle effects but never clears that global.

Once the controller has received the source position, any active pylon makes it
dereference the global every update and pass that object to the particle system.
If camera manipulation can unload the source record while retaining the
controller record, this is a direct dangling-object read and downstream object
use. Heap churn after the unload may let a replacement allocation control some
of the consumed fields; without reuse it may merely keep working on freed memory.

**Test:** in `fortress`, manipulate the layer boundary near
`(-1616, 1920..1992, -977)`. Watch the two placement IDs `0xAE7` (variant 1,
position source) and `0xAE8` (variant 0, controller), the global pointer, and
`GAMEBIT_CF_PowerOn`/the three pylon timers. Confirm the source actually reaches
`objFreeObjdef` while the controller remains active, then check the dereference
in `cfMainCrystal_updateBeams`. [Code and watches](#code-s14).

## S15 - Retained Fuel Cells can overflow a nine-pointer render stack array

**Unchecked stack append with a plausible failed-cleanup amplifier.**

An active Fuel Cell registers in object-type group `0x4F`. Its renderer searches
that group for every other eligible cell within 100 units and appends matches to
a local nine-pointer array with no capacity check. The tenth nearby match writes
past the stack array. Retail stack layout substantially lowers the finding's
value, however: the first overruns hit scratch space, and even the first saved
register corruptions propagate through render functions that do not use those
registers. The first clear control-flow target is the saved return address at 36
nearby candidates, where it is replaced by a Fuel Cell heap pointer and should
normally crash.

Ordinary placements appear to form clusters of only two or three. The deferred
free failure changes the arithmetic: skipped Fuel Cell destruction also skips
its explicit group removal, and group queries do not discard objects merely
because their freed flag is set. Repeatedly abandoning and reloading the same
cluster could therefore feed stale nearby objects to a still-rendered cell. JP
placements contain 16 Fuel Cells in `hollow`, 14 in `wastes`, eight in `temple`
and five in `capeclaw`; local distances still need checking.

**Test:** log group `0x4F` membership and the number of qualifying neighbors at
the renderer's append. Record thresholds 10, 18, 21, 25 and 36. Verify that stale
entries retain valid `extra` storage; if the full destructor ran, this specific
chain does not apply. [Code and watches](#code-s15).

## S16 - Retained Magic Plants can turn staff interaction into type confusion

**Mechanically valid downstream effect, but the tested Thorntail route exhausts
the allocator well before the registry wraps.**

The live object-type registry has room for 256 pointers, but its count is an
eight-bit value. The supposed `count >= 256` guard can therefore never succeed.
On insertion 256 the count wraps from `0xFF` to zero and the insertion algorithm
starts overwriting existing memberships. Every group boundary is also an
eight-bit value, so later group queries eventually keep a plausible small count
while returning an entirely different slice of valid object pointers.

The observed Thorntail Magic Plant duplication is a direct feeder. Every plant
registers once in group `0x34` and once in `0x3E`; its free callback removes both
memberships. An object abandoned by S10 never calls that callback, so each
retained plant advances the registry and every later group boundary by two. TTH
contains eleven `MagicPlant` placements in `hollow` and five in `hollow2` in the
available retail placement data. The first total-count wrap requires at most 128
new retained plants and less if ordinary live objects have already populated the
registry.

The seven-cycle EN runtime capture substantially weakens this as a practical
route. At the point every normal allocation region had already stopped accepting
allocations, the registry count was only 162. It contained 13 distinct Magic
Plants (26 memberships), of which only three plants were abandoned rather than
live. The type registry was still internally consistent. Reaching 256 through
the same loop therefore requires a way to delay/reverse allocator descriptor
exhaustion, or a reload boundary whose dropped tail is much richer in grouped
objects. Without that additional primitive, the game should hit null allocation
failures first.

The useful consumer is Player's group-`0x41` StaffActivated scan. Once that
group's start offset wraps, `objGetAllOfType(0x41)` can return unrelated live
objects. Player does no DLL/type check: an aliased object whose interaction byte
passes `(flags & 0x14) == 0x04` and whose placement byte at `+0x1C` happens to be
2, 3, 4, or 5 produces an A prompt and becomes `gPlayerInteractTarget`.

That is not merely a bad lookup. Pressing A can:

- snap Fox's X/Z and facing relative to fields read from the wrong object,
  making a displacement or clip the least destructive result;
- in mode 2, repeatedly write lift height and a reset byte through the wrong
  object's `extra` pointer at offsets `+0x14` and `+0x1C`; or
- in mode 3, treat the wrong placement halfword at `+0x24` as a game-bit index
  and clear or set that bit during the lever animation, while also writing the
  mirror flag through the wrong `extra` pointer at `+0x1D`.

The aliased object and therefore the displacement, allocation damage, or bit
index depend on the exact registry contents. This is not yet a claimed arbitrary
game-bit write. It is a narrow runtime search: find the first false StaffActivated
member that passes the two byte tests, then inspect its placement `+0x1C/+0x24`
before pressing A. [Code and watches](#code-s16).

## S17 - A retained StaffBoulder can become a persistent warp anchor

**Runtime-confirmed stale-object warp and reward path; preserving the useful
interaction flag without a memory edit still needs a natural setup.**

The return half of the controlled TTH reload abandoned a `StaffBoostPad` and a
mode-2 `StaffBoulder`. Their DLL destructor normally removes them from object
group `0x41`; S10 skipped it. Both objects therefore remained allocated and in
the group even though they were absent from `gObjList`. Fresh copies loaded as
well. This does not require the S16 registry wrap or type confusion: all of the
pointers and layouts are still valid DLL-284 objects.

Player scans the raw group every frame, trusts each object's byte `+0xAF`, and
does no current-distance check. A mode-2 object with bit `0x04` set and bit
`0x10` clear becomes the interaction target. Pressing A enters the lift-rock
state; its setup calls `staffactivated_calcInteractionTargetXZ`, which directly
replaces Fox's X/Z and facing with coordinates derived from the retained
object. Because a dropped object is no longer in `gObjList`, the normal
per-frame clear of low interaction bits never touches it. Thus, if the boulder
is abandoned while its in-range bit is set, that bit should remain set after
Fox moves away and act as a persistent teleport back to the boulder's
interaction point.

The player state itself advances the stale object's lift height and eventually
calls `staffactivated_spawnMapEventDebris`; it does not require the boulder's
normal update to remain scheduled. The tested TTH boulder has scarab-set 2 and
count 2 (two gold scarabs), but its map-event identity gates the contents, so
this is not a duplication primitive. The stale and fresh copies share the same
placement pointer and therefore the same `base.ident`; completing the stale
copy consumes the map-event reward. Runtime testing produced its two scarabs,
then lifting the visible fresh replacement produced nothing. The movement
primitive is more interesting: one camera unload could preserve a return anchor
across geometry or traversal, provided the camera can cross the streaming
boundary while Fox is close enough to that boulder.

In the paused two-reload snapshot, the stale boulder is `0x812791A0`, registry
slot 116, mode 2, at `(-5398.161, -776.930, -3031.942)`. Its interaction byte at
`0x8127924F` is currently `0x00`, so this particular natural attempt was made
out of range. Temporarily changing that byte to `0x04`, unpausing, and pressing
A proved the mechanism: Fox flew horizontally across the map to the interaction
point while retaining his airswim height, the invisible stale lift completed,
and two scarabs spawned. The stale state's lift height finished at `0x800` while
the fresh copy remained at zero. A natural repro must instead arrange for
`+0xAF & 4` at the moment this same object falls into the dropped tail. [Code and
watches](#code-s17).

For the natural test, first stand within the boulder's ordinary prompt radius
and confirm object byte `+0xAF == 0x04`. Keep Fox in place and cross the
streaming boundary using camera zoom/angle alone. On the successful bad flush,
the original pointer must disappear from `gObjList` but remain in group `0x41`
with object flag `0x40` and interaction byte `0x04`. The prompt should then
remain available at arbitrary distance. This distinguishes a genuinely frozen
range flag from merely approaching the fresh replacement after reload.

No TTH liftable rock is currently known to be close enough to a usable camera
streaming boundary to perform that setup while remaining in range. Nor can the
flag be armed afterward: `camcontrol_findBestTarget` enumerates `gObjList` and
explicitly rejects `OBJECT_OBJFLAG_FREED`, so approaching the fresh replacement
cannot retarget the abandoned copy. Consequently the warp is a confirmed engine
primitive but **not presently a natural speedrun setup**. A viable route needs a
new camera-OOB position near a mode-2 object, a way to keep the camera target
latched through its unload, or another StaffActivated mode that is both near a
boundary and useful.

The other TTH group-`0x41` candidates in the measured state include a mode-3
object at `(-6714.145, -716, -940.454)` whose lock bit is `0x140`
(`SH_FirstMagicCaveFound`) and a mode-4 `StaffLeverO` at
`(-4620.136, -795, -3507.510)` tied to bit `0x2B2`
(`SH_OpenedGateToCape`). Mode 3 uses the same direct X/Z snap and can toggle its
placement game bit, but neither object was abandoned by the tested reload and
no boundary setup is claimed for either one.

## S18 - Activate a carryable on its unload frame

**Concrete natural test; not yet runtime confirmed. This is distinct from the
StaffBoulder interaction-byte experiment.**

Changing a retained object's interaction byte to `0x04` cannot by itself make
it grabbable. `0x04` means only that the camera interaction scan considers the
object in range. Generic carryables require `INTERACT_FLAG_ACTIVATED` (`0x01`),
then their own update sends message `0x100008` to Player. `SmallBasket` similarly
sends `0x100010` from its own update. S10 casualties have already been removed
from the update list, and camera targeting excludes freed objects, so an idle
retained basket cannot begin a grab through the StaffBoulder method. Even if a
latched camera pointer sets `0x01` once after the unload, no remaining object
update consumes it.

The promising timing is to stand in grab range, begin the camera-OOB transition,
and press A on the final frame before the page unload. `gameUpdate` applies the
camera's A-button activation before `Obj_UpdateAllObjects`; the still-live
basket can therefore enter its carry state and queue its grab message. Pending
map loads and the streaming free pass run later in the frame. This can free the
basket after it has initiated the grab but before or after Player consumes the
queued message, depending on object/message order.

Player stores the message sender's raw object pointer at `PlayerState + 0x7F8`.
Once the pickup finishes, Player's render routine moves that object to Fox's
hand coordinates and invokes its render callback directly. Streaming ownership
nevertheless remains the object's original `mapEventSlot`, and the page-unload
loop has no held-object check.

`Obj_FreeObject` marks the object freed and removes it from `gObjList` and the
update list, but it does not clear Player's held pointer. This creates two
outcomes worth separating:

1. If the held object is one of the overwritten deferred-free tail entries, its
   allocation and destructor-owned state survive. Fox should retain a valid
   pointer to a freed-but-allocated carryable and may continue rendering it.
2. If it is in the portion that the flush actually destroys, Player retains a
   dangling pointer. A later same-size allocation may alias the held pointer;
   Player's render path then writes positions/rotation into the replacement and
   calls the callback interface selected through that memory. This is more
   dangerous and may simply crash, but it is the higher-impact result.

The measured bad snapshot already proves two TTH `SmallBasket` placements land
in the lost post-capacity tail: pointers `0x81328FC0` at
`(-4334.462, -889.097, -3636.569)` and `0x8132A680` at
`(-4056.540, -995.764, -3335.512)` remained allocated, absent from `gObjList`,
and registered in group `0x10`. Thus this is not merely hoping a random held
object survives; these exact placements survived the tested reload direction.
The first placement is subtype 3 (gold scarab), respawn 255 minutes, leash 512;
the second is subtype 4 (no content-spawn switch case), respawn zero, leash 455.
Runtime scouting subsequently found both baskets just outside the range from
which the known camera-OOB transition can be produced. They remain proof of the
mechanism and useful savestate targets, but neither is currently a natural setup.

Start clean at whichever of those baskets permits the camera boundary setup.
Hold the camera transition immediately short of unloading, confirm its byte
`+0xAF == 0x04`, then try A on successive frames around the transition. Watch
Player `extra +0x7F8`, the basket's flag word `+0xB0`, its `mapEventSlot` byte
`+0xAC`, `userData2` at `+0xF8`, and membership in `gObjList` / group `0x10`.
The success state is: Player's held pointer names that same object, flag `0x40`
is set, it is absent from `gObjList`, and its allocation/group membership remain.
Then let the page reload and test drop, throw, and break behavior against the
fresh copy. A press one frame too late should only freeze `0x05` on a dead
object; a press too early should complete a normal pickup. A non-tail result is
expected to be a dangling-pointer crash and is not the target. [Code and live
probe](#code-s18).

The immediate payoff is limited. Once released, the stale basket still has no
update tick, so its throw physics and break/content code do not advance. While
held, however, Player positions and renders it directly and the basket's leash
logic never runs. This tests persistent carry beyond the source page and may
create a stale/fresh pair, but it does not yet establish repeatable contents or
a useful Any% skip.

## S19 - Unload SnowHorn's Tricky controller, then dig into Magic Cave early

**Retail-backed command, unload and zone-entry chain; the trigger crossing still
needs a clean-console runtime pass.**

The `NW_tricky` controller's destructor unconditionally sets
`GAMEBIT_Tricky_Unlocked_Sidekick_Commands` (`0x4E4`) to one. It does not check
whether the Wastes SharpClaws were defeated or whether the command lesson was
completed. That master bit is sufficient for Tricky's command mask to include
Find Secret and Stay; neither command separately checks the lesson-item bit.

This should be tested without heap exhaustion. Load the controller before
finishing the SharpClaw/sidekick-command lesson, confirm `0x4E4` is clear, then
make the controller unload by leaving its romlist page, warping or exiting the
map, or by any death/reload path that runs ordinary object destruction. If its
destructor runs, `0x4E4` should become one and the Tricky command ring should
immediately expose Find and Stay. This may skip the combat/teaching sequence or
permit early use of command-gated objects, depending on which exits are open at
that point in the route.

There is now a concrete retail route rather than only a generic unload proposal.
The two trigger planes at `wastes.romlist` records 11 and 17 are only about 90
world units apart. Record 11's enter leg shows object group 1; record 17's exit
leg hides object group 1. `NW_tricky` is a group-1 placement. Backtracking across
that room boundary after the controller has loaded should therefore run
`nwTricky_free`; crossing back in reloads the group, but the fresh controller has
no branch that clears the accidentally granted master bit at this story state.

The immediate payload is a real early zone transition. A group-1
`GroundAnima` at `(3732.02, -131.00, 1569.05)` is a pure terrain/story-bit dig:
it is always enabled, has no buried collectible, and sets
`GAMEBIT_NW_MagicCaveVisible` (`0x113`) when Tricky finishes Find. The
`MagicCaveTo` only 10.93 units away reads that same bit. It loads Magic Cave,
selects act 1 / reward group 0, and warps through WARPTAB entry `0x57`; the
return is SnowHorn entry `0x67`. This is the normal SnowHorn magic-capacity cave
being opened before the combat/command lesson that is supposed to grant Find.

A minimal route test is therefore: enter far enough to load group 1 and
`NW_tricky`; reverse across the record-17 plane and confirm the controller's
destructor raises `0x4E4`; cross record 11 back into the room; walk to the dig
patch and issue Find; confirm `0x113` rises; then touch the revealed entrance.
If the room geometry makes the intended leg of record 17 awkward, a death or
full-map unload remains a fallback, but it is no longer the first experiment.

The timing caveat is useful rather than incidental. Before
`GAMEBIT_ITEM_TrickyStayFind_Got` (`0x544`) is obtained, a freshly loaded
controller has no branch that clears `0x4E4`. After that item bit is set, an
unfinished controller clears the master command bit every update while Tricky
is not playing ball. The cleanest test therefore leaves the controller **before
receiving Stay/Find**, and avoids reloading it afterward until the route has used
the early commands.

Do not combine the first test with S10. If `NW_tricky` is one of the abandoned
post-399 deferred frees, its destructor never runs and the unlock is not granted.
EN v1.0's controller is the `wastes.romlist` placement at offset `0x38FC`,
position `(4351.59, -153.27, 915.83)`, load flags `0x10`, group 1. Break on
`nwTricky_free` at EN `0x801CF7C0` to distinguish a real unload from merely
hiding or disabling the controller. [Code and watches](#code-s19).

## S20 - Move a patrol Thorntail to a streaming seam, then unload it mid-sequence

**Player-known positioning setup closes the reachability gap; audited payload is
low-value so far.**

A known staff-hit timing can displace one patrolling `SH_thorntai` during its
animation and make it walk to essentially arbitrary positions, including a TTH
map edge. This supplies something the stock placements did not: Fox can remain
in hit/talk range of a live Thorntail while the camera is poised to unload its
romlist page.

Every retail Thorntail placement has load flag `0x10`. Its current coordinates
therefore do not distance-unload it; the relevant event is disabling its object
group or unloading the source page. Start a talk sequence at the seam, then send
the camera OOB on the same update. In an ordinary unload, object destruction
ends the sequence immediately. In an S10 overflow, a Thorntail placed after the
399 retained entries is removed from the live list but never destroyed, so its
sequence can continue against the valid but abandoned allocation while a fresh
copy reloads.

The current payload audit is deliberately negative. All 65 sequence-map entries
owned by `SH_thorntai`, across both cast actors, were checked in the JP TTH
`ANIMCURV` data. None uses the direct map-warp or gamebit-set/clear sequence
actions. The sequence actor attaches to the old Thorntail at frame zero; it does
not re-resolve to the fresh copy after reload. Tricky also discards a Thorntail
follow pointer on the next update when it sees the object's freed flag. These
facts rule out the simplest fresh-copy wrong warp, reward duplication and
long-lived Tricky-target theories.

The remaining test is narrower: determine whether repeated start/unload/reload
can overlap dialogue slots, leave camera/input state behind, or produce a useful
sequence cancellation. Watch the Thorntail's `seqIndex`, object flag `0x40`,
membership in `gObjList` and group `0x4D`, and the global path-owner ident. A
normal unload should hit `SHthorntail_free` and end the slot. An S10 casualty
should miss that function, remain in group `0x4D`, and keep its old sequence
state until the sequence ends independently. This is worth one controlled test,
but the code no longer supports treating it as a likely progression skip.

## S21 - Retarget the fifth Krazoa return onto the sixth pedestal

**Potential endgame flag from the wrong pedestal; controlled pointer proof first,
natural streaming setup still missing.**

The six Warlock Mountain spirit pedestals share one object type. During the K5
return sequence, a normal player-alignment rewind clears the sequence actor's
target and asks the generic resolver for a live object of that type again. If K5
has just been removed from the live list while its sequence survives, the nearest
eligible replacement is K6. The sequence callback operates on the replacement
object, not on the pedestal that originally started it.

That is unusually valuable because K6's own next update writes `0xCB7`, the
retail "Spirit 6 Released / Andross Revealed" bit. A separate sequence-point
controller then raises its ready bit, and the Transporter accepts the sixth
spirit's Got, Released, **or** Ready state. In other words, this is not merely a
wrong animation: the candidate's payload is the final-spirit transport condition.

S10 supplies the theoretical lifetime mismatch: K5 can leave `gObjList` without
its destructor ending the active sequence. What remains unproven is a natural
Warlock streaming arrangement that makes K5 one of the abandoned deferred-free
tail while K6 and the sequence actors stay alive. Validate the retarget and bit
write with a controlled live-list removal before spending time manufacturing
the 400-object state in route. [Code and watches](#code-s21).

## S22 - Abort Ice Mountain cinematics after their callback and bank completion

**Small state-machine race with rescue/race progression payload; usable abort
primitive not yet found.**

Ice Mountain's `IMMultiSeq` callback arms a pending-completion flag on every
callback tick, but the controller cannot consume it while the sequence actor is
attached because that actor suppresses its ordinary update. If the sequence can
be ended after the first callback while the controller remains loaded, its next
update writes the milestone even though the cinematic did not finish.

The same controller owns the entered-hut, rescued-Tricky and race-started bits.
The latter two can chain: an aborted rescue sequence writes its completion bit
and immediately satisfies the condition that starts the race sequence; aborting
that one can then write race-started. The missing ingredient is a reachable
sequence cancel or actor/controller streaming split that leaves the controller
alive for its following update. [Code and watches](#code-s22).

## S23 - Overflow the live map-block tables at Dragon Rock's landing area

**Natural camera crossing performs deterministic writes beyond three live
streaming arrays; runtime payload is the next target.**

The map loader has room for 64 unique blocks, but it loads the new camera
neighborhood before releasing the old one. Dragon Rock Top contains ordinary
adjacent camera cells whose temporary union is 65 to 67 unique blocks. The
landing-area crossing from grid center `(-22,17)` to `(-21,17)` needs 66 and
writes slots 64 and 65 beyond all three arrays.

Those writes alias the beginning of the following allocations: new block
pointers replace old block IDs, new IDs replace old reference counts, and new
reference counts replace bytes in the map-info buffer. Returning across the
boundary should then reload blocks whose identities were destroyed and extend
the corruption. This is the first candidate in this audit with both a normal
player-controlled setup and a direct OOB write; the open question is whether
repeated crossings yield useful missing/stale collision or only a crash.
[Code, exact boundaries and watches](#code-s23).

## Technical appendix

### Code S01

- [Carryable_updateHeld](../src/dlls/engine/47/47.c) directly appends to
  `hit->anim.hitboxTransformState->contactObjects`, without a limit or duplicate
  check. [ObjHits_AddContactObject](../src/main/objhits.c) has both protections,
  but this caller bypasses it.
- [ObjHitboxTransformState](../include/main/objhits_types.h) has three pointers
  at `+0x100`, then `activeMatrixIndex`, `resetFrames`, padding and the signed
  contact count at `+0x10C..+0x10F`. The fourth pointer overwrites these four bytes.
- On this big-endian machine, an object pointer beginning `0x80` changes the
  matrix index to `0x80`; its last byte becomes the new contact count. The next
  insertion sign-extends that count. It need not write immediately after the
  fourth entry. Matrix refresh can mask the index back into range, so a later
  invalid matrix access depends on timing.
- EN function: `0x800EA9BC`; unchecked pointer store: `0x800EAC24`. At that
  store, `r29` is the carryable. Obtain the support's state through its object
  pointer at `+0x58`; watch state `+0x10C` as a word and `+0x10F` as a byte.
- Retail checked: EN v1.0/v1.1, JP v1.0, and PAL v1.0/v1.1 all contain the
  unchecked append.

### Code S02

- [saveGame_unsaveObjectPos](../src/dlls/engine/23/23.c) searches 63 saved
  positions and compacts the matching entry away. Its final store uses
  `SAVEGAME_OBJECT_POSITION_DIRTY_OFFSET = 0x20158`, beyond the `0xF70`-byte save
  object. Clearing the last position's ID would instead require offset `0x548`.
- EN save buffer: `0x803A32A8`; write target: `0x803C3400`. The target is
  `dataCurveTable + 0x3188`, the pointer field of audio-curve entry **1585**.
  [MusyX data tables](../src/musyx/runtime/data_tables.c) use eight-byte entries.
  `dataCurveNum` is a `u16` at `0x803DE28A`; an active count of 1585 or fewer puts
  the target outside the active prefix. The store leaves the entry's ID and
  reference count unchanged.
- EN function: `0x800E8168`; bad store: `0x800E8368`. Break on the target address to distinguish a real
  saved-position removal from an early return. Dynamically owned placement data,
  a nonzero save-load status, or no matching saved ID bypasses the write.
- [GroundAnimator_update](../src/dlls/objects/312_GroundAnima/GroundAnima.c)
  positions the buried collectible through
  [collectible_setPosition](../src/dlls/objects/237/237.c), which saves its position.
  `collectible_applyPickup` removes the saved position when it has a hide gamebit.
- JP Cape Claw gold-bar records: romlist offsets `0x5668`, `0x56C0`, `0x5718`,
  `0x5770`; IDs `0x47C0A`, `0x47C1B`, `0x47C1D`, `0x47C1F`. Their corresponding
  dig-spot records are at `0x5698`, `0x56F0`, `0x5748`, `0x57A0`.
- Retail checked: EN v1.0/v1.1, JP v1.0, and PAL v1.0/v1.1 all contain the
  wrong-address store. The audio-table identification above is for EN v1.0.

### Code S03

- [playerStateMountBike and player_SeqFn](../src/dlls/objects/195_Player/player.c):
  the mount handler calls `setMountState(VEHICLE_Mounting)` on entry and
  `setMountState(VEHICLE_Mounted)` after `moveDone`. At `movementState == 5`, the
  sequence callback calls player `setState(..., 0x18)` if `focusObject != NULL`.
  However, when `endFlag == 0`, that same call subsequently sets state 1. The
  riding result requires the nonzero `endFlag` branch, or a different riding
  event such as event 4. Event 3 explicitly completes mounting; event 2 dismounts.
- `playerRestoreAfterSequence` clears interaction and collision overrides but
  neither clears `focusObject` nor completes the vehicle's mounting state.
- [SnowBike_setMountState and SnowBike_update](../src/dlls/objects/597/597.c):
  state 2 performs riding setup and sets `completionGameBit`. The update switch
  has idle and riding cases, with no movement case for mounting state 1.
- [collectible_checkProximityPickup](../src/dlls/objects/237/237.c) chooses the
  focus object's position and sends `0x7000A` for the relevant first pickups.
  `playerProcessMessages` starts pickup sequence 0 without a mount-state check.
  `Obj_IsParentSlackClear` checks the player's `OBJECT_OBJFLAG_PARENT_SLACK` bit.
- Watch vehicle extra-state byte `+0x421` (`SnowBikeState.mountState`), Fox's
  extra `+0x7F0` (`focusObject`), and his control mode. The required mismatch is Fox riding while
  the bike still reports 1. No retail or runtime confirmation of that sequence yet.

### Code S04

- [playerProcessMessages](../src/dlls/objects/195_Player/player.c) drains the
  queue; each `0x7000A` replaces `triggerGameBitPtr` and `interactObject` and calls
  `runSequence(0, player, -1)`. The return value is ignored.
- In `player_SeqFn`, event 1 sends `0x7000B` only to the current `interactObject`,
  then clears it. [collectible_checkProximityPickup](../src/dlls/objects/237/237.c)
  sets the pickup latch and first-seen bit before that acknowledgment.
- [ObjSeq_start](../src/dlls/engine/2/2.c) ends an existing sequence on its
  owner before replacing it. `endObjSequence` calls registered cleanup callbacks
  synchronously. The player's `playerRestoreAfterSequence` clears `interactObject`
  without sending `0x7000B`; the collectible's free callback also sends no reply.
  If the first sequence has not run its player callback yet, that cleanup may not
  be installed, but the second request still overwrites the pending pointer.
- Watch each collectible's `pickupLatch` at extra `+0x37`, the player's
  extra `+0x684` (`interactObject`), and messages `0x7000A`/`0x7000B`. Count requests and replies
  per object; a switched camera or animation alone does not prove lost collection.

### Code S05

- [objFreeObjdef](../src/main/object.c) declares `int defs[40]`, appends every
  qualifying child with `defs[count++]`, then frees the collected children.
- Conditions: parent's model has `OBJDEF_FLAG_HITBOX_GROUP`, cleanup `flag == 0`,
  child `anim.parent == parent`, and child `placementData != NULL`.
- EN function: `0x8002BE88`. Break there and count matching live objects before
  stepping the collection loop. The first source-level out-of-bounds index is 40.
  A full reset can call this function with flag 1 and avoid the loop entirely.
- Retail checked in EN: the list starts at `r1 + 8`, and the unchecked indexed
  store is at `0x8002BFBC`. Do not assume its first overrun immediately hits the
  return address; intervening stack contents matter.

### Code S06

- [allocModelStruct and modelInitModelList](../src/main/modelEngine.c) allocate
  a fixed-capacity list, then append without comparing against `capacityEnd`.
  Entries contain a two-byte ID and a four-byte pointer. A write beyond the table
  may initially fall in allocator padding; it is not necessarily an immediate
  overwrite of another allocation.
- [ObjModel_InitResourceCaches](../src/main/model.c) uses capacities `0x8C` and
  `0xC4`. EN globals holding the list pointers: `gModelList = 0x803DCB54`,
  `gModelAnimCacheList = 0x803DCB50`. Inspect `entries`, `end`, and `capacityEnd`
  using [ModelList](../include/main/model_engine.h).
- `ObjModel_Load` increments the cached model header's byte at offset zero.
  `ObjModel_Release` frees on decrement to zero. At 256 references the stored
  count is zero, so a release wraps to 255; **256 then one release is not the
  premature-free case**. At 257 it is one, so a release reaches zero.
- Animation release instead tests `(s8)--animation->refCount <= 0`.
  Establish actual ownership/counts through `modelLoadAnimations`; many instances
  sharing one model header do not each reload its animations.
- Retail checked in EN: `modelInitModelList`, `0x80013CE8`, appends without
  consulting `capacityEnd`. The reference-count thresholds above follow source;
  their load/release instructions have not been independently checked here.

### Code S07

- [ObjContact_RemoveObjectCallbacks](../src/main/objlib.c) decrements both the
  global count and its loop counter after a match, copies the last entry over the
  removed one, then increments the entry pointer. With `[A-P, B-P]`, removing P
  leaves one callback referencing P. It also skips the copy when the resulting
  global count equals 15, a separate boundary case in the same routine.
- EN removal function: `0x80037E44`; callback array: `0x80342D50`, sixteen
  12-byte records; count begins at `0x803DCBF8`. Each record contains object A,
  object B, and callback pointers. A stale registration does not execute its
  callback automatically: dispatch still requires a matching object pair.
- Both removal mistakes were checked in EN retail instructions.
- The direct registration caller found is
  [DLL 211](../src/dlls/objects/211/211.c), `dll_D3_update`. Its `LandedArwing_*`
  function names are not evidence that this is the landed Arwing object.

### Code S08

- [LFXEmitter_copyLightAction](../src/dlls/objects/301_LFXEmitter/LFXEmitter.c)
  copies byte `+0x28` as well as the action's actual `0x28` bytes.
- EN function: `0x8018FF48`; global cache: `0x803AC7B0`; stray destination byte:
  `0x803AC7D8`, the high byte of `gCloudPrisonTargets[0]`.
- EN retail contains the extra byte load at `0x80190030` and store at `0x80190034`.
- The action's heap allocation is rounded up, so copying into a heap action is
  not by itself proof of crossing an allocator block. The global-cache boundary
  is the relevant concrete overrun. Active use of the neighboring list is unproven.

### Code S09

- [vambat_updateEngaged](../src/dlls/objects/202/vambat.c):
  `if (!bs->controlFlags & 0x01000000)` evaluates as
  `(!bs->controlFlags) & 0x01000000`, always zero.
- EN function: `0x80153248`. The alternative aborts on contact and elapsed
  `timeDelta` total above 360 remain. That number is a game-timing threshold,
  not a claim of 360 rendered frames on every video mode.

### Code S10

- [Obj_FreeObject](../src/main/object.c) marks the object freed at line 1268,
  then appends it to `gObjDeferredFreeList` during capture mode 2. Lines
  1302-1305 store the pointer, increment the count, and decrement it again when
  it reaches `OBJ_DEFERRED_FREE_CAPACITY` (400).
- The later cleanup loops only over indices below `gObjDeferredFreeCount`.
  Consequently index 399 is never visited, and each subsequent overflowing free
  replaces that excluded pointer with another object that has already been
  removed from normal engine lists.
- The skipped [objFreeObjdef](../src/main/object.c) path owns the DLL free
  callback, object-type removal, hosted-map unload, model and texture releases,
  message/effect cleanup, and the final object allocation free. This accounts
  for heap growth much larger than the visible duplicated object.
- EN watches: `gObjDeferredFreeCount = 0x803DCB94`; dereference
  `gObjDeferredFreeList` at `0x803DCB98` and watch pointer index 399.
- A zero count after the frame is expected: [Obj_FlushDeferredFreeList](../src/main/object.c)
  destroys only indices below the retained count and then stores zero to the
  counter. The overflow casualties remain recognizable because `Obj_FreeObject`
  already set their `OBJECT_OBJFLAG_FREED` bit and removed them from `gObjList`.
- EN allocator regions begin at `gMmRegionTable = 0x803406A0`. Each 20-byte
  region record is `{numSlots, slotsUsed, start, size, usedBytes}`. In the
  captured TTH state regions 0-3 respectively read `249/250`, `849/850`,
  `849/850`, and `529/580` descriptor slots. [mmAllocFromRegion](../src/main/mm.c)
  returns null immediately at `capacity - 1`, without considering free bytes or
  whether an exact-fit allocation would need another descriptor.
- The captured type registry remained structurally valid at 162 memberships:
  group `0x34` and `0x3E` each contained the same 13 distinct Magic Plants, ten
  live and three freed-but-allocated. This validates S10 without yet reaching
  the separate S16 byte-count wrap.

### Code S11

- [mapProcessRomList](../src/main/shader.c) scans the active prefix of
  `gShaderRomListSlots`, increments `gShaderRomListSlotCount` if no null entry
  exists, and unconditionally writes the selected index. It has no comparison
  with the declared eight-entry capacity.
- EN layout: `gShaderRomListSlots = 0x8038224C`, size `0x40`;
  `gMapBlockCellStateTables = 0x8038228C`, size `0x14`. Entry eight therefore
  overwrites the first two four-byte layer-table pointers.
- Unload compacts only trailing null slots. An abnormal retained entry in the
  middle can keep the active prefix wide even after other pages disappear.

### Code S12

- [mapLoadForObject](../src/main/shader.c) searches exactly forty hosted slots,
  starting at `0x50`. If none is free, the loop exits with `slot == 0x78` and
  continues through `setMapActLut`, `mapBuildRomListIndex`, and
  `updateObjGroups`.
- [SaveGame_setMapActLut](../src/dlls/engine/23/23.c) indexes a forty-byte table
  with `slot - 0x50`. Slot `0x78` writes index 40. EN layout places
  `gExtendedMapActLookup` at `0x803A319C`, size `0x28`, immediately before
  `saveData` at `0x803A31C4`; the written byte is `SaveData.optionsValid`.
- EN `gMapRomListIndexes` starts at `0x803822C8` and occupies exactly
  `120 * 0x8C = 0x41A0` bytes. Index 120 begins at `0x80386468`, exactly the
  address of `gLoadedRomListPages`. The page index builder can consequently
  replace several live page pointers before `updateObjGroups` runs.
- The hosted-page array itself spans `0x80386468..0x80386647`; slots 80-119 are
  `0x803865A8..0x80386647` (inclusive byte ranges).
- `objFreeObjdef` unloads `obj->anim.hostedMapSlot`. Reaching the deferred-free
  failure first leaves the hosted slot occupied and makes repeated carriers a
  direct route toward this threshold.

### Code S13

- Shader initialization allocates 64 elements each for `gMapBlocks`,
  `gMapBlockIds`, and `gMapBlockRefCounts`.
- [trackLoadBlockEnd](../src/main/shader.c) scans the current prefix for an ID of
  `-1`. With no hole it increments `gMapBlockCount`, reports only when the new
  count equals 64, and still writes all three arrays at the old count index.
  Thus the warning accompanies the valid index-63 insertion; the next insertion
  is the first source-level overflow at index 64.
- EN globals: `gMapBlockRefCounts = 0x803DCE8C`, `gMapBlockIds = 0x803DCE94`,
  `gMapBlockCount = 0x803DCE98`, and `gMapBlocks = 0x803DCE9C`. The three arrays
  themselves are heap allocations and must be followed through these pointers.

### Code S14

- [CFMainCryst.c](../src/dlls/objects/331_CFMainCryst/CFMainCryst.c) assigns
  `gCfMainCrystalPositionObject` every update of variant 1. Its free callback
  only calls `freeSource`; it never nulls the global.
- The variant-0 controller caches the source coordinates after a message, but
  active-pylon rendering still reads the global object's X/Z at lines 178-180
  and passes the global object to `partfx->spawnObject` at lines 186-188.
- JP retail `fortress` records: object definition `0xE1`, placement `0xAE7`,
  position `(-1615.078, 1991.597, -976.719)`, layer/record 4, tail starts
  `00 01` (yaw 0, variant 1); placement `0xAE8`, position
  `(-1616.383, 1920.241, -977.430)`, layer/record 5, tail starts `00 00`
  (yaw 0, variant 0).
- EN global: `gCfMainCrystalPositionObject = 0x803DDB10`. A valid repro must
  show the variant-1 object completing `objFreeObjdef` while variant 0 continues
  updating; merely marking it freed during deferred capture leaves its backing
  allocation alive and is not the same use-after-free.

### Code S15

- [FuelCell_render](../src/dlls/objects/291_fuelCell/fuelCell.c) declares
  `GameObject *candidates[9]`. It appends every eligible group-`0x4F` object
  within squared distance 10000 without checking `candidateSlot`.
- [FuelCell_free](../src/dlls/objects/291_fuelCell/fuelCell.c) explicitly removes
  an active cell from group `0x4F`. The deferred-free failure prevents this
  callback from running.
- [objtype.c](../src/main/objtype.c) group queries return raw registry pointers;
  they do not test the object's freed flag. Therefore abandoned but allocated
  cells remain candidates. The corrupting append is the tenth eligible neighbor
  of the cell being rendered, not ten total objects including itself.
- EN retail uses a `0xA0`-byte frame and places the candidate array at `r1+0x18`.
  Candidate indices 9-16 occupy padding and arithmetic scratch. Indices 17-19
  overwrite saved `r23-r25`, but the complete `FuelCell_render -> objRender ->
  renderObjects -> sceneDraw -> sceneRender -> gameUpdate -> gameLoop -> main`
  return chain does not consume those values. Indices 20-25 overwrite
  `r26-r31`; the immediate render wrapper either replaces them or only uses them
  for the rendered object's staff-child loop. In particular, index 24 changes
  that loop's object from the current Fuel Cell to another valid Fuel Cell.
- Candidate index 35, requiring 36 eligible neighbors, overwrites the saved LR
  at `r1+0xA4`. The stored value is necessarily a matching `GameObject*`, not a
  chosen code address. Treat this as a crash threshold unless runtime evidence
  shows an unusually stable data-as-code path.
- JP placements give natural TTH clusters of three cells within 100 units and a
  pair in `hollow2`. Ice Mountain (`newicemount`) has three cells, but its closest
  original pair is about 154 units apart. Repeated retained copies can still be
  coincident, but neither map reaches a meaningful threshold from retail
  placements alone.

### Code S16

- [objAddObjectType](../src/main/objtype.c) compares the byte
  `gObjectTypeListCount` with `0x100`, increments it, then uses the wrapped result
  to drive its pointer-shift loop. It also increments every later byte boundary
  in `gObjectTypeIndices`. `objGetAllOfType` trusts those bytes as the returned
  base and count.
- EN retail confirms the byte behavior: `objAddObjectType = 0x80037200`, count
  load/ineffective comparison at `0x80037220..0x8003722C`, count increment/store
  at `0x8003729C..0x800372A4`, and boundary increments at
  `0x80037398..0x80037430`. EN v1.1, JP v1.0, and both PAL revisions contain
  the same byte load, impossible `0x100` comparison, wrapped store, and byte
  boundary increments.
- EN watches: `gObjectTypeList = 0x803428F8`, `gObjectTypeIndices = 0x80342CF8`,
  and `gObjectTypeListCount = 0x803DCBF0`. StaffActivated start/end bytes are
  `0x80342D39` and `0x80342D3A`.
- [MagicPlant_init](../src/dlls/objects/254_MagicPlant/MagicPlant.c) registers
  groups `0x34` and `0x3E`; [MagicPlant_free](../src/dlls/objects/254_MagicPlant/MagicPlant.c)
  removes both. EN retail init is `0x8017FD84`, with the two registration calls
  at `0x8017FDA8` and `0x8017FDB0`.
- [playerState08](../src/dlls/objects/195_Player/player.c) stores each group-`0x41`
  result into `gPlayerInteractTarget`, tests raw object byte `+0xAF`, and calls
  `staffactivated_getMode` without validating its DLL. EN function:
  `0x802A418C`.
- [staffactivated_calcInteractionTargetXZ](../src/dlls/objects/284/284.c) consumes
  the selected object's position/rotation, placement and `extra` state;
  [staffactivated_setLiftHeight](../src/dlls/objects/284/284.c) writes state
  `+0x14/+0x1C`; [staffactivated_setGameBitMirror](../src/dlls/objects/284/284.c)
  passes placement `+0x24` to `mainSetBits` and writes state `+0x1D`. EN entry
  points are `0x80189F5C`, `0x8018A20C`, and `0x80189BE4` respectively.
- Minimal runtime test: watch `0x803DCBF0` for `0xFF -> 0x00`, then inspect the
  group-`0x41` pointer span beginning at
  `0x803428F8 + 4 * *(u8*)0x80342D39`. Break on the three staff helper entry
  points and reject any call whose target really is DLL 284. For a false target,
  record its object identity, interaction flags, placement `+0x1C`, placement
  `+0x24`, `extra` allocation size, and Fox's before/after coordinates. Testing
  the prompt before the wrap is a useful negative control.

### Code S17

- [staffactivated_init/free](../src/dlls/objects/284/284.c) add and remove every
  DLL-284 instance from group `0x41`. Skipping `staffactivated_free` leaves a
  genuine StaffActivated object in the registry with its placement and extra
  state intact.
- [Obj_ApplyPendingParentLinks](../src/main/object.c) clears interaction bits
  `0..2` only for objects still in `gObjList`. S10 removes its casualties from
  that list before abandoning them, so their last `INTERACT_FLAG_IN_RANGE`
  (`0x04`) value freezes.
- [camcontrol_findBestTarget](../src/dlls/engine/1_camcontrol/camcontrol.c)
  searches the live object list and `camcontrol_isTargetCandidate` rejects the
  freed-object flag. This prevents a leaked object whose frozen byte is zero
  from becoming in-range later merely by revisiting its coordinates.
- [playerState08](../src/dlls/objects/195_Player/player.c) assigns each group
  member to `gPlayerInteractTarget`, tests raw byte `+0xAF` for `(flags & 0x14)
  == 4`, and immediately enters state `0x34` for mode 2 when A is pressed. It
  never recomputes distance to a registry member.
- [playerState34](../src/dlls/objects/195_Player/player.c) initially calls
  `staffactivated_calcInteractionTargetXZ` and writes the returned X/Z directly
  to Fox. Later substates call `staffactivated_setLiftHeight` and
  `staffactivated_spawnMapEventDebris` on the same stale pointer.
- Controlled EN snapshot: group `0x41` occupied slots 105-116. The retained
  StaffBoostPad was slot 105; the retained StaffBoulder was the final slot 116.
  The stale boulder and its fresh copy shared placement data and mode/variant
  values, but the stale pointer had object flag `0x40` and was absent from the
  447-object live list. Its frozen interaction byte was zero in that attempt.
- After changing only that byte to `0x04`, the interaction completed against
  the stale pointer. The post-test snapshot still had the stale object at slot
  116 and outside `gObjList`, with interaction byte `0x04` and lift height
  `0x800`; its fresh copy had lift height zero. Fox was transported to target
  X/Z `(-5371.357, -3015.876)` without a forced Y assignment, and the stale
  object spawned its configured two scarabs. The visible replacement then gave
  no contents, consistent with both copies sharing placement identity and the
  `shouldNotSaveTime` / `addTime` one-shot gate.

### Code S18

- [Carryable_updateHeld](../src/dlls/engine/47/47.c) requires interaction bit
  `0x01` and executes on the carryable's update before sending Player message
  `0x100008`. [SmallBasket_update](../src/dlls/objects/260_SmallBasket/SmallBasket.c)
  likewise owns its pickup state and sends `0x100010`. A stale object removed
  from the update list cannot initiate either path merely from bit `0x04`.
- [gameUpdate](../src/main/gameloop.c) calls camera target feedback before
  `Obj_UpdateAllObjects`, then processes pending map loads and calls
  `Obj_ApplyPendingParentLinks` afterward. This ordering creates the one-frame
  activate/update/queue-message-before-unload window.
- [playerProcessMessages](../src/dlls/objects/195_Player/player.c) stores the
  message sender verbatim at `PlayerState.heldObj` (`+0x7F8`). The player render
  path later writes both local and world coordinates into that object and calls
  its render callback directly while `userData2 == 1`.
- [objShouldUnload](../src/main/shader.c) exempts objects with a pending parent
  or owner, but has no test for Player's held pointer. The surrounding streaming
  loop also unloads objects when their original `mapEventSlot` page disappears
  or is no longer current. Pickup does not change `mapEventSlot`.
- [Obj_FreeObject](../src/main/object.c) removes the object from the live/update
  lists and sets flag `0x40`; it never consults or clears Player's held pointer.
  The class destructor would remove carryable registry memberships, but S10's
  overwritten tail skips that destructor as well.
- [live_dolphin_probe.ps1](../tools/live_dolphin_probe.ps1) reports Player's
  `heldObj`, its live/freed status, DLL/name, map-event slot, `userData2`,
  coordinates and object-group memberships for the boundary test.

### Code S19

- [nwTricky_free](../src/dlls/objects/418_NW_tricky/NW_tricky.c) contains only
  the unconditional `mainSetBits(GAMEBIT_Tricky_Unlocked_Sidekick_Commands, 1)`
  side effect. Its entry points are EN v1.0 `0x801CF7C0`, EN v1.1
  `0x801CFD90`, JP `0x801CF8B0`, PAL v1.0 `0x801CFEF8`, and PAL v1.1
  `0x801CFFE0`; all five retail bodies pass bit `0x4E4` and value one.
- [Tricky_getAvailableCommands](../src/dlls/objects/196_Tricky/tricky.c) builds
  its base mask from Find Secret and Stay whenever bit `0x4E4` is set. The
  separate command-item bits are checked only for Call, Play Ball and Flame.
- The only early clear in `nwTricky_update` is conditional on
  `GAMEBIT_ITEM_TrickyStayFind_Got` (`0x544`). This is why unloading before the
  lesson item is acquired should make the destructor's value persist.
- Retail BITTABLE data places `0x4E4` at
  `gGameBitSaveData + 0x12C`, mask `0x40`. EN's save-data pointer global is
  `0x803DCAE0`. The lesson bit `0x544` and SharpClaw-defeated bit `0xD11` share
  the byte at `gGameBitSaveData + 0x29`, masks `0x02` and `0x20` respectively.
- JP placement evidence: `wastes.romlist + 0x38FC`, raw object `0x31F`, DLL
  418, position `(4351.59, -153.27, 915.83)`, `loadFlags = 0x10`, group 1.
- The natural group boundary is encoded by `wastes.romlist` trigger records 11
  and 17. Record 11 is at offset `0x1F4`, position
  `(4819.74, 22.74, 2066.21)`, and has enter commands `05 13 00 01` (show group
  1) and `05 13 00 0A` (show group 10). Record 17 is at offset `0x374`, position
  `(4861.04, 20.24, 2145.99)`, and has exit command `0A 14 00 01` (hide group
  1). These complete records are byte-identical in JP, EN v1.1, PAL v1.0 and
  PAL v1.1 assets.
- The destination dig is `wastes.romlist + 0x33D8`, raw object `0x1CA`, DLL
  312. Its placement has `sunkGameBit = 0x113`, `enableGameBit = -1`, and
  `disableAutoLink = 1`. [GroundAnimator_update](../src/dlls/objects/312_GroundAnima/GroundAnima.c)
  offers Find when the master command bit is set and writes the sunk bit on
  completion.
- The adjacent entrance is `wastes.romlist + 0x3318`, raw object `0x02E`, DLL
  287, position `(3732.09, -141.65, 1566.59)`. Its retail tail selects object
  group 0, act 1, visible bit `0x113`, Magic Cave map `0x36`, entry WARPTAB
  `0x57`, and exit WARPTAB `0x67`.
- Magic Cave's group-0 `MCUpgradeMa` placement carries collected bit `0x1A6`,
  `GAMEBIT_NW_MagicCaveCollected`. Its sequence callback calls
  `playerAddMaxMagic(..., 0x19)`, establishing the SnowHorn cave's permanent
  magic-capacity reward rather than relying on its room label.
- The controller, both boundary triggers, the dig patch and the entrance records
  are byte-identical across every secondary retail asset set currently present.
  EN v1.0 supplies the matching code path but does not have the extracted
  `orig/GSAE01/files` copy needed for the same byte-for-byte asset comparison.
- `python tools/glitch_mining_probe.py neighbors --version GSAJ01 --map wastes
  --dll 312 --radius 130 --detail` reproduces the dig-to-entrance proximity.

### Code S20

- [SHthorntail_update](../src/dlls/objects/429_SH_thorntai/SHthorntail.c)
  applies hit reactions and animation root motion directly to the object's
  position. Its placement keeps the original `homePosition`, but the leash
  correction only turns an offscreen object back toward home; it does not snap
  the object back. This agrees with the known staff-hit displacement setup.
- All 57 JP `SH_thorntai` placements in `hollow.romlist`/`hollow2.romlist` use
  load flag `0x10`. [objShouldUnload](../src/main/shader.c) handles that flag by
  checking the placement's map-object group, while the surrounding streaming
  loop separately frees it when the loaded romlist page becomes null.
- [Obj_FreeObject](../src/main/object.c) calls `endSequence` when `seqIndex` is
  nonnegative. If S10 abandons the object before destruction, this call and
  `SHthorntail_free` are both skipped. The latter normally clears
  `gSHthorntailPathOwnerIdent` when the unloading placement owns it and removes
  the object from type group `0x4D`.
- Tricky's ambient-activity code can select the nearest member of group `0x4D`,
  but the beginning of Tricky's next update checks `OBJECT_OBJFLAG_FREED`,
  resets its command/activity state and nulls `followObj`. Streaming runs after
  object updates, so there is no later same-frame Tricky update before that
  guard.
- The JP `swaphol/ANIMCURV` scan covered every mapped local sequence and both
  cast actors. None contains `SEQACT_ENVFX` sub-op `0x6` (warp), `0xB` (set
  gamebit), or `0xC` (clear gamebit). The first Thorntail actor toggles its
  target attachment at frame zero, so a leaked sequence retains the old object
  pointer rather than resolving the fresh replacement.
- EN watches: `gSHthorntailPathOwnerIdent = 0x803DBFF8`; group `0x4D` begins and
  ends at bytes `0x80342D45` and `0x80342D46` of the object-type index table.
  `SHthorntail_free = 0x801D5E94`.

### Code S21

- **Route payoff:** this is a candidate for making the K5 turn-in operate on the
  K6 pedestal and raise `GAMEBIT_ITEM_Spirit6_Released` (`0xCB7`, hint name
  "Andross Revealed"). The `WM_seqpoint` at `warlock.romlist + 0x11A0`
  separately watches `0xCB7`, starts local sequence 1 (`0x527`), and on its
  following update sets its disable/ready bit `0xCB8`. The Transporter accepts
  Got, Released, **or** Ready for spirit 6. Success is therefore potentially
  much more valuable than merely changing a shrine visual.
- All six `WM_spiritpl` placements use object type `0x150`. Sequence `0x526`
  (local sequence 0 on the pedestal) creates an override actor whose target type
  is therefore `0x150`. [ObjSeq_resolveTargetObject](../src/dlls/engine/2/2.c)
  selects a previously linked live object first, otherwise the nearest unlinked
  live object of that type.
- The owner actor's Warlock `ANIMCURV` entry is `0x15C2`. It has one override
  opcode (`0x03`) at frame zero, so ordinary forward playback does not provide a
  later detach/reattach. Initial playback does, however, call
  `ObjSeq_RebuildCurveStateToFrame`, which clears `targetObj` and replays that
  override.
- The K5 sequence's player actor (`ANIMCURV` entry `0x15C3`) also attaches at
  frame zero. `player_SeqFn` returns result 1 while it aligns/moves the player.
  [ObjSeq_runBgCmds](../src/dlls/engine/2/2.c) converts the rising nonzero slot
  result into `gObjSeqPendingFrames`; on the following actor tick,
  `ObjSeq_update` rewinds and rebuilds the actor state. That rebuild is a second
  target-resolution opportunity supplied by the normal K5 sequence itself.
- If the K5 pedestal has meanwhile been removed from `gObjList` but its
  destructor was swallowed by S10, its `endSequence` call never occurs. The old
  linked-pair entry is not encountered by the live-list scan, so the rebuilding
  owner actor can choose another pedestal. From the K5 placement at
  `(1496.77, 464.24, 962.01)`, K6 is the nearest other pedestal at about 1,536
  world units; K2 is next at about 1,613. The default resolver therefore favors
  K6 when both are live.
- [WM_spiritplace_SeqFn](../src/dlls/objects/524_WM_spiritpl/WM_spiritpl.c)
  handles sequence event 4 through the object passed to the callback, not the
  object that originally started the sequence. For pedestal idents 2 through 6
  it sets that object's `transitionDelay = 1`. The selected pedestal's next
  ordinary update sets its own placement-defined `sequenceGameBit`; for K6 that
  is `0xCB7`. This update occurs before the cached map-act branch, so a K6 object
  initialized in act 5 can still commit the K6 release bit.
- Required natural setup remains unproven: K5 must be among the overwritten
  deferred-free tail while the sequence actors and a live K6 pedestal survive,
  and the player-result rebuild must occur after K5 leaves `gObjList`. A full
  object-system reset is unsuitable because it also resets the sequence system;
  the candidate needs a streaming/page unload such as the observed OOB reload.
- Fast controlled validation: start K5 sequence 0; identify its dynamic slot;
  after the initial attach, remove only K5 from the live list without calling
  `endSequence`; watch the owner actor enter
  `ObjSeq_RebuildCurveStateToFrame` and break at EN
  `ObjSeq_resolveTargetObject = 0x8008196C`. The returned target must be the K6
  `WM_spiritpl`. Then let event 4 execute and watch byte
  `*(gGameBitSaveData + 0xCA)`, mask `0x01`, change from zero to one. EN
  `WM_spiritplace_SeqFn = 0x801F5690`.

### Code S22

- Ice Mountain's single `IMMultiSeq` placement controls three route milestones:
  completion bits `0x3AE` (entered hut), `0x070` (rescued Tricky), and `0x072`
  (race started), with local sequences `0x0B`, `1`, and `2`.
- [IMMultiSeq_animEventCallback](../src/dlls/objects/276_IMMultiSeq/IMMultiSeq.c)
  sets `IM_MULTI_SEQ_STATE_ADVANCE_PENDING` on every sequence callback tick. It
  does not wait for a particular animation event or the end of the cinematic.
  While the sequence remains attached, however, its actor continually sets the
  controller's `pendingParentObj`; [Obj_UpdateObject](../src/main/object.c)
  skips the controller's ordinary update on that condition. Normal playback
  therefore leaves the completion write armed until the sequence detaches or
  ends, rather than committing it immediately at cinematic start.
- This gives a narrower cutscene-abort test: start the relevant cinematic, allow
  its owner actor to call `IMMultiSeq_animEventCallback` once, then prematurely
  end/free/preempt the sequence **while keeping the `IMMultiSeq` controller
  loaded**. Once the actor no longer suppresses it, the controller's next update
  writes the milestone even though the cinematic did not finish. Unloading the
  controller itself before that update loses the pending state and does not
  write the bit.
- A camera-OOB setup is useful only if it removes/ends the sequence actors while
  the controller stays resident for another update. Moving the camera OOB first
  and unloading the controller before it can start, or unloading the controller
  and its actors together, is not sufficient. Sequence preemption or a narrow
  actor/controller streaming-boundary mismatch is a better primitive to seek.
- The steps can chain. Aborting local sequence 1 commits `0x070`; in the same
  controller update, that newly set bit satisfies step 2's active condition and
  starts local sequence 2. Aborting that second sequence then commits `0x072`.
  Thus one usable premature-end primitive could potentially suppress both the
  rescue/bike cinematic and the race-start cinematic in quick succession.
- EN breakpoints: `IMMultiSeq_animEventCallback = 0x8017CBDC` and
  `IMMultiSeq_update = 0x8017CD28`. Save-data watches through
  `gGameBitSaveData = *(u8**)0x803DCAE0`: `+0x88 & 0x20` for `0x3AE`,
  `+0x86 & 0x04` for `0x070`, and `+0x86 & 0x10` for `0x072`.
- This is useful only if a currently reachable sequence cancel is faster than
  the existing Ice Mountain route. It does not need heap exhaustion, and
  sequence-slot exhaustion is counterproductive because a failed
  `runSequence` never invokes the callback that arms the completion write.

### Code S23

- **This is a natural out-of-bounds write, not a capacity-only thought
  experiment.** [initMapBlocks](../src/main/shader.c) allocates arrays for
  exactly 64 live map-block pointers, 64 block IDs, and 64 reference counts.
  [trackLoadBlockEnd](../src/main/shader.c) increments `gMapBlockCount`, prints
  its overrun warning when the count first reaches 64, but never rejects slot
  64 or any later slot.
- [doPendingMapLoads](../src/main/shader.c) first saves every old cell's slot,
  then loads the complete new camera neighborhood, and only afterward releases
  the old references. A camera-grid crossing therefore temporarily needs the
  union of both neighborhoods. The old blocks cannot provide holes while the
  new blocks are being appended.
- The three allocations are consecutive 32-byte-exact allocations in small
  heap region 2. Consequently slot 64 is a deterministic alias, not an
  allocator-header guess: `gMapBlocks[64]` overwrites `gMapBlockIds[0..1]`,
  `gMapBlockIds[64]` overwrites `gMapBlockRefCounts[0..1]`, and
  `gMapBlockRefCounts[64]` overwrites byte 0 of `gMapInfoBuffer`. Slot 65
  overwrites the next two IDs/counts and byte 1, and so on. The out-of-range
  entries remain self-consistent through these aliases, while the oldest
  in-range block identities and counts are destroyed.
- The active EN v1.0 disc assets contain reachable over-capacity transitions in
  Dragon Rock Top. Of 2,515 valid retail camera centers, only this map has an
  adjacent one-cell transition whose old/new union exceeds 64 blocks. There
  are 26 directed adjacent transitions. The result is identical in the
  extracted EN v1.1, JP, PAL v1.0, and PAL v1.1 assets.
- A direct landing-area transition is camera center `(-22,17)` (62 unique
  blocks) to `(-21,17)` (64 unique blocks). It introduces blocks
  `215, 216, 1592, 217`; the first two fill valid slots 62 and 63, then blocks
  1592 and 217 write slots 64 and 65. The next north/south boundary between
  centers `(-21,17)` and `(-21,18)` has a 67-block union and can append three
  out-of-range blocks in one recenter.
- In world coordinates, the first camera boundary is `X = -13440`; once the
  camera center is in column `-21`, the second is `Z = 11520`. Relative to
  `dragrock`'s retail world origin `(-17920,10880)`, those are local
  `X = 4480` and `Z = 640`. The landing area's TrickyWarp chain and nearby
  placements occupy that same local neighborhood, so this does not require a
  remote camera teleport merely to cross the vulnerable cells.
- Bouncing should amplify the corruption. Once slots 64+ overwrite the first
  block IDs, the next recenter fails to recognize those still-live blocks and
  loads duplicates. Holes from blocks that leave the neighborhood are consumed
  first; subsequent misses extend the high-water count and overwrite later ID
  pairs. This is the immediate experiment: determine whether repeated crossing
  produces missing/stale collision, a wrong retained block, or a useful loader
  failure before it crashes. A progression payload is not claimed yet.
- Active EN v1.0 watches: `trackLoadBlockEnd = 0x80056CEC`,
  `gMapBlockCount = 0x803DCE98`, `gMapBlocks = 0x803DCE9C`,
  `gMapBlockIds = 0x803DCE94`, and `gMapBlockRefCounts = 0x803DCE8C`.
  Break on `trackLoadBlockEnd` with the count at least 64; arguments are block
  pointer `r3`, block ID `r4`, cell slot `r5`, and layer `r6`.
- [map_stream_overflow_probe.py](../tools/map_stream_overflow_probe.py)
  reconstructs the retail neighborhoods and insertion order. It can read the
  active disc directly without extracting it:

  ```text
  python tools/map_stream_overflow_probe.py --version GSAE01 \
    --iso "orig/GSAE01/Star Fox Adventures (USA) (v1.00).iso" \
    --map "Dragon Rock" --max-step 1
  ```

## Additional streaming-memory leads recorded for follow-up

- **Checkpoint duplicate removal:** [engine/3](../src/dlls/engine/3/3.c) has a
  200-entry checkpoint table with an unchecked add. Removal matches only the
  checkpoint sort key rather than its pointer. If duplicate romlist pages add
  identical keys, unloading one page can remove the other entry and leave a
  pointer into freed page memory. Its route search also seeds a local 64-entry
  stack with every nearby matching checkpoint without bounding that initial
  seed phase.
- **TrickyWarp curve cache:**
  [TrickyWarp_isPlayerReachable](../src/dlls/objects/256_TrickyWarp/TrickyWarp.c)
  scans every loaded curve and writes matching IDs into 24 state entries without
  a limit. Duplicate/stale curve pages could overflow the object's complete
  `0x64`-byte extra-state allocation. Normal curve-page de-duplication must be
  defeated first, so this remains a compound lead.
- **Texture cache off-by-one:** [texture.c](../src/main/texture.c) allocates 700
  loaded-texture entries. When all are occupied, the load path constructs entry
  700 before checking that the resulting count exceeds 700, producing one
  16-byte write beyond the allocation. It requires 700 simultaneously retained
  distinct texture records, not 700 references to one texture.
- **Live-object list:** [Obj_RegisterObject](../src/main/object.c) appends to a
  600-pointer live-object allocation without a capacity test. Abandoned deferred
  frees are removed from this list before cleanup fails, so they do not directly
  accumulate toward 601; a separate simultaneous-instantiation setup is needed.
- **Object-sequence cleanup stack:** [endObjSequence](../src/dlls/engine/2/2.c)
  collects matching class-`0x10` objects into a 32-pointer local array without a
  limit. It reports at 16 but keeps appending. Thirty-three simultaneously live
  objects sharing the sequence slot would overwrite the stack.
- **World-transform parent depth:**
  [Obj_BuildWorldTransformMatrix](../src/main/camera.c) stores only four ancestor
  pointers while following parents until null, with neither a depth nor cycle
  check. A five-deep parent chain overflows the local array; a parent cycle keeps
  writing. No player-controlled route to such a hierarchy is currently known.

## Leads held back and false positives

- **Effect-box list:** the global list holds twenty objects and registration has
  no limit. JP CloudRunner Fortress has 35 placements, but most use distance
  loading. The total placed count is insufficient evidence of 21 simultaneous
  registrations. EN list `0x803408A8`; the next word, `0x803408F8`, belongs to
  `gObjHitsSweepEntryPtrs`. Source: [Obj_RegisterEffectBox](../src/main/object.c).
- **Accessory child list:** `ObjLink_AttachChild` has no five-child limit or
  duplicate check; `ObjLink_DetachChild` decrements even if the child is absent.
  Most callers inspected maintain the contract. Replaying an animated object's
  staff-attachment event without its detach event is a possible route, but no
  repeatable sequence has been found. Source: [objlib.c](../src/main/objlib.c),
  [AnimatedObj.c](../src/dlls/objects/198_AnimatedObj/AnimatedObj.c).
- **Frozen-object double free:** object cleanup can queue the render attachment
  for freeing twice, but the allocator rejects an already-freed block. This is
  not sufficient evidence of heap corruption. Source:
  [objFreeObjdef](../src/main/object.c), [ObjModel_Release](../src/main/model.c).
- **Mount-animation camera local:** inspection of the retail instructions finds
  a per-frame vehicle camera-position call. There is no basis for an
  uninitialized-camera-vector finding here.

## Audit notes

Starting checkout: `3753ef0b07`. No gameplay code was changed for this audit.
All five available DOLs passed their configured SHA-1 checks. That validates the
inputs, not every interpretation of their code.

[glitch_mining_probe.py](../tools/glitch_mining_probe.py) is a read-only helper for
rechecking function windows and retail placements. It uses the repository's
existing asset parsers; disassembly additionally needs Capstone. For example:

```text
python tools/glitch_mining_probe.py hashes
python tools/glitch_mining_probe.py disasm Carryable_updateHeld --offset 0x230 --length 0x60
python tools/glitch_mining_probe.py disasm saveGame_unsaveObjectPos --offset 0x1e0 --length 0x28
python tools/glitch_mining_probe.py placements --dll 344 386 --version GSAJ01
python tools/glitch_mining_probe.py placements --name CCgoldbar --version GSAJ01 --detail
```

The next useful work is to establish player-reachable setups and record what the
game actually does. Changing memory to force a threshold can validate a mechanism,
but should be recorded separately from achieving it through gameplay.
