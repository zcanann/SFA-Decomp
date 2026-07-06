# Objects

> Source: [Rena Kunisaki's SFA wiki](https://github.com/RenaKunisaki/StarFoxAdventures/wiki/Objects). Reverse-engineering notes; not independently verified here.

Objects are anything that moves around (sometimes called "actors" in other engines). Objects are
defined in `OBJECTS.bin` in a struct the wiki calls `ObjectFileStruct` (the per-object-*type*
template/definition, shared by every instance of that type); each live instance in memory is an
`ObjInstance`.

## ObjInstance

An instance of an object in memory, such as the player character.

Offset|Type                    |Name              |Description
------|------------------------|------------------|-----------
000000|ObjTransform            |xf                |location, rotation, scale
000018|Vec                     |prevPos           |
000024|Vec                     |vel               |velocity
000030|ObjInstance*            |heldBy            |eg for platform you're standing on; position is relative to this
000034|MapId8                  |map               |related to children and/or player objects
000035|u8                      |mtxIdx            |
000036|u8                      |newOpacity        |
000037|u8                      |opacity           |is set to newOpacity each frame
000038|ObjInstance*            |next              |list is not necessarily in order
00003C|float                   |loadDistance      |same value as 0x40
000040|float                   |cullDistance2     |2040=100% opacity, 128=~50% - camera distance?
000044|ObjCategory             |catId             |same for multiple objs; related to seq
000046|ObjDefEnum               |defNo             |behaviour? changing to others from Krystal (except 0=Fox) prevents moving/animating
000048|ObjDefEnum               |defNo48           |returned from some seq funcs
00004A|s16                     |                  |
00004C|ObjDef*                 |objDef            |The romlist entry that created this object
000050|ObjectFileStruct*       |file              |The object definition
000054|HitState*               |hitstate          |
000058|HitboxMatrix*           |hitboxMtx         |
00005C|int*                    |                  |
000060|int*                    |pEventName        |unused?
000064|Shadow*                 |shadow            |
000068|ObjDll*                 |dll               |-> DLL func ptrs, or NULL
00006C|S16Vec*                 |pVecs             |
000070|astruct_53**            |pTextures         |count = file->nTextures
000074|Vec[2]*                 |focusPoints       |points for camera to look at
000078|ObjTargetField78*       |targetVal_78      |related to camera targeting; one per focus point?
00007C|ModelInstance**         |models            |one per model
000080|Vec                     |oldPos            |unsure how this differs from prevPos
00008C|Vec                     |pos_0x8c          |
000098|float                   |animTimer         |
00009C|float                   |animVal_9c        |
0000A0|s16                     |animId            |which animation is playing
0000A2|s16                     |animId_a2         |
0000A4|float                   |cullOffset        |
0000A8|float                   |cullDistance      |affects brightness and opacity; multiplied by scale; fuzz?
0000AC|MapId8                  |mapId             |crashes if < 0x80; passed to loadCharacter but not used?
0000AD|u8                      |curModel          |which model index to use
0000AE|u8                      |priority          |0x50 for most; determines order added to global obj list
0000AF|ObjInstance_FlagsAF     |flags_0xaf        |28=don't render something (no models?)
0000B0|ObjInstance_FlagsB0     |flags_0xb0        |
0000B2|s16                     |objNo             |
0000B4|s16                     |curSeq            |
0000B6|??                      |                  |
0000B7|??                      |                  |
0000B8|pointer                 |state             |type depends on object
0000BC|pointer                 |seqFn             |`int objSeqFn(ObjInstance *this, ObjInstance *that, ObjSeqState *seqState)`
0000C0|ObjInstance*            |override          |for sequences
0000C4|ObjInstance*            |parent            |
0000C8|ObjInstance*[3]         |child             |
0000D4|byte*                   |                  |
0000D8|s16                     |                  |
0000DA|??                      |                  |
0000DB|??                      |                  |
0000DC|ObjMsgQueue*            |msgQueue          |
0000E0|??                      |                  |
0000E1|??                      |                  |
0000E2|??                      |                  |
0000E3|u8                      |flag_altMtrlColor |
0000E4|u8                      |targetVal_78_count|
0000E5|u8                      |iceFlags          |1:frozen
0000E6|s16                     |shatterTimer      |used when frozen
0000E8|u8                      |hintTextIdx       |
0000E9|u8                      |seqCountE9        |
0000EA|u8                      |                  |relates to freeing
0000EB|u8                      |nChildren         |
0000EC|GXColor                 |colorEC           |
0000F0|u8                      |                  |
0000F1|u8                      |brightness        |
0000F2|u8                      |colorIdx          |
0000F3|??                      |                  |
0000F4|ObjInstanceFieldF4      |                  |union? SPitembeam stores LevelControl here
0000F8|ObjInstanceFieldF8      |                  |union?
0000FC|Vec                     |oldVel            |
000108|pointer                 |cbAfterUpdateBones|`undefined objField108_func(ObjInstance *this, ModelInstance *model, Mtx44 *mtx)`

(0xF4+ might be an object-specific struct? not sure why use that instead of state)

## Message Queue

An object instance can have a message queue, whose size is hard-coded in the object's setup
method. This is used by scripts or code to signal objects to do something. This system seems to
not be very widely used.

The message queue is pointed to by field 0xDC of the ObjInstance. Its structure is:

* `int numMsgs`
* `int maxMsgs` — set by the object's init code on allocation
* `messages[maxMsgs]`:
  * `uint msg` — the message
  * `ObjInstance* from` — the sender
  * `void* param` — type depends on message

An object can send a message to:

* Another object, directly, by pointer
* All objects of a specified defNo or category
* All objects within a certain distance
* All objects

It has the option to exclude itself from the recipients. Objects with no message queue are
ignored. An object can pop or peek messages from its queue, which is normally done in its update
method. An error message is printed to the console if any message is dropped due to the
recipient's queue being full.

A message consists of the message ID (u32), the sender (`ObjInstance*`), and a parameter (any
32-bit type). While message IDs are always treated as an opaque u32, they appear to be composed
of two u16s: the higher is a category, the lower a specific message in that category.

### Category 0x0000
* 0000 0001: unknown, used by DLL 0x19
* 0000 0008 / 0009: used by CF power things
* 0000 000E: when sent to a pushable object, deletes it
* 0000 000F / 0010: used by GunPowderBarrel
* 0000 0011: used by DB_egg

### Category 0x0003
* 0003 0002 / 0003: ?
* 0003 0005 / 0006: used by DLL 0x199, 0x19B

### Category 0x0004
* 0004 0001: used by pushable objects, but only defNo 0x21E and 0x411 which don't exist?
  param: pointer to a float

### Category 0x0005
* 0005 0001 / 0002 / 0003: related to player item-get anim?

### Category 0x0006: Player Damage
* 0006 0001: get knocked to butt, take `param` damage, and make "hurt" sound
* 0006 0002: ?
* 0006 0003: get knocked to butt and take `param` damage
* 0006 0004: related to player being hurt
* 0006 0005: same as 0006 0003?

### Category 0x0007: Collectibles
* 0007 000A: related to collectibles; triggers "got new item" anim on player. Sent from fuel cell
  to player, and from magic gem to player if they've never picked one up before. param: unknown
  pointer, or sequence ID?
* 0007 000B: sent to a collectible when it's picked up; no parameter. Triggers the actual
  collectible action (eg Scarab: plays the sound effect, adds to the player's money).

These don't seem to always be used; eg collecting a Scarab doesn't generate a message, though the
code is there to handle it.

### Category 0x0008: Items
* 0008 0001: sent to player when using an item. param is the item's GameBit.
* 0008 0002: sent to player to set the pending spell ID. param is the "have this spell" GameBit.
  Used for staff booster pads.

### Category 0x000A
* 000A 0001: used by DLL 0x19
* 000A 0002 / 0003 / 0004 / 0006: ?
* 000A 0005: sets a GameBit related to prison key

### Category 0x000E
* 000E 0000: used by DLL 0x19

### Category 0x000F
* 000F 0003: when sent to a pushable object, the sender is saved for some later use
* 000F 0004: used by CloudPrisonControl
* 000F 000B / 000D / 000E / 000F / 0010: ?
* 000F 000C: used by FEseqobject

### Category 0x0010: Carryables
* 0010 0008: related to player collecting item; sent from barrel to player every frame while
  carrying
* 0010 0010: related to player, staff?; sent from basket to player every frame while carrying
  (doesn't appear to make any difference which message is used)

### Category 0x0011: CloudRunner Power Generator
* 0011 0001 / 0002 / 0003 / 0004: related to CloudRunner power crystals

### Category 0x0013: Ship Battle
* 0013 0001 / 0002 / 0003: used by SB_ShipHead

## Object Names

Some objects have a prefix explaining where they're meant to be used or what they are:

Prefix |Meaning
-------|--------
Anim   |cutscene
AND    |Andross
ARW    |Arwing (flying shmup sections)
BGS    |only one instance, "BGSweapon"
CC     |Cape Claw
CF     |CloudRunner Fortress
CFGC   |
comm   |pause menu ("communicator")
CNT    |control objects
CR     |CloudRunner Race?
DB     |Diamond Bay
DBSH   |Diamond Bay Shrine
DF     |Dfalls
DFSH   |Dfalls Shrine
DFP    |Dragon Force Point?
Die    |death cutscene
DIM    |DarkIce Mines
DIM2   |DarkIce Mines 2
DR     |DragonRock
ECSH   |? Shrine
FE     |
Front  |title screen
GC     |
GF     |Great Fox (title screen, cutscenes)
GFRONT |title screen (unused?)
GM     |Game Maze (cheat tokens)
GPSH   |GP shrine
IM     |Ice Mountain
KP     |Krazoa Palace? (but see WM)
KT     |T-Rex Boss
LGT    |lighting
LINK*  |corridors between maps
LF     |Lightfoot Village
MC     |Magic Cave (where staff upgrades are found)
MMSH   |Moon Mountain Shrine
MMP    |Moon Mountain Pass
MS     |
NW     |SnowHorn Wastes
NWSH   |SnowHorn Wastes Shrine
OFP    |Ocean Force Point
SB     |Ship Battle (Krystal shooting down ship at start of game)
SC     |SwapCircle (Lightfoot Village)
SH     |ThornTail Hollow (internally called SwapHol)
SKY    |sky decals (sun, moon...)
SP     |Shop
Trig   |trigger for events?
VFP    |Volcano Force Point
WC     |Walled City
WM     |Krazoa Palace (internally "Warlock", was once called Warlock Mountain)
WORLD  |world map (in orbit)

After the prefix, some names follow helpful patterns:

Name     |Meaning
---------|-------
Badge    |icon above someone's head
CAMERA   |camera control/viewpoint
Cont     |control (sets parameters for area)
Dummy    |unused placeholder
Duster   |Bafomdad (1up)
InfoText |sign explaining the area
LevelCo  |truncation of "Level Control", see Cont
levco    |see Cont
LGT      |light
pickobj  |something that can be picked up?
Pilot    |characters on title screen
Sabre    |Fox (was called Sabre in early development)
Seq      |used in an animation sequence
textblock|unused?

Refer to `objects.xml` for the list. These names are only used in debug messages. Since they're
truncated to 11 characters, they aren't unique (in the kiosk demo version they're 15 characters).

## Object Categories

Each object is assigned a category ID (s16), used in some code to simplify checking for various
types of object (eg "any weapon" or "any door"). The categories aren't named in the game. Several
categories are only used by one object; there are also unused categories (skipped here).

ID  |Description
----|-----------
0000|DummyObject, xyzpoint
0001|Player
0002|Tricky
0004|setuppoint
0005|checkpoint4
0006|collectible
0008|InfoPoint
0009|EffectBox
0010|AnimatedObj
0011|Unused? but checked for by seq cmd 0x03
0012|StaticCamera
0013|WalkCamera
0014|TrigPnt
0015|TrigPln
0016|TrigCyl
0017|TrigArea
0018|TrigTime
0019|TrigButt
001A|TriggSetp
001B|TrigBits
001C|most baddies
001D|torch
001E|sideload
001F|siderepel
0021|texscroll
0024|fireball
0025|warp (transporter, WarpPoint)
0026|mammoth
0027|InvHit
0028|falling rock
0029|edible mushroom
002A|enemy mushroom
002B|bomb plant
002C|curve
002D|player weapon (and ScalesSword)
002E|bike
0030|many things
0031|InfoText, TrickyGuard, ReStartMarker
0032|CampFire
0033|PressureSwitch
0035|CCriverflow
0036|DFropenode
0037|ObjCreator
0038|Some doors
0039|LevelControl
003A|Pushable
003B|TrigCrve
003C|SidekickBall
003D|CFPerch
003E|CFPrisonUncle
003F|CFPrisonCage, CFCageSwitch
0040|CloudRunner
0041|Area
0042|DigTunnel
0043|LevelName
0044|SH_thorntail
0045|DIMLavaBall
0046|DIMSnowBall
0047|DIM2PathGen
0048|WaveAnimator
0049|AlphaAnimator
004A|GroundAnimator
004B|HitAnimator
004C|WallAnimator
004D|XYZAnimator
004E|VisAnimator
004F|ExplodeAnimator
0050|IceSmash
0051|ProjectileSwitch
0052|PressureSwitch52
0053|Other doors
0054|Lock, Landed_Arwing
0055|SeqObject
0056|SeqObj2
0057|IMMultiSeq
0059|WM_Column
005C|sfxPlayer
005D|AppleOnTree
0060|MAGICMaker, LFXEmitter
0061|many things
0063|Exploded, Explodable
0065|MagicPlant
0066|IMIcePillar
0067|KT_FallingRocks, MMP_trenchFX, AreaFXEmit
0068|PerchObject, MoonSeedPlantingSpot
0069|CurveFish
006A|Tree
006B|DIMbosscrackpar, FXEmit
006C|KT_RexFloorSwitch
006D|KT_Rex
006E|SPShop
006F|SPShopKeeper
0070|ShopItem
0071|Cannon, CannonClaw
0072|SkeetlaWall
0073|WaterFallSpray
0078|ARWGenerator
0079|Light
007A|StaffActivated
007B|ProjectedLight
007C|ArwingLevelObj
007D|MagicCaveTop
007E|CmbSrc, DustMoteSou
007F|Decorative
0080|DeathGas
0081|FogControl
0082|GuardClaw
0083|Lightning
FFFF|DR_TestWall

## MODELIND.bin

Just like `OBJINDEX.bin`, this maps model IDs to different model IDs, but this time each map has
its own file. Again, a model ID can be negative to prevent remapping.

## In this codebase

This repo doesn't carry one monolithic `ObjInstance` struct — the same memory record is split
across `ObjAnimComponent` (`include/main/objanim_internal.h`, the object's head, `0x00`-`0xB0`,
`STATIC_ASSERT`-pinned) and `GameObject` (`include/main/game_object.h`, the tail from `0xB0` on,
wrapping `ObjAnimComponent anim` at offset 0). Mappings below were verified by reading the source,
not just offset arithmetic; anything I couldn't confirm live in code is marked "not found".

### Head (0x00-0xB0): `ObjAnimComponent` vs `ObjTransform`/wiki fields

Wiki offset/name | This codebase | Verified how
---|---|---
`0x00` xf (`ObjTransform`: loc/rot/scale) | `rotX/rotY/rotZ/flags` (s16 x4) + `rootMotionScale` (f32) + `localPosX/Y/Z` | `STATIC_ASSERT`s in objanim_internal.h; decomposes the wiki's opaque `ObjTransform` into named fields
`0x18` `Vec prevPos` | `worldPosX/Y/Z` | offset matches (`STATIC_ASSERT ... worldPosX == 0x18`); name differs — not verified whether this is "world position" or "previous frame's position"
`0x24` `Vec vel` | `velocityX/Y/Z` | exact offset + name match (`velocityX == 0x24`)
`0x30` `ObjInstance* heldBy` | `void *parent` | offset matches (`parent == 0x30`); this is a *different* slot from the `0xC4` "parent" below — see discrepancy note
`0x34` map (u8), `0x35` mtxIdx, `0x36` newOpacity, `0x37` opacity | `pad34[2]` (comment: "+0x35 is the signed yaw transform-table index"), `alpha` (u8) @0x36, then `pad37[0x44-0x37]` | offset/width match; own comment on `pad34` independently corroborates wiki's `mtxIdx` ("yaw transform-table index"); `alpha`@0x36 lines up with wiki's `newOpacity`@0x36
`0x38` next, `0x3C` loadDistance, `0x40` cullDistance2 | inside `pad37[13]` (unnamed) | not broken out in this codebase yet — see Ready-to-adopt below
`0x44` `ObjCategory catId` | `s16 classId` | **confirmed by many literal comparisons** matching the wiki's category table exactly: `classId==1`→Player (dozens of sites, e.g. `objseq.c`, `cutcam.c`, `objprint_dolphin.c`), `==2`→Tricky (`dll_00FB_pressureswitchfb.c:239`, checked alongside `==1`), `==0x10`→AnimatedObj (`object.c:1557`, `objseq.c:535`), `==0x11`→"unused, checked by seq cmd" (`objseq.c:4113`, matches wiki note verbatim), `==0x1c`→most baddies (`newseqobj.c`, `cutcam.c`, `dll_0049_cameramodecombat.c`), `==0x2a`→enemy mushroom (`cutcam.c`, `dll_0049_cameramodecombat.c`), `==0x2d`→player weapon (`objprint.c:777` — the player's staff), `==0x6d`→KT_Rex (`dll_0049_cameramodecombat.c`, boss camera)
`0x46` `ObjDefEnum defNo` | `s16 seqId` | offset matches (`seqId == 0x46`). **Strong evidence the repo name is wrong / should be `defNo`**: `src/main/objlib.c`'s own debug format string is `"objmsg (%x): overflow in object %d defno=%d FROM: defno %d\n"`, printed from `((GameObject*)dstObj)->anim.classId` then `anim.seqId` — the retail string itself calls this field `defno`. Also, `ObjList_FindNearestObjectByDefNo(int obj, int defNo, ...)` (`objlib.c:1854`) compares its `defNo` parameter directly against `otherObj->anim.seqId`. See Ready-to-adopt below.
`0x48` `ObjDefEnum defNo48` | `s16 defId` | offset matches (`defId == 0x48`). `object.c:1649`: `type = obj->anim.defId;` used to index `gObjFileRefCount[type]` / `gObjFileBufferTable[type]` (the loaded-object-file ref-count/buffer tables) — consistent with wiki's "def"-flavored guess, though not literally "returned from some seq funcs"
`0x4A` (s16, unnamed) | `pad4A[2]` | matches, unnamed on both sides
`0x4C` `ObjDef* objDef` ("the romlist entry that created this object") | `union { s16 *placementData; struct ObjPlacement *placement; }` | **name collision warning**: wiki's `ObjDef` here means the per-*instance* romlist/placement record — this codebase's own `ObjPlacement` (`include/main/obj_placement.h`, `posX@0x8`, `mapId@0x14`, `STATIC_ASSERT`-pinned). This codebase *also* has a type literally named `ObjDef` (objanim_internal.h) but it means something else — see next row
`0x50` `ObjectFileStruct* file` ("the object definition") | `ObjDef *modelInstance` | offset matches (`modelInstance == 0x50`). **This is the collision**: this codebase's `ObjDef` struct (textureSlotDefs, jointData, hitVolumes, modelCount, jointCount, sequenceCount, helpTextIds, renderFlags...) is the wiki's `ObjectFileStruct`/`file` (the shared per-object-type definition), *not* the wiki's `ObjDef` (which is the per-instance placement, i.e. this codebase's `ObjPlacement`). Anyone cross-referencing the wiki against this codebase's `ObjDef` type needs to read it as "`file`", not as wiki's "`objDef`"
`0x54` `HitState* hitstate` | `ObjHitReactState *hitReactState` | offset + name family match (`hitReactState == 0x54`)
`0x58` `HitboxMatrix* hitboxMtx` | `pad58[0x5C-0x58]` (unnamed, 4 bytes) | offset matches, not broken out yet
`0x5C` `int*` (unnamed) | `struct ObjWeaponDaTable *weaponDaTable` | offset matches (`weaponDaTable == 0x5C`); this codebase has a name, wiki doesn't
`0x60` `int* pEventName` ("unused?") | `struct ObjAnimEventTable *eventTable` | offset matches (`eventTable == 0x60`); `ObjAnimEventTable{ s32 byteCount; ObjAnimPackedEvent *entries; }` looks like a real per-object *event table*, not a "name" — likely resolves wiki's uncertainty here
`0x64` `Shadow* shadow` | `ObjModelState *modelState` | offset matches (`modelState == 0x64`); `ObjModelState` is mostly shadow fields (`shadowScale/shadowTexture/shadowWorkBuffer/shadowCastSlot/shadowRenderResource/shadowOffsetX-Z/shadowTintB/shadowAlpha`) plus a couple of world-pos overrides, so wiki's "Shadow*" guess is close but incomplete
`0x68` `ObjDll* dll` | `int **dll` | **exact offset + name match**. The pointed-to vtable shape (`ObjectDescriptor` in `include/main/object_descriptor.h`: `initialise/release/init/update/hitDetect/render/free/getObjectTypeId/getExtraSize` slots) is this codebase's equivalent of wiki's `ObjDll`
`0x6C` `S16Vec* pVecs` | `u8 *jointPoseData` | offset matches (`jointPoseData == 0x6C`); plausible same data (packed joint rotations as s16 vectors) under a different name/type
`0x70` `astruct_53** pTextures` (count = file->nTextures) | `ObjTextureRuntimeSlot *textureSlots` | offset matches (`textureSlots == 0x70`)
`0x74` `Vec[2]* focusPoints` ("points for camera to look at") | `ObjHitVolumeRuntimeTransform *hitVolumeTransforms` | offset matches (`hitVolumeTransforms == 0x74`); `sizeof(ObjHitVolumeRuntimeTransform) == 0x18` = `sizeof(Vec[2])`, so the two guesses agree on element size but disagree on purpose (hit-volume transform vs camera focus point) — open discrepancy, not resolved here
`0x78` `ObjTargetField78* targetVal_78` ("camera targeting; one per focus point") | `ObjHitVolumeRuntimeBounds *hitVolumeBounds` | offset matches (`hitVolumeBounds == 0x78`, `sizeof == 0x5`). This codebase's name is corroborated by a real function signature: `Obj_SetActiveHitVolumeBounds(GameObject *obj, int xBound, int zBound, int yBound, u8 radiusOrHeight, u8 flags)` (`game_object.h`) — 3 packed bounds + radius/height + flags = 5 bytes, matching the struct size. This looks like a case where this codebase's evidence-based name is more likely correct than the wiki's camera-targeting guess
`0x7C` `ModelInstance** models` ("one per model") | `ObjAnimBank **banks` | offset matches (`banks == 0x7C`); "one per model" vs "one per anim bank" — plausibly the same array under a different lens
`0x80` `Vec oldPos` ("unsure how this differs from prevPos") | `previousLocalPosX/Y/Z` | offset matches (`previousLocalPosX == 0x80`) — resolves the wiki's own uncertainty: this is the *previous local position*, distinct from `0x18` (world position)
`0x8C` `Vec pos_0x8c` (wiki has no name for this) | `previousWorldPosX/Y/Z` | offset matches (`previousWorldPosX == 0x8C`) — **resolves a wiki "??"**: previous *world* position, paired with `0x80`'s previous *local* position
`0x98` `float animTimer` | `f32 currentMoveProgress` | offset matches (`currentMoveProgress == 0x98`)
`0x9C` `float animVal_9c` (wiki has no real name) | `f32 activeMoveProgress` | offset matches (`activeMoveProgress == 0x9C`) — resolves another wiki "??"
`0xA0` `s16 animId` | `s16 currentMove` | offset + concept match (`currentMove == 0xA0`)
`0xA2` `s16 animId_a2` | `s16 activeMove` | offset + concept match (`activeMove == 0xA2`)
`0xA4` `float cullOffset` | `void *targetObj` | offset matches (`targetObj == 0xA4`) but **semantics disagree**: this codebase derives it as a `GameObject*` attention/track target from CAM-unit and `baddieControl.c` evidence (own comment cites a "0xA4-as-pointer census"), not a float. Flagged as an open discrepancy, not resolved
`0xA8` `float cullDistance` | `f32 hitboxScale` | offset matches (`hitboxScale == 0xA8`) but semantics disagree (visual LOD/fade distance vs a hit-detection scale factor) — open discrepancy
`0xAC` `MapId8 mapId` | `s8 mapEventSlot` | offset matches (`mapEventSlot == 0xAC`); both land in the "map" domain, exact relationship unconfirmed
`0xAD` `u8 curModel` ("which model index to use") | `s8 bankIndex` in `ObjAnimComponent`, **but** `objlib.c` independently defines `#define OBJ_ACTIVE_MODEL_INDEX_OFFSET 0xad` | Same absolute offset, two different repo-internal names (`bankIndex` vs "active model index"), and the wiki's `curModel` sides with `objlib.c`'s naming — worth reconciling, see Ready-to-adopt below
`0xAE` `u8 priority` | `s8 activeHitboxMode` | offset matches (`activeHitboxMode == 0xAE`) but semantics disagree (render-order priority vs hitbox mode) — open discrepancy
`0xAF` `ObjInstance_FlagsAF flags_0xaf` (bit 0x28 = "don't render") | `union { s8 resetHitboxMode; u8 resetHitboxFlags; }`, bits documented as `INTERACT_FLAG_*` (`0x01 ACTIVATED, 0x04 IN_RANGE, 0x08 DISABLED, 0x10 PROMPT_SUPPRESSED`) | offset matches (`resetHitboxFlags == 0xAF`). `src/main/objlib.c` independently defines the *same bit values* at the *same offset* under yet another name: `#define OBJTRIGGER_FLAGS_OFFSET 0xaf`, `OBJTRIGGER_CURRENT_ENABLE_FLAG 0x01`, `OBJTRIGGER_ID_ENABLE_FLAG 0x04`, `OBJTRIGGER_CURRENT_BLOCK_FLAG 0x08`, `OBJTRIGGER_ID_BLOCK_FLAG 0x10` — three names (wiki's "flags_0xaf", objanim_internal.h's `INTERACT_FLAG_*`, objlib.c's `OBJTRIGGER_*`) for the same byte/bits

### Tail (0xB0+): `GameObject` vs wiki fields

Wiki offset/name | This codebase | Verified how
---|---|---
`0xB0` `ObjInstance_FlagsB0 flags_0xb0` | `u16 objectFlags` | exact offset + name-family match. `objlib.c` independently has `#define OBJLINK_FLAGS_OFFSET 0xb0`, `OBJLINK_FLAGS_DEAD 0x0040` — matches `game_object.h`'s own `OBJECT_OBJFLAG_FREED 0x40` at the same offset (internal consensus, two files agree)
`0xB2` `s16 objNo` | `u8 unkB2[2]` | offset matches, not broken out yet — wiki's name is a plausible fill-in
`0xB4` `s16 curSeq` | `s16 seqIndex` | offset + concept match (`seqIndex` is the "trigger-sequence index", passed to `ObjectTriggerInterface.endSequence(seqIndex)`)
`0xB6`/`0xB7` unknown | `u8 unkB6[2]` | matches, unnamed on both sides
`0xB8` `state` (type depends on object) | `void *extra` | exact offset + concept match ("per-class state block")
`0xBC` `seqFn`: `int objSeqFn(ObjInstance*, ObjInstance*, ObjSeqState*)` | `void *animEventCallback` | **exact signature match confirmed in live code**: `snowclaw.c` declares `int snowclaw_animEventCallback(int obj, int a2, ObjSeqState* seq)` and assigns it to `obj->animEventCallback` — same 3-arg (this, other, seqState) shape the wiki describes for `seqFn`
`0xC0` `ObjInstance* override` ("for sequences") | `void *pendingParentObj` | offset matches; own comment describes a different mechanism (pending anim-parent link consumed by `Obj_ApplyPendingParentLinks`) than wiki's "override for sequences" — not reconciled
`0xC4` `ObjInstance* parent` | `void *ownerObj` in `game_object.h`, **but** `objlib.c` defines `#define OBJLINK_PARENT_OFFSET 0xc4` | Same offset, and `objlib.c`'s own name (`OBJLINK_PARENT_OFFSET`) matches the wiki's `parent` exactly, while `game_object.h`'s comment calls it `ownerObj` ("owner-ward chain link... objprint walks it to the chain root for shadow state") — two repo-internal names for the same slot, wiki corroborates the `objlib.c` side
`0xC8` `ObjInstance*[3] child` | `void *childObjs[5]` | offset matches (`OBJLINK_CHILD_LIST_OFFSET 0xc8` in `objlib.c`); this codebase models 5 slots spanning through `0xDC` where the wiki instead lists `child[3]` (`0xC8`-`0xD4`) plus a `byte*`, `s16`, and 2 unknown bytes (`0xD4`-`0xDC`) — both total exactly 20 bytes (`0xC8`-`0xDC`), just diced differently
`0xD4`-`0xDB` (byte*, s16, 2 unknown) | covered by the tail of `childObjs[5]` above | see above
`0xDC` `ObjMsgQueue* msgQueue` | `void *unkDC`, **and** `src/main/objlib.c` independently defines `#define OBJMSG_QUEUE_OFFSET 0xdc` | **Exact match, fully confirmed**: `objlib.c`'s own `ObjMsgQueue`/`ObjMsgEntry` structs are a byte-for-byte match of the wiki's Message Queue section — see the dedicated subsection below
`0xE0`-`0xE2` unknown | `u8 unkE0[4]` (spans `0xE0`-`0xE3`, so also covers wiki's named `0xE3` byte below) | matches
`0xE3` `u8 flag_altMtrlColor` | inside `unkE0[4]` above | not broken out yet
`0xE4` `u8 targetVal_78_count` | `u8 hitVolumeIndex` | offset matches (`hitVolumeIndex == 0xE4`) but names/semantics disagree (focus-point count vs active hit-volume node index) — open discrepancy
`0xE5` `u8 iceFlags` (bit 1 = "frozen") | `u8 colorFadeFlags`, **and** `objlib.c` defines `#define OBJLINK_CHILD_STATE_OFFSET 0xe5` | offset matches. This codebase's own bit name **corroborates the wiki exactly**: `#define OBJ_COLOR_FADE_FLAG_FROZEN 0x1` with the comment "freeze render attachment active (`objIsFrozen`)" — same bit, same meaning, independently named. A third repo name (`OBJLINK_CHILD_STATE_OFFSET`) exists for the same byte in `objlib.c`, suggesting this byte may pack more than one concern
`0xE6` `s16 shatterTimer` ("used when frozen") | `s16 colorFadeFrames` | offset matches (`colorFadeFrames == 0xE6`); own comment ("frames left; `-=` framesThisStep, `<=0`... clear") matches wiki's "used when frozen" countdown exactly
`0xE8` `u8 hintTextIdx` | `u8 paletteIndex` | offset matches (`paletteIndex == 0xE8`). **The repo's own function proves the wiki's name is the correct one**: `objSetHintTextIdx(int obj, u16 idx)` (`object.c:384`, declared in `game_object.h`) writes `((GameObject*)obj)->paletteIndex = idx` — a function literally named "set hint text index" writes the field this codebase calls `paletteIndex`. Strong rename candidate — see Ready-to-adopt below
`0xE9` `u8 seqCountE9` | `s8 unkE9`, **and** `objlib.c` defines `#define OBJCONTACT_OBJECT_REFCOUNT_OFFSET 0xe9` | offset matches; wiki's "seq count" vs this codebase's "contact-callback object refcount" disagree on purpose — open discrepancy
`0xEA` `u8` ("relates to freeing") | `u8 unkEA` | offset matches, not broken out yet
`0xEB` `u8 nChildren` | `u8 childCount`, **and** `objlib.c` defines `#define OBJLINK_CHILD_COUNT_OFFSET 0xeb` | exact offset + concept match, corroborated independently by `objlib.c`'s own define name
`0xEC` `GXColor colorEC` (4 bytes, r/g/b/a) | `u8 unkEC[3]` (`0xEC`-`0xEE`) + `s8 colorFadeAlpha` @`0xEF` | together span the same 4 bytes as wiki's `GXColor`; the last byte (alpha) already has a name on this side (`colorFadeAlpha`) consistent with GXColor's alpha channel
`0xF0` `u8` (unnamed) | `u8 fadeCounter` | offset matches; this codebase has a name, wiki doesn't
`0xF1` `u8 brightness`, `0xF2` `u8 colorIdx`, `0xF3` unknown | `u8 unkF1[3]` | offset span matches (3 bytes); wiki's names are plausible fill-ins for this codebase's `unkF1[3]` — see Ready-to-adopt below
`0xF3` unknown | also matches `objlib.c`'s `#define OBJ_MODEL_JOINT_COUNT_OFFSET 0xf3` | `objlib.c` independently names this byte "joint count" — resolves the wiki's `0xF3 ??`
`0xF4` `ObjInstanceFieldF4` (union; "SPitembeam stores LevelControl here") | `s32 unkF4` | offset matches (`unkF4 == 0xF4`); own comment calls this an "anim.c/campfire.c flag word" — consistent with wiki's "union, meaning varies by object" framing. `src/main/dll/SP/dll_0289_spitembeam.c` exists in this codebase (SPitembeam) but its use of this field wasn't traced in this pass
`0xF8` `ObjInstanceFieldF8` (union) | `s32 unkF8` | offset matches (`unkF8 == 0xF8`)
`0xFC` `Vec oldVel` | `f32 externalVelX/Y/Z` | offset matches (`externalVelX..externalVelZ == 0xFC-0x104`); own comment: "velocity imparted externally (carrier object's velocity / move-data velocity), added to `anim.velocity` in the localPos integration" — plausibly the same "old/other velocity" concept under a more specific name
`0x108` `cbAfterUpdateBones` callback | not modeled — `GameObject`'s own comment says "the record extends past 0x108; total size unverified; do not take `sizeof(GameObject)`" | not found; consistent with the wiki that there's more struct beyond this codebase's current `GameObject` tail

### Message Queue — confirmed field-for-field

`src/main/objlib.c` implements this section almost exactly:

- `#define OBJMSG_QUEUE_OFFSET 0xdc` — matches the wiki's field 0xDC precisely.
- `ObjMsgQueue { u32 count; u32 capacity; ObjMsgEntry entries[1]; }` — `count`/`capacity` are the
  wiki's `numMsgs`/`maxMsgs`.
- `ObjMsgEntry { u32 message; u32 sender; u32 param; }` — a byte-for-byte match of the wiki's
  `msg`/`from`/`param` triple.
- `ObjMsg_Peek` / `ObjMsg_Pop` (peek/pop, "normally done in the update method"), `ObjMsg_SendToObject`
  (direct-by-pointer send), `ObjMsg_SendToObjects` (send by defNo/category), `ObjMsg_SendToNearbyObjects`
  (send within radius), and `ObjMsg_AllocQueue` (the "size hard-coded in the object's setup method"
  allocator) cover every send/receive mode the wiki describes.
- `OBJMSG_SEND_INCLUDE_SENDER` / `OBJMSG_SEND_MATCH_ANY` / `OBJMSG_SEND_MATCH_OBJTYPE` flags on the
  send functions correspond to the wiki's "option to exclude itself" and "match by defNo or
  category" behavior.
- The overflow warning is a real retail string: `char sObjMsgOverflowInObjectWarning[] =
  "objmsg (%x): overflow in object %d defno=%d FROM: defno %d\n";` — matches the wiki's "an error
  message is printed to the console if any message is dropped".

### Category-ID (`classId`) sample cross-references

Beyond the ones already in the offset table above: `dll_020A_wmgeneralscales.c` (WM dir = wiki's
"Krazoa Palace / internally Warlock") is General Scales, plausibly related to the wiki's "0x2D
player weapon (and ScalesSword)" note, though not confirmed as the same object. `dll_0116_wmcolumn.c`
matches category `0x59 WM_Column` by name exactly. `dll_00EF_pushable.c`, `dll_0145_cloudprisoncontrol.c`,
`dll_0158_gunpowderbarrel.c`, `dll_023F_dbegg.c`, `dll_0143_feseqobject.c`, `dll_0019_dll19func0.c`,
`dll_0199_dll199.c`, and `dll_019B_dll19b.c` are the concrete DLLs behind the wiki's message-category
notes for "pushable object", "CloudPrisonControl", "GunPowderBarrel", "DB_egg", "FEseqobject", and
"DLL 0x19/0x199/0x19B" respectively (see Message Queue section above).

### Object Name prefixes — directory confirmation

`src/main/dll/` has per-area subdirectories that match many of the wiki's prefixes exactly, with
file names inside matching the wiki's per-object patterns (eg `dll_014F_cfprisonuncle.c` = CF +
"prison uncle", `dll_0153_cfperch.c` = CF + "perch", `dll_0154_cfprisoncage.c` = CF +
"prison cage", `dll_0164_cflevelcontrol.c` = CF + LevelControl): `ARW/`, `CC/`, `CF/`, `DF/`
(covers both Dfalls and DFP), `DIM/`, `DR/`, `IM/`, `LGT/`, `MMP/`, `NW/`, `SB/`, `SC/`, `SH/`,
`SP/`, `VF/` (wiki's VFP), `WC/`, `WM/`. Not found as directories: `AND`, `BGS`, `CFGC`, `CR`,
`DB`/`DBSH`, `ECSH`, `FE`, `GC`, `GF`/`GFRONT`, `GM`, `GPSH`, `KP`, `KT`, `LF`, `MC`, `MMSH`,
`OFP`, `SKY`, `WORLD` — those objects exist as loose files directly under `src/main/dll/` (eg
`dll_023F_dbegg.c` for DB) rather than in a subdirectory.

### `ObjectDescriptor` = wiki's `ObjDll`

`include/main/object_descriptor.h`'s `ObjectDescriptor` family (`initialise`, `release`, `init`,
`update`, `hitDetect`, `render`, `free`, `getObjectTypeId`, `getExtraSize` callback slots, plus
size-variant siblings `ObjectDescriptor11`..`ObjectDescriptor24` for classes with extra tail
callbacks) is this codebase's realization of the wiki's `ObjDll` — the vtable pointed to by
`ObjInstance.dll` @ `0xBC`/`ObjAnimComponent.dll` @ `0x68`.

### Not found in this codebase

- No `ObjCategory`, `ObjDefEnum`, `MapId8`, `HitboxMatrix`, `ObjTargetField78`, or `Shadow` type
  names exist verbatim — the corresponding data is present (see table above) under different
  names, or as raw ints/offsets.
- No enum or table of the wiki's ~130 category IDs (`0000`-`0083`, `FFFF`) exists in this
  codebase; every consumer spells the category out as a bare hex literal against `anim.classId`.
- `objects.xml` (referenced by the wiki for the full object-name list) is not part of this
  codebase; `docs/orig/object_catalog.md` / `tools/orig/object_catalog.py` are this project's own,
  independently-built cross-reference of `OBJECTS.bin`/`OBJECTS.tab`/`OBJINDEX.bin` and are worth
  reading alongside this page.

## Ready-to-adopt code

None of these are struct edits — they're maintainer-actionable notes backed by concrete evidence
found above. Do not apply directly; verify against the target function before touching a header.

1. **`ObjAnimComponent.seqId` (offset 0x46) is very likely misnamed — the retail debug string and
   this codebase's own `ObjList_FindNearestObjectByDefNo` call it `defno`.** A maintainer touching
   `include/main/objanim_internal.h` could rename with a comment:
   ```c
   s16 defNo; /* offset 0x46, aka ObjInstance.defNo on the wiki. Renamed from seqId: retail
                 debug string in objlib.c reads "...defno=%d..." from this field, and
                 ObjList_FindNearestObjectByDefNo(obj, defNo, ...) compares its defNo
                 parameter directly against this member. */
   ```

2. **`ObjAnimComponent.bankIndex` (offset 0xAD) may be better named around "active model index".**
   `src/main/objlib.c` already has `#define OBJ_ACTIVE_MODEL_INDEX_OFFSET 0xad` for the same byte,
   and the wiki independently calls it `curModel` ("which model index to use") — two out of three
   sources agree against the current header's `bankIndex`. Worth reconciling next time that field
   is touched, rather than renaming blindly (it is genuinely read as a bank index in some sites,
   eg `object.c:1634`'s `banks[bankIndex]`, so the two concepts may simply be the same array
   serving both roles).

3. **`GameObject.paletteIndex` (offset 0xE8) is confirmed by its own setter to be a hint-text
   index, not a palette index.** `object.c`'s `objSetHintTextIdx(int obj, u16 idx)` writes exactly
   this field. A maintainer could rename:
   ```c
   u8 hintTextIdx; /* obj+0xE8; renamed from paletteIndex - objSetHintTextIdx's own name and
                       body (object.c) confirm this is the sign/info-text hint index, not a
                       palette slot. Callers: dll_0121_infotext.c, CC/dll_0122_cctestinfot.c */
   ```

4. **`GameObject.unkF1[3]` (offsets 0xF1-0xF3) has wiki-sourced fill-in candidates worth checking
   against usage before adopting:**
   ```c
   u8 brightness; /* 0xF1, per wiki */
   u8 colorIdx;   /* 0xF2, per wiki */
   u8 pad;        /* 0xF3 - but see OBJ_MODEL_JOINT_COUNT_OFFSET 0xf3 in objlib.c, which
                      independently names this byte "joint count"; the two guesses conflict,
                      confirm against a real read site before picking one */
   ```

5. **A category-ID enum doesn't exist yet.** Every `anim.classId` comparison in this codebase
   spells its target out as a bare hex literal. Only the values this pass actually found compared
   live are listed below (not the full wiki table — see the "Object Categories" table above for
   the rest, unverified against this codebase):
   ```c
   /* ObjAnimComponent.classId (offset 0x44) - object category, wiki's ObjCategory/catId.
    * Only categories with a confirmed live == comparison in this codebase are named here. */
   #define OBJCATEGORY_PLAYER          0x0001 /* objseq.c, cutcam.c, objprint_dolphin.c, ... */
   #define OBJCATEGORY_TRICKY          0x0002 /* dll_00FB_pressureswitchfb.c */
   #define OBJCATEGORY_ANIMATEDOBJ     0x0010 /* object.c, objseq.c */
   #define OBJCATEGORY_UNUSED_SEQ03    0x0011 /* objseq.c:4113 - "checked for by seq cmd 0x03" */
   #define OBJCATEGORY_MOST_BADDIES    0x001C /* newseqobj.c, cutcam.c, dll_0049_cameramodecombat.c */
   #define OBJCATEGORY_ENEMY_MUSHROOM  0x002A /* cutcam.c, dll_0049_cameramodecombat.c */
   #define OBJCATEGORY_PLAYER_WEAPON   0x002D /* objprint.c - the player's staff */
   #define OBJCATEGORY_KT_REX          0x006D /* dll_0049_cameramodecombat.c - boss camera */
   ```
