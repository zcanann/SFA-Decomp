#ifndef MAIN_OBJHITREACT_H_
#define MAIN_OBJHITREACT_H_

#include "global.h"
#include "main/pi_dolphin.h"

typedef struct ObjHitReactEntry ObjHitReactEntry;
typedef struct ObjAnimBank ObjAnimBank;
typedef struct ObjAnimComponent ObjAnimComponent;
typedef struct ObjHitbox ObjHitbox;

typedef struct ObjHitReactEffectPos {
  s16 x;
  s16 y;
  s16 z;
  u8 pad06[2];
  f32 scale;
} ObjHitReactEffectPos;

typedef struct ObjHitReactEffectColorArgs {
  u32 hitFxMode;
  u32 colorR;
  u32 colorG;
  u32 colorB;
} ObjHitReactEffectColorArgs;

typedef void (*ObjHitReactEffectSpawnFn)(int parent,int mode,ObjHitReactEffectPos *pos,
                                         u32 flags,int sequenceId,void *args);

typedef struct ObjHitReactEffectVTable {
  void *pad00;
  ObjHitReactEffectSpawnFn spawn;
} ObjHitReactEffectVTable;

typedef struct ObjHitReactEffectHandle {
  ObjHitReactEffectVTable *vtable;
} ObjHitReactEffectHandle;

typedef struct ObjHitReactMoveEntry {
  s16 moveId;
  s16 firstEntryByteOffset;
  s16 entryByteCount;
} ObjHitReactMoveEntry;

extern ObjHitReactEffectColorArgs gObjHitReactEffectColorArgs;
extern char sObjHitReactHitstateFrameString[];
extern char sObjHitReactSphereOverflowString[];
extern char sObjHitReactResetString[7];
extern f32 gObjHitReactAltEffectScale;
extern int gObjHitReactResetObjectCount;
extern ObjAnimComponent **gObjHitReactResetObjects;

#define OBJHITREACT_MAX_RESET_OBJECTS 0x32
#define OBJHITREACT_REACTION_STATE_MASK 0xff
#define OBJHITREACT_ENTRY_COUNT_MASK 0xff
#define OBJHITREACT_REACTION_STATE_INACTIVE 0
#define OBJHITREACT_REACTION_STATE_ACTIVE 1
#define OBJHITREACT_COLLISION_SKIP_REACTION 0x11
#define OBJHITREACT_NO_SFX_ID -1
#define OBJHITREACT_NO_REACTION_ANIM -1
#define OBJHITREACT_HIT_FX_MODE_EFFECT 1
#define OBJHITREACT_HIT_EFFECT_ID 0x5A
#define OBJHITREACT_HIT_EFFECT_RESOURCE_COUNT 1
#define OBJHITREACT_HIT_EFFECT_PARENT_NONE 0
#define OBJHITREACT_HIT_EFFECT_MODE 1
#define OBJHITREACT_HIT_EFFECT_SPAWN_FLAGS 0x401
#define OBJHITREACT_HIT_EFFECT_NO_SOURCE -1
#define OBJHITREACT_ALT_EFFECT_COUNT 1
#define OBJHITREACT_RESET_FRAME_COUNT 0x400
#define OBJHITREACT_ENTRY_TAB_FILE_ID MLDF_FILEID_OBJHITS_BIN
#define OBJHITREACT_ENTRY_ARENA_BYTES 300
#define OBJHITREACT_ACTIVE_HITBOX_MODE 1
#define OBJHITREACT_SHAPE_RESET_UPDATE 0x08
#define OBJHITREACT_RESET_HITBOX_MODE 2
#define OBJHITREACT_DISABLED_HITBOX_MODE 0x64
#define OBJHITREACT_MOVE_ID_END -1
#define OBJHITREACT_MOVE_ENTRY_SHORT_COUNT 3

typedef struct ObjHitReactState {
  int activeHit;
  s16 activeEntryByteCount;
  s16 entryBufferByteCapacity;
  ObjHitReactEntry *entries;
  u8 pad0C[0x58 - 0x0C];
  s16 resetFrameCount;
  u8 pad5A[0x60 - 0x5A];
  s16 flags;
  u8 shapeFlags;
  u8 pad63[0xAE - 0x63];
  u8 activeHitboxMode;
  u8 resetHitboxMode;
} ObjHitReactState;

struct ObjHitReactEntry {
  s16 primaryHitSfxId;
  s16 secondaryHitSfxId;
  s16 reactionMoveId;
  u8 pad06[2];
  u8 hitEffectMode;
  u8 pad09[3];
  f32 reactionStepScale;
  u8 pad10[4];
};

STATIC_ASSERT(sizeof(ObjHitReactEffectPos) == 0x0C);
STATIC_ASSERT(offsetof(ObjHitReactEffectPos, x) == 0x00);
STATIC_ASSERT(offsetof(ObjHitReactEffectPos, y) == 0x02);
STATIC_ASSERT(offsetof(ObjHitReactEffectPos, z) == 0x04);
STATIC_ASSERT(offsetof(ObjHitReactEffectPos, scale) == 0x08);

STATIC_ASSERT(sizeof(ObjHitReactEffectColorArgs) == 0x10);
STATIC_ASSERT(offsetof(ObjHitReactEffectVTable, spawn) == 0x04);
STATIC_ASSERT(offsetof(ObjHitReactEffectHandle, vtable) == 0x00);

STATIC_ASSERT(sizeof(ObjHitReactMoveEntry) == 0x06);
STATIC_ASSERT(offsetof(ObjHitReactMoveEntry, moveId) == 0x00);
STATIC_ASSERT(offsetof(ObjHitReactMoveEntry, firstEntryByteOffset) == 0x02);
STATIC_ASSERT(offsetof(ObjHitReactMoveEntry, entryByteCount) == 0x04);

STATIC_ASSERT(sizeof(ObjHitReactState) == 0xB0);
STATIC_ASSERT(offsetof(ObjHitReactState, activeHit) == 0x00);
STATIC_ASSERT(offsetof(ObjHitReactState, activeEntryByteCount) == 0x04);
STATIC_ASSERT(offsetof(ObjHitReactState, entryBufferByteCapacity) == 0x06);
STATIC_ASSERT(offsetof(ObjHitReactState, entries) == 0x08);
STATIC_ASSERT(offsetof(ObjHitReactState, resetFrameCount) == 0x58);
STATIC_ASSERT(offsetof(ObjHitReactState, flags) == 0x60);
STATIC_ASSERT(offsetof(ObjHitReactState, shapeFlags) == 0x62);
STATIC_ASSERT(offsetof(ObjHitReactState, activeHitboxMode) == 0xAE);
STATIC_ASSERT(offsetof(ObjHitReactState, resetHitboxMode) == 0xAF);

STATIC_ASSERT(sizeof(ObjHitReactEntry) == 0x14);
STATIC_ASSERT(offsetof(ObjHitReactEntry, primaryHitSfxId) == 0x00);
STATIC_ASSERT(offsetof(ObjHitReactEntry, secondaryHitSfxId) == 0x02);
STATIC_ASSERT(offsetof(ObjHitReactEntry, reactionMoveId) == 0x04);
STATIC_ASSERT(offsetof(ObjHitReactEntry, hitEffectMode) == 0x08);
STATIC_ASSERT(offsetof(ObjHitReactEntry, reactionStepScale) == 0x0C);

int ObjHitReact_Update(int obj,ObjHitReactEntry *reactionEntryTable,u32 reactionEntryCount,
                       u32 reactionState,float *reactionStepScale);
void ObjHitReact_ResetActiveObjects(int objectCount);
int ObjHitbox_AllocRotatedBounds(ObjHitbox *hitbox,u32 arena);
void ObjHitReact_LoadMoveEntries(ObjAnimComponent *objAnim,ObjAnimBank *bank,int objType,
                                 ObjHitReactState *hitState,int moveId,int async);
u32 ObjHitReact_InitState(int objType,ObjAnimBank *bank,ObjHitReactState *hitState,
                          u32 entryArena,ObjAnimComponent *objAnim);
void ObjHitReact_UpdateResetObjects(void);
ObjAnimComponent **ObjHitReact_GetResetObjects(int *outObjectCount);

#endif /* MAIN_OBJHITREACT_H_ */
