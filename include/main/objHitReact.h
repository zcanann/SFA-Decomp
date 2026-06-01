#ifndef MAIN_OBJHITREACT_H_
#define MAIN_OBJHITREACT_H_

#include "global.h"
#include "ghidra_import.h"

typedef struct ObjHitReactEntry ObjHitReactEntry;
typedef struct ObjAnimBank ObjAnimBank;
typedef struct ObjAnimComponent ObjAnimComponent;

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
  s16 firstEntryOffset;
  s16 entryBytes;
} ObjHitReactMoveEntry;

#define OBJHITREACT_MAX_RESET_OBJECTS 0x32
#define OBJHITREACT_STATE_ACTIVE 0x01
#define OBJHITREACT_STATE_RESET_PENDING 0x08
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
#define OBJHITREACT_ENTRY_TAB_FILE_ID 0x41
#define OBJHITREACT_ENTRY_ARENA_BYTES 300
#define OBJHITREACT_ACTIVE_HITBOX_MODE 1
#define OBJHITREACT_RESET_MODE_MASK 0x30
#define OBJHITREACT_RESET_HITBOX_MODE 2

typedef struct ObjHitReactState {
  int activeHit;
  s16 activeEntryBytes;
  s16 entryByteCapacity;
  ObjHitReactEntry *entries;
  u8 pad0C[0x58 - 0x0C];
  s16 resetFrameCount;
  u8 pad5A[0x60 - 0x5A];
  s16 flags;
  u8 resetFlags;
  u8 pad63[0xAE - 0x63];
  u8 activeHitboxMode;
  u8 resetHitboxMode;
} ObjHitReactState;

struct ObjHitReactEntry {
  s16 hitSfxA;
  s16 hitSfxB;
  s16 reactionAnim;
  u8 pad06[2];
  u8 hitFxMode;
  u8 pad09[3];
  f32 cooldown;
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
STATIC_ASSERT(offsetof(ObjHitReactMoveEntry, firstEntryOffset) == 0x02);
STATIC_ASSERT(offsetof(ObjHitReactMoveEntry, entryBytes) == 0x04);

STATIC_ASSERT(sizeof(ObjHitReactState) == 0xB0);
STATIC_ASSERT(offsetof(ObjHitReactState, activeHit) == 0x00);
STATIC_ASSERT(offsetof(ObjHitReactState, activeEntryBytes) == 0x04);
STATIC_ASSERT(offsetof(ObjHitReactState, entryByteCapacity) == 0x06);
STATIC_ASSERT(offsetof(ObjHitReactState, entries) == 0x08);
STATIC_ASSERT(offsetof(ObjHitReactState, resetFrameCount) == 0x58);
STATIC_ASSERT(offsetof(ObjHitReactState, flags) == 0x60);
STATIC_ASSERT(offsetof(ObjHitReactState, resetFlags) == 0x62);
STATIC_ASSERT(offsetof(ObjHitReactState, activeHitboxMode) == 0xAE);
STATIC_ASSERT(offsetof(ObjHitReactState, resetHitboxMode) == 0xAF);

STATIC_ASSERT(sizeof(ObjHitReactEntry) == 0x14);
STATIC_ASSERT(offsetof(ObjHitReactEntry, hitSfxA) == 0x00);
STATIC_ASSERT(offsetof(ObjHitReactEntry, hitSfxB) == 0x02);
STATIC_ASSERT(offsetof(ObjHitReactEntry, reactionAnim) == 0x04);
STATIC_ASSERT(offsetof(ObjHitReactEntry, hitFxMode) == 0x08);
STATIC_ASSERT(offsetof(ObjHitReactEntry, cooldown) == 0x0C);

int objHitReact_update(int obj,ObjHitReactEntry *reactionEntries,u32 reactionEntryCount,
                       u32 reactionState,float *reactionStepScale);
void ObjHitReact_ResetActiveObjects(int objectCount);
void ObjHitReact_LoadMoveEntries(int objAnim,ObjAnimBank *bank,int objType,
                                 ObjHitReactState *hitState,int moveId,int async);
uint ObjHitReact_InitState(int objType,ObjAnimBank *bank,ObjHitReactState *hitState,
                           uint entryArena,int objAnim);
void ObjHitReact_UpdateResetObjects(void);
ObjAnimComponent **ObjHitReact_GetResetObjects(int *outObjectCount);

#define objHitReactFn_80089890 objHitReact_update

#endif /* MAIN_OBJHITREACT_H_ */
