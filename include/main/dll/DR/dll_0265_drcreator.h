#ifndef MAIN_DLL_DR_DLL_0265_DRCREATOR_H_
#define MAIN_DLL_DR_DLL_0265_DRCREATOR_H_

#include "global.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

/* Obj_AllocObjectSetup(36,...) buffer composed in DR_Creator_update and
 * DR_Creator_SeqFn. Head is the common ObjPlacement;
 * tail (0x18..0x23) is file-local. */
typedef struct DrcreatorSetup
{
    ObjPlacement base; /* 0x00..0x17 */
    u8 pad18;          /* 0x18 */
    u8 unk19;          /* 0x19 */
    u8 pad1A[0x24 - 0x1A];
} DrcreatorSetup;

STATIC_ASSERT(offsetof(DrcreatorSetup, unk19) == 0x19);
STATIC_ASSERT(sizeof(DrcreatorSetup) == 0x24);

typedef struct DrcreatorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 gameBitId;     /* 0x18: copied into runtime gameBitId */
    s16 behaviorMode;  /* 0x1A switch selector: 3/9 run-sequence, 4 spawn-projectiles */
    s16 spawnInterval; /* 0x1C: copied into runtime spawnInterval */
    s8 rotXByte;       /* 0x1E: <<8 seeds anim.rotX */
    s8 timerVariance;  /* 0x1F: copied into runtime timerVariance */
    u8 speedScale;     /* 0x20: projectile speed scalar, stored at runtime[0] */
} DrcreatorPlacement;

STATIC_ASSERT(offsetof(DrcreatorPlacement, behaviorMode) == 0x1A);
STATIC_ASSERT(offsetof(DrcreatorPlacement, speedScale) == 0x20);
STATIC_ASSERT(sizeof(DrcreatorPlacement) == 0x22);

typedef struct DrcreatorSpawnProjectileCallbackState
{
    u8 pad0[0x4 - 0x0];
    s16 spawnGameBit;
    u8 pad6[0xA - 0x6];
    s16 velocitySpread;
    u8 padC[0x10 - 0xC];
} DrcreatorSpawnProjectileCallbackState;

typedef struct DrcreatorState
{
    u8 pad0[0x2 - 0x0];
    s16 unk2;          /* 0x2 */
    s16 gameBitId;     /* 0x4 */
    s16 spawnInterval; /* 0x6: base interval reloaded into spawnTimer */
    s16 spawnTimer;    /* 0x8 */
    s16 timerVariance; /* 0xA */
    u8 padC[0x24 - 0xC];
    f32 velocityX; /* 0x24 */
    f32 velocityY; /* 0x28 */
    f32 velocityZ; /* 0x2C */
    u8 pad30[0xC4 - 0x30];
    s32 creatorObj; /* 0xC4 */
} DrcreatorState;

STATIC_ASSERT(offsetof(DrcreatorState, gameBitId) == 0x4);
STATIC_ASSERT(offsetof(DrcreatorState, spawnTimer) == 0x8);
STATIC_ASSERT(offsetof(DrcreatorState, velocityX) == 0x24);
STATIC_ASSERT(offsetof(DrcreatorState, velocityY) == 0x28);
STATIC_ASSERT(offsetof(DrcreatorState, velocityZ) == 0x2C);
STATIC_ASSERT(offsetof(DrcreatorState, creatorObj) == 0xC4);

int DR_Creator_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
int DR_Creator_getExtraSize(void);
int DR_Creator_getObjectTypeId(void);
void DR_Creator_free(void);
void DR_Creator_render(void);
void DR_Creator_hitDetect(void);
void DR_Creator_update(int obj);
void DR_Creator_init(int obj, char* arg);
void DR_Creator_release(void);
void DR_Creator_initialise(void);

#endif /* MAIN_DLL_DR_DLL_0265_DRCREATOR_H_ */
