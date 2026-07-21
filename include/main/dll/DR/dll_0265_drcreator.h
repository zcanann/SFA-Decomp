#ifndef MAIN_DLL_DR_DLL_0265_DRCREATOR_H_
#define MAIN_DLL_DR_DLL_0265_DRCREATOR_H_

#include "main/game_object.h"
#include "global.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

extern char sDrCreatorTimeFormat[];
extern ObjectDescriptor gDrCreatorObjDescriptor;

typedef enum DrcreatorBehaviorMode
{
    DRCREATOR_BEHAVIOR_SEQUENCE_0 = 3,
    DRCREATOR_BEHAVIOR_TIMED_PROJECTILES = 4,
    DRCREATOR_BEHAVIOR_SEQUENCE_4 = 9
} DrcreatorBehaviorMode;

/* DRHomingMis setup buffer composed in DR_Creator_update and
 * DR_Creator_SeqFn. Head is the common ObjPlacement;
 * tail (0x18..0x23) is file-local. */
typedef struct DrcreatorSetup
{
    ObjPlacement base; /* 0x00..0x17 */
    u8 pad18;          /* 0x18 */
    u8 projectileVariant; /* 0x19: DRHomingMis setup variant */
    u8 pad1A[0x24 - 0x1A];
} DrcreatorSetup;

STATIC_ASSERT(offsetof(DrcreatorSetup, projectileVariant) == 0x19);
STATIC_ASSERT(sizeof(DrcreatorSetup) == 0x24);

typedef struct DrcreatorPlacement
{
    ObjPlacement base;
    s16 spawnGameBit;  /* 0x18: enables sequences/projectile spawning */
    s16 behaviorMode;  /* 0x1A: DrcreatorBehaviorMode */
    s16 spawnInterval; /* 0x1C: copied into runtime spawnInterval */
    s8 rotX;           /* 0x1E: 1/256-turn initial pitch */
    s8 timerVariance;  /* 0x1F: copied into runtime timerVariance */
    u8 speedScale;     /* 0x20: projectile speed scalar, stored at runtime[0] */
} DrcreatorPlacement;

STATIC_ASSERT(offsetof(DrcreatorPlacement, spawnGameBit) == 0x18);
STATIC_ASSERT(offsetof(DrcreatorPlacement, behaviorMode) == 0x1A);
STATIC_ASSERT(offsetof(DrcreatorPlacement, speedScale) == 0x20);
STATIC_ASSERT(sizeof(DrcreatorPlacement) == 0x24);

typedef struct DrcreatorStateFlags
{
    u8 initialized : 1; /* set by DR_Creator_init; reader not yet recovered */
    u8 unk1 : 1;
    u8 unk2 : 1;
    u8 unk3 : 1;
    u8 unk4 : 1;
    u8 unk5 : 1;
    u8 unk6 : 1;
    u8 unk7 : 1;
} DrcreatorStateFlags;

typedef struct DrcreatorState
{
    s32 speedScale;    /* 0x0: magnitude used for DRHomingMis velocity */
    s16 spawnGameBit;  /* 0x4 */
    s16 spawnInterval; /* 0x6: base interval reloaded into spawnTimer */
    s16 spawnTimer;    /* 0x8 */
    union {
        s16 timerVariance;  /* timed-spawn random delay */
        s16 velocitySpread; /* sequence-event X/Z launch spread */
    };
    u8 padC[0x18 - 0xC];
    DrcreatorStateFlags flags;
    u8 pad19[0x1C - 0x19];
} DrcreatorState;

STATIC_ASSERT(offsetof(DrcreatorState, speedScale) == 0x0);
STATIC_ASSERT(offsetof(DrcreatorState, spawnGameBit) == 0x4);
STATIC_ASSERT(offsetof(DrcreatorState, spawnTimer) == 0x8);
STATIC_ASSERT(offsetof(DrcreatorState, flags) == 0x18);
STATIC_ASSERT(sizeof(DrcreatorState) == 0x1C);

int DR_Creator_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int DR_Creator_getExtraSize(void);
int DR_Creator_getObjectTypeId(void);
void DR_Creator_free(void);
void DR_Creator_render(void);
void DR_Creator_hitDetect(void);
void DR_Creator_update(GameObject* obj);
void DR_Creator_init(GameObject* obj, DrcreatorPlacement* placement);
void DR_Creator_release(void);
void DR_Creator_initialise(void);

extern const f32 lbl_803E69A8;

#endif /* MAIN_DLL_DR_DLL_0265_DRCREATOR_H_ */
