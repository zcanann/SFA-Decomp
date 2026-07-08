/*
 * drcreator (DLL 0x265) - a spawner that periodically emits projectile
 * objects while the level is loaded and its arming game bit is set.
 * Spawn cadence is driven by spawnTimer/spawnInterval/timerVariance; each
 * projectile is launched with a velocity derived from the creator's
 * facing (DR_Creator_update) or a randomised spread
 * (DR_Creator_SeqFn).
 */
#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

#define DRCREATOR_CHILD_OBJ_PROJECTILE 1725

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

int DR_Creator_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    int placement = *(int*)&((GameObject*)obj)->anim.placementData;
    char* runtime;
    int setup;
    int projectile;
    logPrintf(sDrCreatorTimeFormat, *(s16*)(placement + 0x1a), *(s16*)((u8*)animUpdate + 0x58));
    if (Obj_IsLoadingLocked() == 0)
    {
        return 0;
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (((DrcreatorPlacement*)placement)->behaviorMode)
        {
        case 3:
        case 4:
        case 9:
            runtime = ((GameObject*)obj)->extra;
            if (mainGetBit(((DrcreatorSpawnProjectileCallbackState*)runtime)->spawnGameBit) != 0)
            {
                setup = Obj_AllocObjectSetup(36, DRCREATOR_CHILD_OBJ_PROJECTILE);
                ((DrcreatorSetup*)setup)->base.posX = ((GameObject*)obj)->anim.localPosX;
                ((DrcreatorSetup*)setup)->base.posY = ((GameObject*)obj)->anim.localPosY;
                ((DrcreatorSetup*)setup)->base.posZ = ((GameObject*)obj)->anim.localPosZ;
                ((DrcreatorSetup*)setup)->base.color[0] = 1;
                ((DrcreatorSetup*)setup)->base.color[1] = 1;
                ((DrcreatorSetup*)setup)->base.color[2] = 255;
                ((DrcreatorSetup*)setup)->base.color[3] = 255;
                ((DrcreatorSetup*)setup)->unk19 = 2;
                projectile = Obj_SetupObject(setup, 5, -1, -1, 0);
                if ((void*)projectile != NULL)
                {
                    ((DrcreatorState*)projectile)->unk2 = 0;
                    ((GameObject*)projectile)->anim.rotX = randomGetRange(0, 65535);
                    ((DrcreatorState*)projectile)->velocityX =
                        lbl_803E69A8 *
                        (f32)(int)randomGetRange(-((DrcreatorSpawnProjectileCallbackState*)runtime)->velocitySpread,
                                                 ((DrcreatorSpawnProjectileCallbackState*)runtime)->velocitySpread);
                    ((DrcreatorState*)projectile)->velocityY = lbl_803E69A8 * (f32) * (int*)runtime;
                    ((DrcreatorState*)projectile)->velocityZ =
                        lbl_803E69A8 *
                        (f32)(int)randomGetRange(-((DrcreatorSpawnProjectileCallbackState*)runtime)->velocitySpread,
                                                 ((DrcreatorSpawnProjectileCallbackState*)runtime)->velocitySpread);
                    ((DrcreatorState*)projectile)->creatorObj = obj;
                }
            }
            break;
        }
    }
    return 0;
}

int DR_Creator_getExtraSize(void)
{
    return 0x1c;
}

int DR_Creator_getObjectTypeId(void)
{
    return 0x0;
}

void DR_Creator_free(void)
{
}

void DR_Creator_render(void)
{
}

void DR_Creator_hitDetect(void)
{
}

void DR_Creator_update(int obj)
{
    int placement = *(int*)&((GameObject*)obj)->anim.placementData;
    char* runtime = ((GameObject*)obj)->extra;
    int setup;
    char* projectile;
    if (Obj_IsLoadingLocked() != 0)
    {
        switch (((DrcreatorPlacement*)placement)->behaviorMode)
        {
        case 3:
        case 9:
            if (mainGetBit(((DrcreatorState*)runtime)->gameBitId) != 0)
            {
                (*gObjectTriggerInterface)
                    ->runSequence((((DrcreatorPlacement*)placement)->behaviorMode == 3) ? 0 : 4, (void*)obj, -1);
            }
            break;
        case 4:
            if (mainGetBit(((DrcreatorState*)runtime)->gameBitId) != 0)
            {
                ((DrcreatorState*)runtime)->spawnTimer -= framesThisStep;
                if (((DrcreatorState*)runtime)->spawnTimer <= 0)
                {
                    setup = Obj_AllocObjectSetup(36, DRCREATOR_CHILD_OBJ_PROJECTILE);
                    ((DrcreatorSetup*)setup)->base.posX = ((GameObject*)obj)->anim.localPosX;
                    ((DrcreatorSetup*)setup)->base.posY = ((GameObject*)obj)->anim.localPosY;
                    ((DrcreatorSetup*)setup)->base.posZ = ((GameObject*)obj)->anim.localPosZ;
                    ((DrcreatorSetup*)setup)->base.color[0] = 1;
                    ((DrcreatorSetup*)setup)->base.color[1] = 1;
                    ((DrcreatorSetup*)setup)->base.color[2] = 255;
                    ((DrcreatorSetup*)setup)->base.color[3] = 250;
                    if (((GameObject*)obj)->anim.mapEventSlot == 2)
                    {
                        ((DrcreatorSetup*)setup)->unk19 = 4;
                    }
                    else
                    {
                        ((DrcreatorSetup*)setup)->unk19 = 1;
                    }
                    projectile = (char*)Obj_SetupObject(setup, 5, -1, -1, 0);
                    if (projectile != NULL)
                    {
                        ((DrcreatorState*)projectile)->unk2 = 0;
                        ((GameObject*)projectile)->anim.rotX = randomGetRange(0, 65535);
                        ((DrcreatorState*)projectile)->velocityX =
                            lbl_803E69B8 *
                            (lbl_803E69BC *
                             ((f32) * (int*)runtime *
                              -mathSinf((lbl_803E69C0 * (f32)((GameObject*)obj)->anim.rotX) / lbl_803E69C4)));
                        ((DrcreatorState*)projectile)->velocityY =
                            lbl_803E69B8 * ((f32) * (int*)runtime * (lbl_803E69C8 * (f32)(int)randomGetRange(0, 1000)));
                        ((DrcreatorState*)projectile)->velocityZ =
                            lbl_803E69B8 *
                            (lbl_803E69BC *
                             ((f32) * (int*)runtime *
                              -mathCosf((lbl_803E69C0 * (f32)((GameObject*)obj)->anim.rotX) / lbl_803E69C4)));
                        ((DrcreatorState*)projectile)->creatorObj = obj;
                    }
                    ((DrcreatorState*)runtime)->spawnTimer =
                        ((DrcreatorState*)runtime)->spawnInterval +
                        randomGetRange(0, ((DrcreatorState*)runtime)->timerVariance);
                }
            }
            break;
        }
    }
}

void DR_Creator_init(int obj, char* arg)
{
    char* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)(((DrcreatorPlacement*)arg)->rotXByte << 8);
    ((DrcreatorState*)state)->gameBitId = ((DrcreatorPlacement*)arg)->gameBitId;
    ((DrcreatorState*)state)->spawnInterval = ((DrcreatorPlacement*)arg)->spawnInterval;
    ((DrcreatorState*)state)->spawnTimer = randomGetRange(0, ((DrcreatorState*)state)->spawnInterval);
    ((DrcreatorState*)state)->timerVariance = ((DrcreatorPlacement*)arg)->timerVariance;
    *(int*)state = ((DrcreatorPlacement*)arg)->speedScale;
    ((BitFlags8*)(state + 0x18))->b0 = 1;
    mainSetBits(0x5dd, 0);
    ((GameObject*)obj)->animEventCallback = DR_Creator_SeqFn;
}

void DR_Creator_release(void)
{
}

void DR_Creator_initialise(void)
{
}

char sDrCreatorTimeFormat[15] = " Time %i : %i \000";
