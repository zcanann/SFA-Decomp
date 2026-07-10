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
#include "main/dll/DR/dll_0265_drcreator.h"

#define DRCREATOR_CHILD_OBJ_PROJECTILE 1725

int DR_Creator_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    int placement = *(int*)&(obj)->anim.placementData;
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
            runtime = (obj)->extra;
            if (mainGetBit(((DrcreatorSpawnProjectileCallbackState*)runtime)->spawnGameBit) != 0)
            {
                setup = Obj_AllocObjectSetup(36, DRCREATOR_CHILD_OBJ_PROJECTILE);
                ((DrcreatorSetup*)setup)->base.posX = (obj)->anim.localPosX;
                ((DrcreatorSetup*)setup)->base.posY = (obj)->anim.localPosY;
                ((DrcreatorSetup*)setup)->base.posZ = (obj)->anim.localPosZ;
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
                    ((DrcreatorState*)projectile)->creatorObj = (int)obj;
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

void DR_Creator_update(GameObject* obj)
{
    int placement = *(int*)&(obj)->anim.placementData;
    char* runtime = (obj)->extra;
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
                    ((DrcreatorSetup*)setup)->base.posX = (obj)->anim.localPosX;
                    ((DrcreatorSetup*)setup)->base.posY = (obj)->anim.localPosY;
                    ((DrcreatorSetup*)setup)->base.posZ = (obj)->anim.localPosZ;
                    ((DrcreatorSetup*)setup)->base.color[0] = 1;
                    ((DrcreatorSetup*)setup)->base.color[1] = 1;
                    ((DrcreatorSetup*)setup)->base.color[2] = 255;
                    ((DrcreatorSetup*)setup)->base.color[3] = 250;
                    if ((obj)->anim.mapEventSlot == 2)
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
                            (lbl_803E69BC * ((f32) * (int*)runtime *
                                             -mathSinf((lbl_803E69C0 * (f32)(obj)->anim.rotX) / lbl_803E69C4)));
                        ((DrcreatorState*)projectile)->velocityY =
                            lbl_803E69B8 * ((f32) * (int*)runtime * (lbl_803E69C8 * (f32)(int)randomGetRange(0, 1000)));
                        ((DrcreatorState*)projectile)->velocityZ =
                            lbl_803E69B8 *
                            (lbl_803E69BC * ((f32) * (int*)runtime *
                                             -mathCosf((lbl_803E69C0 * (f32)(obj)->anim.rotX) / lbl_803E69C4)));
                        ((DrcreatorState*)projectile)->creatorObj = (int)obj;
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

void DR_Creator_init(GameObject* obj, char* arg)
{
    char* state = obj->extra;
    obj->anim.rotX = (s16)(((DrcreatorPlacement*)arg)->rotXByte << 8);
    ((DrcreatorState*)state)->gameBitId = ((DrcreatorPlacement*)arg)->gameBitId;
    ((DrcreatorState*)state)->spawnInterval = ((DrcreatorPlacement*)arg)->spawnInterval;
    ((DrcreatorState*)state)->spawnTimer = randomGetRange(0, ((DrcreatorState*)state)->spawnInterval);
    ((DrcreatorState*)state)->timerVariance = ((DrcreatorPlacement*)arg)->timerVariance;
    *(int*)state = ((DrcreatorPlacement*)arg)->speedScale;
    ((BitFlags8*)(state + 0x18))->b0 = 1;
    mainSetBits(0x5dd, 0);
    obj->animEventCallback = DR_Creator_SeqFn;
}

void DR_Creator_release(void)
{
}

void DR_Creator_initialise(void)
{
}

char sDrCreatorTimeFormat[15] = " Time %i : %i \000";
