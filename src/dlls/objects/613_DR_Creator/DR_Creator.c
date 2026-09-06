/*
 * DR_Creator (DLL 613) - a spawner that periodically emits projectile
 * objects while the level is loaded and its arming game bit is set.
 * Spawn cadence is driven by spawnTimer/spawnInterval/timerVariance; each
 * projectile is launched with a velocity derived from the creator's
 * facing (DR_Creator_update) or a randomised spread
 * (DR_Creator_SeqFn).
 */
#include "main/dll/DR/dll_0265_drcreator.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/debug.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "sys/objects/lifecycle.h"
#include "sys/objects.h"
#include "main/objseq.h"
#include "main/vecmath.h"

#define DRCREATOR_CHILD_OBJ_DRHOMINGMIS 1725
#define DRCREATOR_INIT_CLEAR_GAMEBIT 0x5DD

int DR_Creator_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate)
{
    int i;
    DrcreatorPlacement* placement = (DrcreatorPlacement*)obj->anim.placementData;
    DrcreatorState* state;
    DrcreatorSetup* setup;
    GameObject* projectile;
    logPrintf(sDrCreatorTimeFormat, placement->behaviorMode, animUpdate->curFrame);
    if ((u8)Obj_CanSetupObject() == 0)
    {
        return 0;
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (placement->behaviorMode)
        {
        case DRCREATOR_BEHAVIOR_SEQUENCE_0:
        case DRCREATOR_BEHAVIOR_TIMED_PROJECTILES:
        case DRCREATOR_BEHAVIOR_SEQUENCE_4:
            state = obj->extra;
            if (mainGetBit(state->spawnGameBit) != 0)
            {
                setup = (DrcreatorSetup*)Obj_AllocObjectSetup(sizeof(DrcreatorSetup), DRCREATOR_CHILD_OBJ_DRHOMINGMIS);
                setup->base.posX = obj->anim.localPosX;
                setup->base.posY = obj->anim.localPosY;
                setup->base.posZ = obj->anim.localPosZ;
                setup->base.color[0] = 1;
                setup->base.color[1] = 1;
                setup->base.color[2] = 255;
                setup->base.color[3] = 255;
                setup->projectileVariant = 2;
                projectile = objSetupObject(&setup->base, 5, -1, -1, NULL);
                if (projectile != NULL)
                {
                    projectile->anim.rotY = 0;
                    projectile->anim.rotX = randomGetRange(0, 65535);
                    projectile->anim.velocityX =
                        0.2f *
                        randomGetRange(-state->velocitySpread, state->velocitySpread);
                    projectile->anim.velocityY = 0.2f * (f32)state->speedScale;
                    projectile->anim.velocityZ =
                        0.2f *
                        randomGetRange(-state->velocitySpread, state->velocitySpread);
                    projectile->ownerObj = obj;
                }
            }
            break;
        }
    }
    return 0;
}

int DR_Creator_getExtraSize(void)
{
    return sizeof(DrcreatorState);
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
    DrcreatorPlacement* placement = (DrcreatorPlacement*)obj->anim.placementData;
    DrcreatorState* state = obj->extra;
    DrcreatorSetup* setup;
    GameObject* projectile;
    if ((u8)Obj_CanSetupObject() != 0)
    {
        switch (placement->behaviorMode)
        {
        case DRCREATOR_BEHAVIOR_SEQUENCE_0:
        case DRCREATOR_BEHAVIOR_SEQUENCE_4:
            if (mainGetBit(state->spawnGameBit) != 0)
            {
                (*gObjectTriggerInterface)->runSequence(
                    (placement->behaviorMode == DRCREATOR_BEHAVIOR_SEQUENCE_0) ? 0 : 4, (void*)obj, -1);
            }
            break;
        case DRCREATOR_BEHAVIOR_TIMED_PROJECTILES:
            if (mainGetBit(state->spawnGameBit) != 0)
            {
                state->spawnTimer -= framesThisStep;
                if (state->spawnTimer <= 0)
                {
                    setup = (DrcreatorSetup*)Obj_AllocObjectSetup(sizeof(DrcreatorSetup), DRCREATOR_CHILD_OBJ_DRHOMINGMIS);
                    setup->base.posX = obj->anim.localPosX;
                    setup->base.posY = obj->anim.localPosY;
                    setup->base.posZ = obj->anim.localPosZ;
                    setup->base.color[0] = 1;
                    setup->base.color[1] = 1;
                    setup->base.color[2] = 255;
                    setup->base.color[3] = 250;
                    if (obj->anim.mapEventSlot == 2)
                    {
                        setup->projectileVariant = 4;
                    }
                    else
                    {
                        setup->projectileVariant = 1;
                    }
                    projectile = objSetupObject(&setup->base, 5, -1, -1, NULL);
                    if (projectile != NULL)
                    {
                        projectile->anim.rotY = 0;
                        projectile->anim.rotX = randomGetRange(0, 65535);
                        projectile->anim.velocityX =
                            0.03f *
                            (10.0f * ((f32)state->speedScale *
                                             -mathSinf((3.14159274f * (f32)obj->anim.rotX) / 32768.0f)));
                        projectile->anim.velocityY =
                            0.03f * ((f32)state->speedScale * (0.01f * randomGetRange(0, 1000)));
                        projectile->anim.velocityZ =
                            0.03f *
                            (10.0f * ((f32)state->speedScale *
                                             -mathCosf((3.14159274f * (f32)obj->anim.rotX) / 32768.0f)));
                        projectile->ownerObj = obj;
                    }
                    state->spawnTimer = state->spawnInterval + randomGetRange(0, state->timerVariance);
                }
            }
            break;
        }
    }
}

void DR_Creator_init(GameObject* obj, DrcreatorPlacement* placement)
{
    DrcreatorState* state = obj->extra;
    obj->anim.rotX = (s16)(placement->rotX << 8);
    state->spawnGameBit = placement->spawnGameBit;
    state->spawnInterval = placement->spawnInterval;
    state->spawnTimer = randomGetRange(0, state->spawnInterval);
    state->timerVariance = placement->timerVariance;
    state->speedScale = placement->speedScale;
    state->flags.initialized = 1;
    mainSetBits(DRCREATOR_INIT_CLEAR_GAMEBIT, 0);
    obj->animEventCallback = DR_Creator_SeqFn;
}

void DR_Creator_release(void)
{
}

void DR_Creator_initialise(void)
{
}

ObjectDescriptor gDrCreatorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DR_Creator_initialise,
    (ObjectDescriptorCallback)DR_Creator_release,
    0,
    (ObjectDescriptorCallback)DR_Creator_init,
    (ObjectDescriptorCallback)DR_Creator_update,
    (ObjectDescriptorCallback)DR_Creator_hitDetect,
    (ObjectDescriptorCallback)DR_Creator_render,
    (ObjectDescriptorCallback)DR_Creator_free,
    (ObjectDescriptorCallback)DR_Creator_getObjectTypeId,
    DR_Creator_getExtraSize,
};

char sDrCreatorTimeFormat[15] = " Time %i : %i \000";
