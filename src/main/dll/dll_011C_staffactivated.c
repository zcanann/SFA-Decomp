/*
 * staffactivated (DLL 0x11C, CloudRunner staff-activated object) - a
 * scenery/mechanism object placed in the world that responds to staff
 * activation. Its placement `mode` selects behavior: MODE_ACTION runs
 * trigger sequence 0 and spawns the activation particle fx when the
 * STAFFACTIVATED_TRIGGER_GAMEBIT becomes set; MODE_LIFT raises the object
 * (cfPrisonGuard lift mechanic); MODE_HIT_REACTION / MODE_DAMAGE_FIRST
 * defer to the shared landed-arwing hit/damage handlers. The hitbox mode
 * byte (anim.resetHitboxMode) carries the LOCKED/DISABLED/HIT_TRIGGER
 * interaction bits, and per-object enable is gated by the setup's
 * activeGameBit / lockGameBit and the STAFFACTIVATED_ENABLE_GAMEBIT.
 */
#include "main/effect_interfaces.h"
#include "main/dll/staffflags_struct.h"
#include "main/game_object.h"
#include "main/dll/CF/staffactivated_helpers.h"
#include "main/objseq.h"
#include "main/dll/VF/vf_shared.h"
#include "main/gamebits.h"
extern f32 lbl_803E3BBC;
extern f32 lbl_803E3BDC;
extern f32 lbl_803E3BF0;
extern f32 gStaffActivatedPi;
extern f32 gStaffActivatedBinAngleScale;
extern f32 lbl_803E3BFC;
extern f32 lbl_803E3C00;
extern f32 lbl_803E3C04;
extern f32 lbl_803E3C08;
extern f32 lbl_803E3C0C;
extern f32 gStaffActivatedMinRootMotionScale;
extern f32 lbl_803E3C14;
extern f32 lbl_803E3C18;
extern float mathSinf(float x);
extern float mathCosf(float x);
extern void ObjGroup_RemoveObject(u32 obj, int group);
extern void ObjGroup_AddObject(u32 obj, int group);
extern void ObjHitbox_SetSphereRadius(int obj, int radius);
extern int fn_80295CE4(void);
extern void landed_arwing_updateHitReaction(GameObject* obj, void* state);
extern void landed_arwing_updateDamageTexture(GameObject* obj, void* state);

#define STAFFACTIVATED_OBJ_FLAG_HIT_TRIGGER 0x04
#define STAFFACTIVATED_OBJ_FLAG_LOCKED      0x08
#define STAFFACTIVATED_OBJ_FLAG_DISABLED    0x10

#define STAFFACTIVATED_MODE_ACTION        0
#define STAFFACTIVATED_MODE_LIFT          2
#define STAFFACTIVATED_MODE_HIT_REACTION  3
#define STAFFACTIVATED_MODE_DAMAGE_FIRST  4
#define STAFFACTIVATED_MODE_DAMAGE_SECOND 5

#define STAFFACTIVATED_TRIGGER_GAMEBIT 0xd2a
#define STAFFACTIVATED_ENABLE_GAMEBIT  0x957
#define STAFFACTIVATED_PARTICLE_ID     0x7c3

#define STAFFACTIVATED_OBJ_GROUP 0x41

STATIC_ASSERT(sizeof(StaffActivatedState) == 0x24);
STATIC_ASSERT(offsetof(StaffActivatedState, targetX) == 0x00);
STATIC_ASSERT(offsetof(StaffActivatedState, targetZ) == 0x04);
STATIC_ASSERT(offsetof(StaffActivatedState, liftVelocity) == 0x0c);
STATIC_ASSERT(offsetof(StaffActivatedState, previousLiftHeight) == 0x10);
STATIC_ASSERT(offsetof(StaffActivatedState, liftHeight) == 0x14);
STATIC_ASSERT(offsetof(StaffActivatedState, peakLiftHeight) == 0x18);
STATIC_ASSERT(offsetof(StaffActivatedState, liftReset) == 0x1c);
STATIC_ASSERT(offsetof(StaffActivatedState, flags) == 0x1d);
STATIC_ASSERT(offsetof(StaffActivatedState, hitCooldown) == 0x20);
STATIC_ASSERT(sizeof(StaffActivatedSetup) == 0x28);
STATIC_ASSERT(offsetof(StaffActivatedSetup, type) == 0x18);
STATIC_ASSERT(offsetof(StaffActivatedSetup, mode) == 0x1c);
STATIC_ASSERT(offsetof(StaffActivatedSetup, size) == 0x1d);
STATIC_ASSERT(offsetof(StaffActivatedSetup, debrisObjectSet) == 0x1e);
STATIC_ASSERT(offsetof(StaffActivatedSetup, debrisCount) == 0x1f);
STATIC_ASSERT(offsetof(StaffActivatedSetup, timedEventSeconds) == 0x20);
STATIC_ASSERT(offsetof(StaffActivatedSetup, activeGameBit) == 0x22);
STATIC_ASSERT(offsetof(StaffActivatedSetup, lockGameBit) == 0x24);

void staffactivated_calcInteractionTargetXZ(int obj, f32* outX, f32* outZ)
{
    int mode;
    StaffActivatedState* state;
    GameObject* gobj;

    gobj = (GameObject*)obj;
    state = gobj->extra;
    mode = ((StaffActivatedSetup*)gobj->anim.placementData)->mode;

    switch (mode)
    {
    case STAFFACTIVATED_MODE_LIFT:
        *outX = -(lbl_803E3BF0 * mathSinf(gStaffActivatedPi * (f32)(gobj->anim.rotX) / gStaffActivatedBinAngleScale) -
                  state->targetX);
        *outZ = -(lbl_803E3BF0 * mathCosf(gStaffActivatedPi * (f32)(gobj->anim.rotX) / gStaffActivatedBinAngleScale) -
                  state->targetZ);
        break;
    case STAFFACTIVATED_MODE_HIT_REACTION:
        *outX = lbl_803E3BF0 * mathSinf(gStaffActivatedPi * (f32)(gobj->anim.rotX) / gStaffActivatedBinAngleScale) +
                state->targetX;
        *outZ = lbl_803E3BF0 * mathCosf(gStaffActivatedPi * (f32)(gobj->anim.rotX) / gStaffActivatedBinAngleScale) +
                state->targetZ;
        break;
    case STAFFACTIVATED_MODE_ACTION:
        *outX = lbl_803E3BFC * mathSinf(gStaffActivatedPi * (f32)(gobj->anim.rotX) / gStaffActivatedBinAngleScale) +
                gobj->anim.localPosX;
        *outZ = lbl_803E3BFC * mathCosf(gStaffActivatedPi * (f32)(gobj->anim.rotX) / gStaffActivatedBinAngleScale) +
                gobj->anim.localPosZ;
        break;
    default:
        *outX = lbl_803E3BF0 * mathSinf(gStaffActivatedPi * (f32)(gobj->anim.rotX) / gStaffActivatedBinAngleScale) +
                gobj->anim.localPosX;
        *outZ = lbl_803E3BF0 * mathCosf(gStaffActivatedPi * (f32)(gobj->anim.rotX) / gStaffActivatedBinAngleScale) +
                gobj->anim.localPosZ;
        break;
    }
}

u32 cfPrisonGuard_getLiftHeight(int* obj)
{
    StaffActivatedState* state = ((GameObject*)obj)->extra;
    return state->liftHeight;
}

void cfPrisonGuard_setLiftHeight(int* obj, int height)
{
    StaffActivatedState* state = ((GameObject*)obj)->extra;
    state->liftHeight = height;
    state->liftReset = 1;
}

u8 objGetByteParam1C(int* obj)
{
    StaffActivatedSetup* setup = (StaffActivatedSetup*)((GameObject*)obj)->anim.placementData;
    return setup->mode;
}

int staffactivated_getExtraSize(void)
{
    return sizeof(StaffActivatedState);
}

int staffactivated_getObjectTypeId(void)
{
    return 0x40;
}

void staffactivated_free(int obj)
{
    ObjGroup_RemoveObject(obj, STAFFACTIVATED_OBJ_GROUP);
}

void staffactivated_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E3BBC);
}

void staffactivated_update(GameObject* obj)
{
    struct PartfxParams
    {
        int pad;
        s16 life;
        s16 extra;
        f32 scale;
        f32 posX;
        f32 posY;
        f32 posZ;
    } stk;
    StaffActivatedSetup* setup = (StaffActivatedSetup*)obj->anim.placementData;
    StaffActivatedState* state = obj->extra;
    int isSet;
    int gameBit;

    Obj_GetPlayerObject();

    if (((StaffFlags*)&state->flags)->b6)
    {
        obj->anim.resetHitboxFlags |= STAFFACTIVATED_OBJ_FLAG_LOCKED;
    }
    else
    {
        obj->anim.resetHitboxFlags &= ~STAFFACTIVATED_OBJ_FLAG_LOCKED;
    }

    if (((StaffFlags*)&state->flags)->b7 == 0 || fn_80295CE4() == 0)
    {
        obj->anim.resetHitboxFlags |= STAFFACTIVATED_OBJ_FLAG_DISABLED;
    }
    else
    {
        obj->anim.resetHitboxFlags &= ~STAFFACTIVATED_OBJ_FLAG_DISABLED;
    }

    switch (setup->mode)
    {
    case STAFFACTIVATED_MODE_LIFT:
        staffactivated_updateLiftHeight((int)obj, state);
        break;
    case STAFFACTIVATED_MODE_HIT_REACTION:
        landed_arwing_updateHitReaction(obj, state);
        break;
    case STAFFACTIVATED_MODE_DAMAGE_FIRST:
    case STAFFACTIVATED_MODE_DAMAGE_SECOND:
        landed_arwing_updateDamageTexture(obj, state);
        break;
    case STAFFACTIVATED_MODE_ACTION:
        if (obj->anim.resetHitboxFlags & STAFFACTIVATED_OBJ_FLAG_HIT_TRIGGER)
        {
            if (GameBit_Get(STAFFACTIVATED_TRIGGER_GAMEBIT) == 0)
            {
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                GameBit_Set(STAFFACTIVATED_TRIGGER_GAMEBIT, 1);
            }
        }
        if (GameBit_Get(STAFFACTIVATED_ENABLE_GAMEBIT) == 0)
        {
            obj->anim.resetHitboxFlags |= STAFFACTIVATED_OBJ_FLAG_DISABLED;
        }
        isSet = 0;
        gameBit = setup->activeGameBit;
        if (gameBit == -1 || GameBit_Get(gameBit) != 0)
        {
            isSet = 1;
        }
        ((StaffFlags*)&state->flags)->b7 = isSet;
        if (((StaffFlags*)&state->flags)->b7)
        {
            stk.posX = lbl_803E3C00;
            stk.posY = lbl_803E3C04;
            stk.posZ = lbl_803E3BDC;
            stk.scale = lbl_803E3BBC;
            stk.extra = 0;
            stk.life = 0x64;
            (*gPartfxInterface)->spawnObject((void*)obj, STAFFACTIVATED_PARTICLE_ID, &stk, 2, -1, NULL);
            stk.posX = lbl_803E3C00;
            stk.posY = lbl_803E3C04;
            stk.posZ = lbl_803E3BDC;
            stk.scale = lbl_803E3BBC;
            stk.extra = 5;
            stk.life = 0xa;
            (*gPartfxInterface)->spawnObject((void*)obj, STAFFACTIVATED_PARTICLE_ID, &stk, 2, -1, NULL);
        }
        break;
    default:
        isSet = 0;
        gameBit = setup->activeGameBit;
        if (gameBit == -1 || GameBit_Get(gameBit) != 0)
        {
            isSet = 1;
        }
        ((StaffFlags*)&state->flags)->b7 = isSet;
        break;
    }
}

void staffactivated_init(GameObject* obj, StaffActivatedSetup* setupData)
{
    StaffActivatedState* state;
    int sizeIndex;
    int modelVariant;
    f32 scale;
    StaffFlags* flags;

    state = obj->extra;
    ObjGroup_AddObject((u32)obj, STAFFACTIVATED_OBJ_GROUP);
    obj->anim.rotX = (s16)((s32)setupData->type << 8);

    sizeIndex = setupData->size;
    if (sizeIndex > 2)
    {
        sizeIndex = 2;
    }

    if (setupData->mode == STAFFACTIVATED_MODE_LIFT)
    {
        switch (sizeIndex)
        {
        case 2:
            modelVariant = 2;
            scale = lbl_803E3C08;
            break;
        default:
            modelVariant = 1;
            scale = lbl_803E3BBC;
            break;
        case 0:
            modelVariant = 0;
            scale = lbl_803E3C0C;
            break;
        }
    }
    else
    {
        scale = lbl_803E3BBC;
    }

    if (obj->anim.hitReactState != NULL)
    {
        ObjHitbox_SetSphereRadius((int)obj,
                                  (int)((f32)((ObjHitsPriorityState*)obj->anim.hitReactState)->primaryRadius * scale));
    }

    obj->anim.rootMotionScale = obj->anim.modelInstance->rootMotionScaleBase * scale;
    /* the *(f32*)& launder on the min-scale constant is load-bearing here (the
       plain compare regresses); keep the forced load feeding the branch. */
    if (obj->anim.rootMotionScale < *(f32*)&gStaffActivatedMinRootMotionScale)
    {
        obj->anim.rootMotionScale = gStaffActivatedMinRootMotionScale;
    }

    switch (setupData->mode)
    {
    case STAFFACTIVATED_MODE_LIFT:
        obj->hitVolumeIndex = modelVariant;
        state->targetX = -(lbl_803E3C14 * (obj->anim.rootMotionScale *
                                           (lbl_803E3C18 * mathSinf((gStaffActivatedPi * (f32)obj->anim.rotX) /
                                                                    gStaffActivatedBinAngleScale))) -
                           obj->anim.localPosX);
        state->targetZ = -(lbl_803E3C14 * (obj->anim.rootMotionScale *
                                           (lbl_803E3C18 * mathCosf((gStaffActivatedPi * (f32)obj->anim.rotX) /
                                                                    gStaffActivatedBinAngleScale))) -
                           obj->anim.localPosZ);
        break;
    case STAFFACTIVATED_MODE_HIT_REACTION:
        state->targetX =
            lbl_803E3C14 *
                (obj->anim.rootMotionScale *
                 (lbl_803E3C18 * mathSinf((gStaffActivatedPi * (f32)obj->anim.rotX) / gStaffActivatedBinAngleScale))) +
            obj->anim.localPosX;
        state->targetZ =
            lbl_803E3C14 *
                (obj->anim.rootMotionScale *
                 (lbl_803E3C18 * mathCosf((gStaffActivatedPi * (f32)obj->anim.rotX) / gStaffActivatedBinAngleScale))) +
            obj->anim.localPosZ;
        break;
    default:
        state->targetX = obj->anim.localPosX;
        state->targetZ = obj->anim.localPosZ;
        break;
    }

    flags = (StaffFlags*)&state->flags;
    if (setupData->activeGameBit > 0)
    {
        flags->b7 = GameBit_Get(setupData->activeGameBit);
    }
    else
    {
        flags->b7 = 1;
    }
    flags->b4 = 0;

    if (setupData->lockGameBit > 0)
    {
        if ((flags->b6 = GameBit_Get(setupData->lockGameBit)) != 0)
        {
            switch (setupData->mode)
            {
            case STAFFACTIVATED_MODE_HIT_REACTION:
                ((void (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)((ObjAnimComponent*)obj, lbl_803E3BBC);
                break;
            case STAFFACTIVATED_MODE_DAMAGE_FIRST:
                flags->b6 = 0;
                break;
            case STAFFACTIVATED_MODE_LIFT:
                break;
            case STAFFACTIVATED_MODE_DAMAGE_SECOND:
                break;
            }
        }
    }
}
