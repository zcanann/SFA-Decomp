#include "main/dll/dll_0117_appleontree.h"
#include "main/game_object.h"
#include "main/objlib.h"
#include "main/obj_placement.h"
#include "main/objseq.h"

extern f32 lbl_803E3848;
extern void objRenderFn_8003b8f4(f32);
extern void dll_FC_initialise_nop(void);
extern void dll_FC_release_nop(void);
extern void dll_FC_init(int obj, int objDef);
extern void dll_FC_update(int obj);
extern void dll_FC_hitDetect(int* obj);
extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern f32 lbl_803E384C;

void dll_FC_free_nop(void)
{
}

int dll_FC_getExtraSize_ret_8(void) { return 0x8; }
int dll_FC_getObjectTypeId(void) { return 0x0; }

void dll_FC_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3848);
}

void dll_FC_hitDetect(int* obj)
{
    extern void objRenderFn_80041018(int* obj); /* #57 */
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    if ((objAnim->modelInstance->flags & 1u) == 0u) return;
    if (objAnim->hitVolumeTransforms == NULL) return;
    objRenderFn_80041018(obj);
}

ObjectDescriptor gDllFCObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_FC_initialise_nop,
    (ObjectDescriptorCallback)dll_FC_release_nop,
    0,
    (ObjectDescriptorCallback)dll_FC_init,
    (ObjectDescriptorCallback)dll_FC_update,
    (ObjectDescriptorCallback)dll_FC_hitDetect,
    (ObjectDescriptorCallback)dll_FC_render,
    (ObjectDescriptorCallback)dll_FC_free_nop,
    (ObjectDescriptorCallback)dll_FC_getObjectTypeId,
    dll_FC_getExtraSize_ret_8,
};

typedef struct BabyCloudRunnerPlacement
{
    ObjPlacement base;
    s16 gateGameBit;
    s16 rememberedGameBit;
    u8 targetGroup;
    u8 triggerIdMin;
    u8 triggerIdMax;
    u8 flags;
    u8 pad20[0x24 - 0x20];
} BabyCloudRunnerPlacement;

typedef struct BabyCloudRunnerState
{
    u8 mode;
    u8 triggerId;
    u8 rememberedGameBitValue;
    u8 pad03;
    GameObject* target;
} BabyCloudRunnerState;

STATIC_ASSERT(sizeof(BabyCloudRunnerState) == 0x8);
STATIC_ASSERT(sizeof(BabyCloudRunnerPlacement) == 0x24);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, gateGameBit) == 0x18);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, rememberedGameBit) == 0x1A);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, targetGroup) == 0x1C);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, triggerIdMin) == 0x1D);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, triggerIdMax) == 0x1E);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, flags) == 0x1F);
STATIC_ASSERT(offsetof(BabyCloudRunnerState, target) == 0x4);

void dll_FC_update(int obj)
{
    BabyCloudRunnerPlacement* placement;
    BabyCloudRunnerState* state;
    uint bitVal;
    float local8;

    local8 = lbl_803E384C;
    placement = (BabyCloudRunnerPlacement*)((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;

    if ((u32)state->target == 0)
    {
        state->target = (GameObject*)ObjGroup_FindNearestObject(placement->targetGroup, obj, &local8);
        if ((u32)state->target == 0) goto end;
        if ((int)placement->rememberedGameBit == -1)
        {
            state->rememberedGameBitValue = 0;
        }
        else
        {
            bitVal = GameBit_Get((int)placement->rememberedGameBit);
            state->rememberedGameBitValue = (byte)bitVal;
        }
        state->mode = 1;
    }

    ((GameObject*)obj)->anim.localPosX = state->target->anim.localPosX;
    ((GameObject*)obj)->anim.localPosY = state->target->anim.localPosY;
    ((GameObject*)obj)->anim.localPosZ = state->target->anim.localPosZ;
    ((GameObject*)obj)->anim.rotX = state->target->anim.rotX;
    ((GameObject*)obj)->anim.rotZ = state->target->anim.rotZ;
    ((GameObject*)obj)->anim.rotY = state->target->anim.rotY;

    switch (state->mode)
    {
    case 3:
        break;
    case 1:
        if ((state->rememberedGameBitValue != 0) && ((placement->flags & 1) == 0))
        {
            *(u8*)&state->target->anim.resetHitboxMode &= ~0x20;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x08;
            state->mode = 3;
        }
        else if (((int)placement->gateGameBit != -1) &&
            (GameBit_Get((int)placement->gateGameBit) == 0))
        {
            *(u8*)&state->target->anim.resetHitboxMode &= ~0x20;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x08;
            state->mode = 2;
        }
        else if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0)
        {
            if ((placement->flags & 2) != 0)
            {
                GameBit_Set((int)placement->gateGameBit, 0);
            }
            if ((int)placement->rememberedGameBit != -1)
            {
                GameBit_Set((int)placement->rememberedGameBit, 1);
            }
            if ((placement->flags & 4) != 0)
            {
                bitVal = randomGetRange((int)placement->triggerIdMin, (int)placement->triggerIdMax);
                state->triggerId = (byte)bitVal;
            }
            else
            {
                state->triggerId += 1;
                if (state->triggerId > placement->triggerIdMax)
                {
                    state->triggerId = placement->triggerIdMin;
                }
            }
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x08;
            state->rememberedGameBitValue = 1;
            (*gObjectTriggerInterface)->runSequence(state->triggerId, (void*)obj, -1);
        }
        else
        {
            *(u8*)&state->target->anim.resetHitboxMode |= 0x20;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x08;
        }
        break;
    case 2:
        if (GameBit_Get((int)placement->gateGameBit) != 0)
        {
            state->mode = 1;
        }
        break;
    }
end:
    return;
}

void dll_FC_init(int obj, int objDef)
{
    BabyCloudRunnerState* state;
    BabyCloudRunnerPlacement* placement;

    state = ((GameObject*)obj)->extra;
    placement = (BabyCloudRunnerPlacement*)objDef;
    state->mode = 0;
    state->triggerId = placement->triggerIdMax;
    ((GameObject*)obj)->objectFlags |= 0x4000;
    return;
}

void dll_FC_release_nop(void)
{
}

void dll_FC_initialise_nop(void)
{
}

int dll_14D_getObjectTypeId(void);
