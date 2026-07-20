#include "main/frame_timing.h"
#include "main/mm.h"
#include "main/newclouds.h"
#include "main/objanim_update.h"
#include "main/objfx.h"
#include "main/obj_group.h"
#include "main/dll/dll_02BA_mclightning.h"
#include "main/game_object.h"
#include "main/dll/mclightning_state.h"
#include "main/object_descriptor.h"

#define MCLIGHTNING_OBJGROUP 0x48

int mclightning_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    McLightningState* state = obj->extra;
    int i;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (state->flags.phase)
        {
        case MCLIGHTNING_PHASE_READ_PARAM_A:
            state->flags.phase = MCLIGHTNING_PHASE_READ_PARAM_B;
            state->boltParamA = 0.01f * (f32)(u32)animUpdate->eventIds[i];
            break;
        case MCLIGHTNING_PHASE_READ_PARAM_B:
            state->flags.phase = MCLIGHTNING_PHASE_READ_PARAM_C;
            state->boltParamB = 0.01f * (f32)(u32)animUpdate->eventIds[i];
            break;
        case MCLIGHTNING_PHASE_READ_PARAM_C:
            state->flags.phase = MCLIGHTNING_PHASE_READ_PARAM_D;
            state->boltParamC = animUpdate->eventIds[i];
            break;
        case MCLIGHTNING_PHASE_READ_PARAM_D:
            state->flags.phase = MCLIGHTNING_PHASE_READ_TARGET;
            state->boltParamD = animUpdate->eventIds[i];
            break;
        case MCLIGHTNING_PHASE_READ_TARGET:
            state->flags.phase = MCLIGHTNING_PHASE_ARMED;
            state->targetLinkId = animUpdate->eventIds[i];
            obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            break;
        default:
            state->flags.phase = MCLIGHTNING_PHASE_ABORTED;
            break;
        }
    }
    return 0;
}

int mclightning_getExtraSize(void)
{
    return 0x1c;
}

void mclightning_free(GameObject* obj)
{
    McLightningState* state = (obj)->extra;

    ObjGroup_RemoveObject((int)obj, MCLIGHTNING_OBJGROUP);
    if (state->boltHandle != NULL)
    {
        mm_free(state->boltHandle);
    }
}

void mclightning_render(GameObject* obj, int p2, int p3, int p4, int p5, f32 scale)
{
    McLightningState* state = (obj)->extra;
    u32 mode = state->flags.phase;
    if (mode == MCLIGHTNING_PHASE_ARMED)
    {
        int count;
    u32* objs = ObjGroup_GetObjects(MCLIGHTNING_OBJGROUP, &count);
        int i;
        for (i = 0; i < count; i++)
        {
            int* candidate = (int*)objs[i];
            if (*(u8*)(*(int*)((int)candidate + 0x4c) + 0x1b) == state->targetLinkId)
                break;
        }
        if (i == count)
        {
            state->flags.phase = MCLIGHTNING_PHASE_ABORTED;
        }
        else
        {
            McLightningState* foundState;
            state->boltHandle = lightningCreate(
                (const Vec3f*)&obj->anim.localPosX, (const Vec3f*)(objs[i] + 0xc), state->boltParamA,
                state->boltParamB, state->boltParamC, state->boltParamD, 0);
            state->flags.phase = MCLIGHTNING_PHASE_ACTIVE;
            state->boltFrameTimer = 0.0f;
            if (state->flags.spawnFlags & 1)
            {
                objfx_spawnHitEffectBurst(obj, state->hitEffectScale, 1, 7, 0x1e, NULL);
            }
            foundState = (McLightningState*)*(int*)(objs[i] + 0xb8);
            if (foundState->flags.spawnFlags & 1)
            {
                objfx_spawnHitEffectBurst((void*)objs[i], foundState->hitEffectScale, 1, 7, 0x1e, NULL);
            }
            if (state->flags.spawnFlags & 2)
            {
                objfx_spawnDirectionalBurst(obj, 5, state->burstEffectChance, 1, 1, 0x64, 5.0f, NULL, 0);
            }
            if (foundState->flags.spawnFlags & 2)
            {
                objfx_spawnDirectionalBurst((void*)objs[i], 5, foundState->burstEffectChance, 1, 1, 0x64,
                                            5.0f, NULL, 0);
            }
        }
    }
    else if (mode == MCLIGHTNING_PHASE_ACTIVE)
    {
        if (state->boltHandle != NULL)
        {
            u32 frame;
            lightningRender(state->boltHandle);
            state->boltFrameTimer += timeDelta;
            frame = (u16)(0.5f + state->boltFrameTimer);
            *(u16*)((int)state->boltHandle + 0x20) = frame;
            if (*(u16*)((int)state->boltHandle + 0x20) >= *(u16*)((int)state->boltHandle + 0x22))
            {
                mm_free(state->boltHandle);
                state->boltHandle = NULL;
                state->flags.phase = MCLIGHTNING_PHASE_READ_PARAM_A;
                (obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            }
        }
    }
}

void mclightning_update(GameObject* obj)
{
    McLightningState* state = obj->extra;

    if (state->boltHandle != NULL)
    {
        mm_free(state->boltHandle);
        state->boltHandle = NULL;
    }
    state->flags.phase = MCLIGHTNING_PHASE_READ_PARAM_A;
    obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
}

void mclightning_init(GameObject* obj, McLightningSetup* setup)
{
    McLightningState* state = (obj)->extra;
    f32 effectScale;

    (obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    (obj)->animEventCallback = mclightning_SeqFn;
    ObjGroup_AddObject((int)obj, MCLIGHTNING_OBJGROUP);
    state->flags.spawnFlags = setup->spawnFlags;
    effectScale = 1.0f;
    state->hitEffectScale = effectScale;
    state->burstEffectChance = effectScale;
}

ObjectDescriptor gMCLightningObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)mclightning_init,
    (ObjectDescriptorCallback)mclightning_update,
    0,
    (ObjectDescriptorCallback)mclightning_render,
    (ObjectDescriptorCallback)mclightning_free,
    0,
    (ObjectDescriptorExtraSizeCallback)mclightning_getExtraSize,
};
