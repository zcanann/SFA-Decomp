#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/dll/mclightning_state.h"

#define MCLIGHTNING_OBJGROUP 0x48

int mclightning_handleScriptEvents(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    McLightningState* state = ((GameObject*)obj)->extra;
    int i;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (state->flags.phase)
        {
        case 0:
            state->flags.phase = 1;
            state->boltParamA = lbl_803E7440 * (f32)(u32)
            animUpdate->eventIds[i];
            break;
        case 1:
            state->flags.phase = 2;
            state->boltParamB = lbl_803E7440 * (f32)(u32)
            animUpdate->eventIds[i];
            break;
        case 2:
            state->flags.phase = 3;
            state->boltParamC = animUpdate->eventIds[i];
            break;
        case 3:
            state->flags.phase = 4;
            state->boltParamD = animUpdate->eventIds[i];
            break;
        case 4:
            state->flags.phase = 5;
            state->targetLinkId = animUpdate->eventIds[i];
            ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            break;
        default:
            state->flags.phase = 0xa;
            break;
        }
    }
    return 0;
}

int mclightning_getExtraSize(void) { return 0x1c; }

void mclightning_free(int obj)
{
    McLightningState* state = ((GameObject*)obj)->extra;

    ObjGroup_RemoveObject(obj, MCLIGHTNING_OBJGROUP);
    if (state->boltHandle != NULL)
    {
        mm_free(state->boltHandle);
    }
}

void mclightning_update(int obj)
{
    McLightningState* state = ((GameObject*)obj)->extra;

    if (state->boltHandle != NULL)
    {
        mm_free(state->boltHandle);
        state->boltHandle = NULL;
    }
    state->flags.phase = 0;
    ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
}

void mclightning_init(int obj, u8* setup)
{
    McLightningState* state = ((GameObject*)obj)->extra;
    f32 v;

    ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    ((GameObject*)obj)->animEventCallback = mclightning_handleScriptEvents;
    ObjGroup_AddObject(obj, MCLIGHTNING_OBJGROUP);
    state->flags.spawnFlags = setup[0x1a];
    v = lbl_803E745C;
    state->hitEffectScale = v;
    state->burstEffectChance = v;
}

void mclightning_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    McLightningState* state = ((GameObject*)obj)->extra;
    u32 mode = state->flags.phase;
    if (mode == 5)
    {
        int count;
        int* objs = ObjGroup_GetObjects(0x48, &count);
        int i;
        for (i = 0; i < count; i++)
        {
            int* o = (int*)objs[i];
            if (*(u8*)(*(int*)((int)o + 0x4c) + 0x1b) == state->targetLinkId)
                break;
        }
        if (i == count)
        {
            state->flags.phase = 0xa;
        }
        else
        {
            McLightningState* foundState;
            state->boltHandle =
                lightningCreate(&((GameObject*)obj)->anim.localPosX, (f32*)(objs[i] + 0xc),
                                state->boltParamA, state->boltParamB, state->boltParamC,
                                state->boltParamD, 0);
            state->flags.phase = 6;
            state->boltFrameTimer = lbl_803E7450;
            if (state->flags.spawnFlags & 1)
            {
                extern void hitDetectFn_80097070(int obj, f32 c, int a, int b, int d, int e);
                hitDetectFn_80097070(obj, state->hitEffectScale, 1, 7, 0x1e, 0);
            }
            foundState = (McLightningState*)*(int*)(objs[i] + 0xb8);
            if (foundState->flags.spawnFlags & 1)
            {
                extern void hitDetectFn_80097070(int obj, f32 c, int a, int b, int d, int e);
                hitDetectFn_80097070(objs[i], foundState->hitEffectScale, 1, 7, 0x1e, 0);
            }
            if (state->flags.spawnFlags & 2)
            {
                extern void objfx_spawnDirectionalBurst(int obj, int p2, f32 f1, int p4, int p5,
                                                        int p6, f32 f2, void* p8, int p9);
                objfx_spawnDirectionalBurst(obj, 5, state->burstEffectChance, 1, 1, 0x64,
                                            lbl_803E7454, 0, 0);
            }
            if (foundState->flags.spawnFlags & 2)
            {
                extern void objfx_spawnDirectionalBurst(int obj, int p2, f32 f1, int p4, int p5,
                                                        int p6, f32 f2, void* p8, int p9);
                objfx_spawnDirectionalBurst(objs[i], 5, foundState->burstEffectChance, 1, 1, 0x64,
                                            lbl_803E7454, 0, 0);
            }
        }
    }
    else if (mode == 6)
    {
        if (state->boltHandle != NULL)
        {
            u32 frame;
            lightningRender(state->boltHandle);
            state->boltFrameTimer += timeDelta;
            frame = (u16)(lbl_803E7458 + state->boltFrameTimer);
            *(u16*)((int)state->boltHandle + 0x20) = frame;
            if (*(u16*)((int)state->boltHandle + 0x20) >=
                *(u16*)((int)state->boltHandle + 0x22))
            {
                mm_free(state->boltHandle);
                state->boltHandle = NULL;
                state->flags.phase = 0;
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            }
        }
    }
}
