/*
 * mclightning (DLL 0x2BA) - a paired lightning-arc object. Each instance
 * collects five anim-event parameters in order (handleScriptEvents drives
 * the phase 0->5 state machine: two scaled bolt arc params, two raw bolt
 * params, then a target link id) before unhiding itself. Once armed
 * (phase 5), render() locates the partner object in object group 0x48 that
 * carries the matching targetLinkId, creates the lightning bolt between the
 * two via lightningCreate, and - per each end's spawnFlags - fires a hit
 * pulse and/or a directional spark burst. Phase 6 then renders and ages the
 * bolt each frame until its lifetime field elapses, frees it, and returns to
 * the hidden idle phase 0.
 *
 * spawnFlags (state->flags.spawnFlags, from setup[0x1a]):
 *   bit 0 -> emit a hit pulse at that end
 *   bit 1 -> emit a directional spark burst at that end
 *
 * The ObjectDescriptor that wires these mclightning_* callbacks is not in this
 * TU (no in-repo reference); it lives in the owning DLL's descriptor table.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/dll/mclightning_state.h"

#define MCLIGHTNING_OBJ_GROUP 0x48

/* state->flags.phase values */
#define MCLIGHTNING_PHASE_PARAM_A 0  /* awaiting first scaled bolt arc param */
#define MCLIGHTNING_PHASE_PARAM_B 1  /* awaiting second scaled bolt arc param */
#define MCLIGHTNING_PHASE_PARAM_C 2  /* awaiting boltParamC */
#define MCLIGHTNING_PHASE_PARAM_D 3  /* awaiting boltParamD */
#define MCLIGHTNING_PHASE_LINK_ID 4  /* awaiting targetLinkId, then unhide */
#define MCLIGHTNING_PHASE_ARMED 5    /* params complete; spawn bolt on render */
#define MCLIGHTNING_PHASE_ACTIVE 6   /* bolt live; render and age each frame */
#define MCLIGHTNING_PHASE_DONE 0xa   /* no partner / sequence finished */

/* state->flags.spawnFlags bits (from setup[0x1a]) */
#define MCLIGHTNING_SPAWN_HIT_PULSE 1
#define MCLIGHTNING_SPAWN_SPARK_BURST 2

int mclightning_handleScriptEvents(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    McLightningState* state = ((GameObject*)obj)->extra;
    int i;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (state->flags.phase)
        {
        case MCLIGHTNING_PHASE_PARAM_A:
            state->flags.phase = MCLIGHTNING_PHASE_PARAM_B;
            state->boltParamA = lbl_803E7440 * (f32)(u32)animUpdate->eventIds[i];
            break;
        case MCLIGHTNING_PHASE_PARAM_B:
            state->flags.phase = MCLIGHTNING_PHASE_PARAM_C;
            state->boltParamB = lbl_803E7440 * (f32)(u32)animUpdate->eventIds[i];
            break;
        case MCLIGHTNING_PHASE_PARAM_C:
            state->flags.phase = MCLIGHTNING_PHASE_PARAM_D;
            state->boltParamC = animUpdate->eventIds[i];
            break;
        case MCLIGHTNING_PHASE_PARAM_D:
            state->flags.phase = MCLIGHTNING_PHASE_LINK_ID;
            state->boltParamD = animUpdate->eventIds[i];
            break;
        case MCLIGHTNING_PHASE_LINK_ID:
            state->flags.phase = MCLIGHTNING_PHASE_ARMED;
            state->targetLinkId = animUpdate->eventIds[i];
            ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            break;
        default:
            state->flags.phase = MCLIGHTNING_PHASE_DONE;
            break;
        }
    }
    return 0;
}

int mclightning_getExtraSize(void) { return sizeof(McLightningState); }

void mclightning_free(int obj)
{
    McLightningState* state = ((GameObject*)obj)->extra;

    ObjGroup_RemoveObject(obj, MCLIGHTNING_OBJ_GROUP);
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
    state->flags.phase = MCLIGHTNING_PHASE_PARAM_A;
    ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
}

void mclightning_init(int obj, u8* setup)
{
    McLightningState* state = ((GameObject*)obj)->extra;
    f32 v; /* single-letter name is a CSE/coloring lever: shared by both stores below */

    ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    ((GameObject*)obj)->animEventCallback = (void*)mclightning_handleScriptEvents;
    ObjGroup_AddObject(obj, MCLIGHTNING_OBJ_GROUP);
    state->flags.spawnFlags = setup[0x1a];
    v = lbl_803E745C;
    state->hitEffectScale = v;
    state->burstEffectChance = v;
}

void mclightning_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    McLightningState* state = ((GameObject*)obj)->extra;
    u32 phase = state->flags.phase;
    if (phase == MCLIGHTNING_PHASE_ARMED)
    {
        int count;
        int* objs = ObjGroup_GetObjects(MCLIGHTNING_OBJ_GROUP, &count);
        int i;
        for (i = 0; i < count; i++)
        {
            GameObject* partner = (GameObject*)objs[i];
            if (*(u8*)((int)partner->anim.placement + 0x1b) == state->targetLinkId)
                break;
        }
        if (i == count)
        {
            state->flags.phase = MCLIGHTNING_PHASE_DONE;
        }
        else
        {
            McLightningState* partnerState;
            state->boltHandle =
                lightningCreate(&((GameObject*)obj)->anim.localPosX,
                                &((GameObject*)objs[i])->anim.localPosX,
                                state->boltParamA, state->boltParamB, state->boltParamC,
                                state->boltParamD, 0);
            state->flags.phase = MCLIGHTNING_PHASE_ACTIVE;
            state->boltFrameTimer = lbl_803E7450;
            if (state->flags.spawnFlags & MCLIGHTNING_SPAWN_HIT_PULSE)
            {
                extern void hitDetectFn_80097070(int obj, f32 c, int a, int b, int d, int e);
                hitDetectFn_80097070(obj, state->hitEffectScale, 1, 7, 0x1e, 0);
            }
            partnerState = ((GameObject*)objs[i])->extra;
            if (partnerState->flags.spawnFlags & MCLIGHTNING_SPAWN_HIT_PULSE)
            {
                extern void hitDetectFn_80097070(int obj, f32 c, int a, int b, int d, int e);
                hitDetectFn_80097070(objs[i], partnerState->hitEffectScale, 1, 7, 0x1e, 0);
            }
            if (state->flags.spawnFlags & MCLIGHTNING_SPAWN_SPARK_BURST)
            {
                extern void objfx_spawnDirectionalBurst(int obj, int p2, f32 f1, int p4, int p5,
                                                        int p6, f32 f2, void* p8, int p9);
                objfx_spawnDirectionalBurst(obj, 5, state->burstEffectChance, 1, 1, 0x64,
                                            lbl_803E7454, 0, 0);
            }
            if (partnerState->flags.spawnFlags & MCLIGHTNING_SPAWN_SPARK_BURST)
            {
                extern void objfx_spawnDirectionalBurst(int obj, int p2, f32 f1, int p4, int p5,
                                                        int p6, f32 f2, void* p8, int p9);
                objfx_spawnDirectionalBurst(objs[i], 5, partnerState->burstEffectChance, 1, 1, 0x64,
                                            lbl_803E7454, 0, 0);
            }
        }
    }
    else if (phase == MCLIGHTNING_PHASE_ACTIVE)
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
                state->flags.phase = MCLIGHTNING_PHASE_PARAM_A;
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            }
        }
    }
}
