/*
 * arwblocker (DLL 0x2A8) - an invisible trigger volume in the on-rails
 * Arwing flight sections. It starts hidden with hit-detection disabled;
 * once the Arwing (or, as a fallback, the player object) closes to within
 * a fixed distance it fades in, enables its hitbox and fires one of two
 * object sequences (selected by the placement's sequenceMode). The
 * animEventCallback (ARWBlocker_SeqFn) reports whether the blocker
 * is currently "armed" (mode 1 and not yet locked) to the sequence system.
 */
#include "main/frame_timing.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/vecmath.h"
#include "main/dll/ARW/dll_02A8_arwblocker.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "main/object_render_legacy.h"

/* placement sequenceMode: which object sequence the blocker fires on approach */
#define ARWBLOCKER_SEQMODE_DEFAULT 0 /* fires sequence 0; never reports "armed" */
#define ARWBLOCKER_SEQMODE_ARMED   1 /* fires sequence 1; reports armed until locked */


#pragma peephole off
int ARWBlocker_SeqFn(GameObject* obj)
{
    ARWBlockerState* state = obj->extra;
    switch (state->sequenceMode)
    {
    case ARWBLOCKER_SEQMODE_ARMED:
        if (state->sequenceLocked != 0)
        {
            break;
        }
        return 1;
    case ARWBLOCKER_SEQMODE_DEFAULT:
        break;
    }
    return 0;
}

int ARWBlocker_getExtraSize(void)
{
    return 2;
}

int ARWBlocker_getObjectTypeId(void)
{
    return 0;
}

#pragma peephole on
void ARWBlocker_free(void)
{
}

#pragma scheduling off
void ARWBlocker_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}
#pragma scheduling reset

void ARWBlocker_hitDetect(void)
{
}

#pragma scheduling off
#pragma peephole off
void ARWBlocker_update(GameObject* obj)
{
    ObjAnimComponent* objAnim = &(obj)->anim;
    ARWBlockerState* state = (obj)->extra;
    GameObject* arwing = (GameObject*)getArwing();

    if (arwing == NULL)
        arwing = Obj_GetPlayerObject();
        if (Vec_distance(&objAnim->worldPosX, &arwing->anim.worldPosX) < 5120.0f)
    {
        int alpha = (int)(3.0f * timeDelta + (f32)(u32)objAnim->alpha);
        if (alpha > 0xff)
            alpha = 0xff;
        objAnim->alpha = alpha;
        (obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        ObjHits_EnableObject((int)obj);
        if ((obj)->unkF4 == 0)
        {
            switch (state->sequenceMode)
            {
            case ARWBLOCKER_SEQMODE_ARMED:
                (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                break;
            case ARWBLOCKER_SEQMODE_DEFAULT:
            default:
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                break;
            }
            (obj)->unkF4 = 1;
        }
    }
}

void ARWBlocker_init(GameObject* obj, int setup)
{
    ObjAnimComponent* objAnim = &(obj)->anim;
    ARWBlockerState* state = (obj)->extra;
    ARWBlockerSetup* mapData = (ARWBlockerSetup*)setup;

    (obj)->anim.rotX = -0x8000;
    (obj)->anim.rotZ = (s16)(mapData->rotZ << 8);
    (obj)->animEventCallback = ARWBlocker_SeqFn;
    state->sequenceMode = mapData->sequenceMode;
    (obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    objAnim->alpha = 0;
    ObjHits_DisableObject((int)obj);
}

#pragma scheduling on
#pragma peephole on
void ARWBlocker_release(void)
{
}

void ARWBlocker_initialise(void)
{
}
