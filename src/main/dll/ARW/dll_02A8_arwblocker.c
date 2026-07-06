/*
 * arwblocker (DLL 0x2A8) - an invisible trigger volume in the on-rails
 * Arwing flight sections. It starts hidden with hit-detection disabled;
 * once the Arwing (or, as a fallback, the player object) closes to within
 * a fixed distance it fades in, enables its hitbox and fires one of two
 * object sequences (selected by the placement's sequenceMode). The
 * animEventCallback (arwblocker_getBlockState) reports whether the blocker
 * is currently "armed" (mode 1 and not yet locked) to the sequence system.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

/* placement sequenceMode: which object sequence the blocker fires on approach */
#define ARWBLOCKER_SEQMODE_DEFAULT 0 /* fires sequence 0; never reports "armed" */
#define ARWBLOCKER_SEQMODE_ARMED   1 /* fires sequence 1; reports armed until locked */

typedef struct ARWBlockerSetup
{
    ObjPlacement base;
    s8 rotZ;
    u8 sequenceMode;
    u8 pad1A[0x24 - 0x1A];
} ARWBlockerSetup;

typedef struct ARWBlockerState
{
    u8 sequenceMode;
    u8 sequenceLocked;
} ARWBlockerState;

STATIC_ASSERT(sizeof(ARWBlockerState) == 0x2);
STATIC_ASSERT(sizeof(ARWBlockerSetup) == 0x24);
STATIC_ASSERT(offsetof(ARWBlockerState, sequenceMode) == 0x00);
STATIC_ASSERT(offsetof(ARWBlockerState, sequenceLocked) == 0x01);
STATIC_ASSERT(offsetof(ARWBlockerSetup, rotZ) == 0x18);
STATIC_ASSERT(offsetof(ARWBlockerSetup, sequenceMode) == 0x19);

#pragma peephole off
int arwblocker_getBlockState(int obj)
{
    ARWBlockerState* state = ((GameObject*)obj)->extra;
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

int arwblocker_getExtraSize(void) { return 2; }

int arwblocker_getObjectTypeId(void) { return 0; }

#pragma peephole on
void arwblocker_free(void)
{
}

void arwblocker_hitDetect(void)
{
}

void arwblocker_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E7218);
}

#pragma scheduling off
#pragma peephole off
void arwblocker_init(int obj, int setup)
{
    ObjAnimComponent* objAnim = &((GameObject*)obj)->anim;
    ARWBlockerState* state = ((GameObject*)obj)->extra;
    ARWBlockerSetup* mapData = (ARWBlockerSetup*)setup;

    ((GameObject*)obj)->anim.rotX = -0x8000;
    ((GameObject*)obj)->anim.rotZ = (s16)(mapData->rotZ << 8);
    ((GameObject*)obj)->animEventCallback = arwblocker_getBlockState;
    state->sequenceMode = mapData->sequenceMode;
    ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    objAnim->alpha = 0;
    ObjHits_DisableObject(obj);
}

#pragma scheduling on
#pragma peephole on
void arwblocker_release(void)
{
}

void arwblocker_initialise(void)
{
}

#pragma scheduling off
#pragma peephole off
void arwblocker_update(int obj)
{
    ObjAnimComponent* objAnim = &((GameObject*)obj)->anim;
    ARWBlockerState* state = ((GameObject*)obj)->extra;
    int arwing = getArwing();

    if ((u32)arwing == 0)
        arwing = Obj_GetPlayerObject();
    if (Vec_distance((int)&objAnim->worldPosX, (int)&((GameObject*)arwing)->anim.worldPosX) < lbl_803E721C)
    {
        int alpha = (int)
        (lbl_803E7220 * timeDelta + (f32)(u32)
        objAnim->alpha
        )
        ;
        if (alpha > 0xff)
            alpha = 0xff;
        objAnim->alpha = alpha;
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        ObjHits_EnableObject(obj);
        if (((GameObject*)obj)->unkF4 == 0)
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
            ((GameObject*)obj)->unkF4 = 1;
        }
    }
}
