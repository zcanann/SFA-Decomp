#include "main/proximitymine.h"
#include "main/audio/sfx.h"
#include "main/objhits.h"
#include "main/engine_shared.h"
#include "main/audio/sfx_trigger_ids.h"

extern void ObjHitbox_SetCapsuleBounds(void* obj, int height, int param3, int param4);
extern void storeZeroToFloatParam(f32* p);
extern void s16toFloat(f32* p, s16 val);
extern void fn_8009A8C8(void* obj, f32 param2);
extern void spawnExplosion(void* obj, f32 param2, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
extern void modelLightStruct_freeSlot(void* handle);
extern f32 lbl_803E6768;
extern f32 lbl_803E676C;
extern f32 lbl_803E6770;
extern f32 lbl_803E6774;
extern f32 lbl_803DC24C;

void proximitymine_resetToIdle(ProximityMineObject* obj)
{
    ProximityMineState* state;
    f32 zero;

    state = obj->state;
    Obj_GetPlayerObject();
    Sfx_StopFromObject((u32)obj, 0x2e9);
    Sfx_StopFromObject((u32)obj, 0x2e8);
    Sfx_PlayFromObject((u32)obj, SFXTRIG_crthit6);
    zero = lbl_803E6768;
    obj->velocityX = zero;
    obj->velocityZ = zero;
    storeZeroToFloatParam(&state->renderTimer);
    s16toFloat(&state->renderTimer, 10);
    state->mode = PROXIMITYMINE_MODE_EXPIRED;
    ObjHits_EnableObject((u32)obj);
    ObjHits_MarkObjectPositionDirty((int)obj);
    storeZeroToFloatParam(&state->resetTimer);
    fn_8009A8C8(obj, lbl_803E676C);
    {
        f32 dist = state->triggerDistance - lbl_803E6774;
        spawnExplosion(obj, dist * lbl_803DC24C + lbl_803E6770, 1, 1, 0, 1, 0, 1, 0);
    }
    ObjHitbox_SetCapsuleBounds(obj, state->triggerDistance, -5, 10);
    ObjHits_SetHitVolumeSlot((u32)obj, 13, 1, 0);
    ObjHits_EnableObject((u32)obj);
    if (state->effectHandle != NULL)
    {
        modelLightStruct_freeSlot(&state->effectHandle);
    }
}
