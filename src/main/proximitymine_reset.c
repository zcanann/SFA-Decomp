#include "main/proximitymine.h"
#include "main/audio/sfx.h"
#include "main/objhits.h"
#include "main/object_api.h"
#include "main/objfx.h"
#include "main/dll/objfx_api.h"
#include "main/maketex_timer_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx_ids.h"

extern f32 lbl_803E6768;
extern f32 lbl_803E676C;
extern f32 lbl_803E6770;
extern f32 lbl_803E6774;
extern f32 lbl_803DC24C;

extern void modelLightStruct_freeSlot(void* handle);

void proximitymine_resetToIdle(ProximityMineObject* obj)
{
    ProximityMineState* state;
    f32 zero;

    state = obj->state;
    Obj_GetPlayerObject();
    Sfx_StopFromObject((u32)obj, SFXTRIG_id_2e9);
    Sfx_StopFromObject((u32)obj, SFXTRIG_id_2e8);
    Sfx_PlayFromObject((u32)obj, SFXTRIG_crthit6);
    zero = lbl_803E6768;
    obj->velocityX = zero;
    obj->velocityZ = zero;
    storeZeroToFloatParam(&state->renderTimer);
    s16toFloat(&state->renderTimer, 10);
    state->mode = PROXIMITYMINE_MODE_EXPIRED;
    ObjHits_EnableObject((u32)obj);
    ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
    storeZeroToFloatParam(&state->resetTimer);
    fn_8009A8C8((GameObject*)obj, lbl_803E676C);
    {
        f32 dist = state->triggerDistance - lbl_803E6774;
        spawnExplosionLegacy(obj, dist * lbl_803DC24C + lbl_803E6770, 1, 1, 0, 1, 0, 1, 0);
    }
    ObjHitbox_SetCapsuleBounds((ObjAnimComponent*)obj, state->triggerDistance, -5, 10);
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, PROXIMITYMINE_HIT_VOLUME_SLOT, 1, 0);
    ObjHits_EnableObject((u32)obj);
    if (state->effectHandle != NULL)
    {
        modelLightStruct_freeSlot(&state->effectHandle);
    }
}
