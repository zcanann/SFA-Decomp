#include "ghidra_import.h"
#include "main/proximitymine.h"

extern void *Obj_GetPlayerObject(void);
extern void Sfx_StopFromObject(void *obj, u16 sfxId);
extern void Sfx_PlayFromObject(void *obj, u16 sfxId);
extern void ObjHits_EnableObject(void *obj);
extern void ObjHits_MarkObjectPositionDirty(void *obj);
extern void ObjHitbox_SetCapsuleBounds(void *obj, int height, int param3, int param4);
extern void ObjHits_SetHitVolumeSlot(void *obj, int param2, int param3, int param4);
extern void storeZeroToFloatParam(void *timer);
extern void s16toFloat(void *timer, int duration);
extern void fn_8009A8C8(void *obj, f32 param2);
extern void spawnExplosion(void *obj, f32 param2, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
extern void fn_8001CB3C(void *handle);

extern f32 lbl_803E6768;
extern f32 lbl_803E676C;
extern f32 lbl_803E6770;
extern f32 lbl_803E6774;
extern f32 lbl_803DC24C;

#pragma scheduling off
#pragma peephole off
void proximitymine_resetToIdle(ProximityMineObject *obj)
{
    ProximityMineState *state;
    f32 zero;

    state = obj->state;
    Obj_GetPlayerObject();
    Sfx_StopFromObject(obj, 0x2e9);
    Sfx_StopFromObject(obj, 0x2e8);
    Sfx_PlayFromObject(obj, 0xf1);
    zero = lbl_803E6768;
    obj->velocityX = zero;
    obj->velocityZ = zero;
    storeZeroToFloatParam(state->renderTimer);
    s16toFloat(state->renderTimer, 10);
    state->mode = 0;
    ObjHits_EnableObject(obj);
    ObjHits_MarkObjectPositionDirty(obj);
    storeZeroToFloatParam(state->resetTimer);
    fn_8009A8C8(obj, lbl_803E676C);
    {
        f32 dist = state->triggerDistance - lbl_803E6774;
        spawnExplosion(obj, dist * lbl_803DC24C + lbl_803E6770, 1, 1, 0, 1, 0, 1, 0);
    }
    ObjHitbox_SetCapsuleBounds(obj, (s32)state->triggerDistance, -5, 10);
    ObjHits_SetHitVolumeSlot(obj, 13, 1, 0);
    ObjHits_EnableObject(obj);
    if (state->effectHandle != NULL) {
        fn_8001CB3C(&state->effectHandle);
    }
}
#pragma peephole reset
#pragma scheduling reset
