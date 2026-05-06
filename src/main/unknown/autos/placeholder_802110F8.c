#include "ghidra_import.h"

extern void *Obj_GetPlayerObject(void);
extern void Sfx_StopFromObject(void *obj, u16 sfxId);
extern void Sfx_PlayFromObject(void *obj, u16 sfxId);
extern void ObjHits_EnableObject(void *obj);
extern void ObjHits_MarkObjectPositionDirty(void *obj);
extern void ObjHitbox_SetCapsuleBounds(void *obj, int height, int param3, int param4);
extern void ObjHits_SetHitVolumeSlot(void *obj, int param2, int param3, int param4);
extern void fn_8008016C(void *timer);
extern void fn_80080178(void *timer, int duration);
extern void fn_8009A8C8(void *obj, f32 param2);
extern void fn_8009AB70(void *obj, f32 param2, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
extern void fn_8001CB3C(void *handle);

extern f32 lbl_803E6768;
extern f32 lbl_803E676C;
extern f32 lbl_803E6770;
extern f32 lbl_803E6774;
extern f32 lbl_803DC24C;

typedef struct ProximityMineState {
    void *targetObj;
    void *effectHandle;
    f32 triggerDistance;
    f32 verticalStep;
    u8 unk10[4];
    u8 renderTimer[4];
    u8 launchTimer[4];
    u8 resetTimer[4];
    u8 bounceTimer[4];
    u8 initTimer[4];
    u8 lifespanTimer[4];
    s8 mode;
    u8 unk2D;
    u8 flashMode;
    u8 unk2F;
    u8 effectVisible;
    u8 unk31[3];
} ProximityMineState;

typedef struct ProximityMineObject {
    u8 unk0[0xc];
    f32 posX;
    f32 posY;
    f32 posZ;
    u8 unk18[0xc];
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
    u8 unk30[0x88];
    ProximityMineState *state;
} ProximityMineObject;

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
    fn_8008016C(state->renderTimer);
    fn_80080178(state->renderTimer, 10);
    state->mode = 0;
    ObjHits_EnableObject(obj);
    ObjHits_MarkObjectPositionDirty(obj);
    fn_8008016C(state->resetTimer);
    fn_8009A8C8(obj, lbl_803E676C);
    fn_8009AB70(obj,
                (state->triggerDistance - lbl_803E6774) * lbl_803DC24C + lbl_803E6770,
                1, 1, 0, 1, 0, 1, 0);
    ObjHitbox_SetCapsuleBounds(obj, (s32)state->triggerDistance, -5, 10);
    ObjHits_SetHitVolumeSlot(obj, 13, 1, 0);
    ObjHits_EnableObject(obj);
    if (state->effectHandle != NULL) {
        fn_8001CB3C(&state->effectHandle);
    }
}
