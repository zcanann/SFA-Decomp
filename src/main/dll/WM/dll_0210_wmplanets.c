#include "main/dll/WM/wm_shared.h"
#include "main/game_object.h"

typedef struct WmPlanetsState {
    s16 orbitYawStep;
    s16 yawStep;
    s16 orbitYaw;
    s16 pad06;
    s16 orbitPitch;
    s16 pad0A;
    f32 heightOffset;
    f32 baseX;
    f32 baseY;
    f32 baseZ;
} WmPlanetsState;

typedef struct WmPlanetsRotationWork {
    s16 yaw;
    s16 pitch;
    s16 roll;
    s16 pad06;
    f32 scale;
    f32 zeroX;
    f32 zeroY;
    f32 zeroZ;
} WmPlanetsRotationWork;

typedef union WmPlanetsVector {
    f32 f[3];
    u32 word[3];
} WmPlanetsVector;

extern void vecRotateZXY(void *angles, void *outVec);
extern u32 lbl_802C2500[3];

int wmplanets_getExtraSize(void) { return 0x1c; }

int wmplanets_getObjectTypeId(void) { return 0x0; }

void wmplanets_free(void) {}

void wmplanets_hitDetect(void) {}

void wmplanets_release(void) {}

void wmplanets_initialise(void) {}

#pragma peephole off
#pragma scheduling off
void wmplanets_update(int *obj) {
    WmPlanetsState *state;
    WmPlanetsVector vec;
    WmPlanetsRotationWork rotate;

    state = ((GameObject *)obj)->extra;
    vec.word[0] = lbl_802C2500[0];
    vec.word[1] = lbl_802C2500[1];
    vec.word[2] = lbl_802C2500[2];
    vec.f[2] = state->heightOffset;

    state->orbitYaw = state->orbitYaw + state->orbitYawStep;

    rotate.zeroX = lbl_803E5F9C;
    rotate.zeroY = lbl_803E5F9C;
    rotate.zeroZ = lbl_803E5F9C;
    rotate.scale = lbl_803E5F98;
    rotate.roll = 0;
    rotate.pitch = 0;
    rotate.yaw = state->orbitYaw;
    vecRotateZXY(&rotate, vec.f);

    rotate.zeroX = lbl_803E5F9C;
    rotate.zeroY = lbl_803E5F9C;
    rotate.zeroZ = lbl_803E5F9C;
    rotate.scale = lbl_803E5F98;
    rotate.roll = 0;
    rotate.pitch = state->orbitPitch;
    rotate.yaw = 0;
    vecRotateZXY(&rotate, vec.f);

    ((GameObject *)obj)->anim.localPosX = vec.f[0] + state->baseX;
    ((GameObject *)obj)->anim.localPosY = vec.f[1] + state->baseY;
    ((GameObject *)obj)->anim.localPosZ = vec.f[2] + state->baseZ;
    *(s16 *)obj = (s16)(*(s16 *)obj + state->yawStep * (s32)timeDelta);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wmplanets_init(int *obj, u8 *init) {
    WmPlanetsState *inner = ((GameObject *)obj)->extra;
    f32 a = lbl_803E5FA0 * *(f32 *)((char *)*(int *)&((GameObject *)obj)->anim.modelInstance + 4);
    ((GameObject *)obj)->anim.rootMotionScale = a * (lbl_803E5F98 + (f32)(s32)(s8)init[0x18]);
    if (*(s16 *)init != 0) {
        inner->heightOffset = -(f32)(s32)((s8)init[0x19] << 4);
    } else {
        inner->heightOffset = lbl_803E5F9C;
    }
    inner->orbitYawStep = (s16)randomGetRange(0x64, 0xc8);
    inner->yawStep = (s16)randomGetRange(0xc8, 0x190);
    inner->orbitYaw = 0;
    inner->orbitPitch = (s16)randomGetRange(0, 0x960);
    inner->baseX = ((GameObject *)obj)->anim.localPosX;
    inner->baseY = ((GameObject *)obj)->anim.localPosY;
    inner->baseZ = ((GameObject *)obj)->anim.localPosZ;
    Obj_SetActiveModelIndex((int)obj, *(s16 *)((char *)init + 0x1a));
    ((GameObject *)obj)->anim.localPosZ = *(f32 *)((char *)init + 0x10) + inner->heightOffset;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wmplanets_render(int p1, int p2, int p3, int p4, int p5, s8 vis) {
    if (vis != 0) {
        objRenderFn_8003b8f4(lbl_803E5F98);
    }
}
#pragma scheduling reset
#pragma peephole reset
