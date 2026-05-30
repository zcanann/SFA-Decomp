#include "main/dll/WM/wm_shared.h"

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

extern void mathFn_80021ac8(void *angles, void *outVec);
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

    state = *(WmPlanetsState **)((char *)obj + 0xb8);
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
    mathFn_80021ac8(&rotate, vec.f);

    rotate.zeroX = lbl_803E5F9C;
    rotate.zeroY = lbl_803E5F9C;
    rotate.zeroZ = lbl_803E5F9C;
    rotate.scale = lbl_803E5F98;
    rotate.roll = 0;
    rotate.pitch = state->orbitPitch;
    rotate.yaw = 0;
    mathFn_80021ac8(&rotate, vec.f);

    *(f32 *)((char *)obj + 0xc) = vec.f[0] + state->baseX;
    *(f32 *)((char *)obj + 0x10) = vec.f[1] + state->baseY;
    *(f32 *)((char *)obj + 0x14) = vec.f[2] + state->baseZ;
    *(s16 *)obj = (s16)(*(s16 *)obj + state->yawStep * (s32)timeDelta);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wmplanets_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    f32 a = lbl_803E5FA0 * *(f32 *)((char *)*(int *)((char *)obj + 0x50) + 4);
    *(f32 *)((char *)obj + 8) = a * (lbl_803E5F98 + (f32)(s32)(s8)init[0x18]);
    if (*(s16 *)init != 0) {
        *(f32 *)((char *)inner + 0xc) = -(f32)(s32)((s8)init[0x19] << 4);
    } else {
        *(f32 *)((char *)inner + 0xc) = lbl_803E5F9C;
    }
    *(s16 *)inner = (s16)randomGetRange(0x64, 0xc8);
    *(s16 *)((char *)inner + 2) = (s16)randomGetRange(0xc8, 0x190);
    *(s16 *)((char *)inner + 4) = 0;
    *(s16 *)((char *)inner + 8) = (s16)randomGetRange(0, 0x960);
    *(f32 *)((char *)inner + 0x10) = *(f32 *)((char *)obj + 0xc);
    *(f32 *)((char *)inner + 0x14) = *(f32 *)((char *)obj + 0x10);
    *(f32 *)((char *)inner + 0x18) = *(f32 *)((char *)obj + 0x14);
    Obj_SetActiveModelIndex((int)obj, *(s16 *)((char *)init + 0x1a));
    *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)init + 0x10) + *(f32 *)((char *)inner + 0xc);
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
