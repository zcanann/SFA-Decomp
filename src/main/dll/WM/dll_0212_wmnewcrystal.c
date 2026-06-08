#include "main/dll/WM/wm_shared.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"

#define WMNEWCRYSTAL_GAMEBIT_ACTIVE 0xd27
#define WMNEWCRYSTAL_GAMEBIT_AMBIENT_FX 0xe49
#define WMNEWCRYSTAL_OBJECT_BLUE 0x783
#define WMNEWCRYSTAL_OBJECT_GREEN 0x784
#define WMNEWCRYSTAL_PARTICLE_ID 0x7ed

typedef struct WmNewCrystalState {
    u8 pad0[0x34];
    u8 altFxParams[0x34];
    u8 active;
} WmNewCrystalState;

typedef struct WmNewCrystalEventData {
    u8 pad0[0x81];
    u8 events[10];
    u8 eventCount;
} WmNewCrystalEventData;

typedef struct WmNewCrystalParticleParams {
    u8 pad0[6];
    s16 pathPoint;
    u8 pad8[4];
    f32 x;
    f32 y;
    f32 z;
} WmNewCrystalParticleParams;

extern void *Camera_GetCurrentViewSlot(void);
extern void PSVECSubtract(f32 *a, f32 *b, f32 *out);
extern void PSVECNormalize(f32 *src, f32 *dst);
extern void PSVECScale(f32 *src, f32 *dst, f32 scale);
extern void PSVECAdd(f32 *a, f32 *b, f32 *out);
extern void spawnExplosion(int *obj, f32 scale, int a, int b, int c, int d, int e, int f, int g);
extern void WM_newcrystalFn_800969b0(int *obj, void *params, int enabled, f32 a, f32 b, f32 c,
                                     f32 d, f32 e);
extern void objfx_spawnDirectionalBurst(int *obj, u8 idx, u8 kind, u8 mode, u8 chance, void *origin,
                           int flags, f32 f8val, f32 mult);
extern f32 lbl_803E6038;
extern f32 lbl_803E603C;
extern f32 lbl_803E6040;
extern f32 lbl_803E6044;
extern f32 lbl_803E6048;
extern f32 lbl_803E604C;
extern f32 lbl_803E6050;
extern f32 lbl_803E6054;
extern f32 lbl_803E6058;

int wmnewcrystal_getExtraSize(void) { return 0x6c; }

int wmnewcrystal_getObjectTypeId(void) { return 0x0; }

void wmnewcrystal_free(void) {}

void wmnewcrystal_hitDetect(void) {}

void wmnewcrystal_update(void) {}

void wmnewcrystal_release(void) {}

void wmnewcrystal_initialise(void) {}

#pragma peephole off
#pragma scheduling off
int wmnewcrystal_SeqFn(int *obj, int unused, WmNewCrystalEventData *eventData) {
    WmNewCrystalState *state;
    WmNewCrystalParticleParams params;
    f32 cameraDelta[3];
    int i;

    state = *(WmNewCrystalState **)((char *)obj + 0xb8);
    for (i = 0; i < eventData->eventCount; i++) {
        switch (eventData->events[i]) {
        case 1:
            PSVECSubtract((f32 *)((char *)Camera_GetCurrentViewSlot() + 0xc),
                          &((GameObject *)obj)->anim.localPosX, cameraDelta);
            PSVECNormalize(cameraDelta, cameraDelta);
            PSVECScale(cameraDelta, cameraDelta, lbl_803E6038);
            PSVECAdd(&((GameObject *)obj)->anim.localPosX, cameraDelta, &((GameObject *)obj)->anim.localPosX);
            ((GameObject *)obj)->anim.worldPosX = *(f32 *)((char *)obj + 0xc);
            ((GameObject *)obj)->anim.worldPosY = ((GameObject *)obj)->anim.localPosY;
            ((GameObject *)obj)->anim.worldPosZ = ((GameObject *)obj)->anim.localPosZ;
            spawnExplosion(obj, lbl_803E6038, 1, 1, 0, 0, 0, 0, 0);
            ((GameObject *)obj)->anim.flags = ((GameObject *)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
            if (((GameObject *)obj)->anim.seqId == WMNEWCRYSTAL_OBJECT_BLUE) {
                GameBit_Set(WMNEWCRYSTAL_GAMEBIT_ACTIVE, 0);
            }
            break;
        case 2:
            state->active = 0;
            break;
        }
    }

    if (GameBit_Get(WMNEWCRYSTAL_GAMEBIT_ACTIVE) == 0) {
        return 0;
    }

    if (((GameObject *)obj)->anim.seqId == WMNEWCRYSTAL_OBJECT_BLUE) {
        if (GameBit_Get(WMNEWCRYSTAL_GAMEBIT_AMBIENT_FX) == 0) {
            (*gPartfxInterface)->spawnObject(obj, WMNEWCRYSTAL_PARTICLE_ID, NULL, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, WMNEWCRYSTAL_PARTICLE_ID, &params, 2, -1, NULL);
        }
        WM_newcrystalFn_800969b0(obj, state, 1, lbl_803E603C, lbl_803E6040, lbl_803E6044,
                                 lbl_803E6048, lbl_803E6038);
        WM_newcrystalFn_800969b0(obj, state->altFxParams, 1, lbl_803E603C, lbl_803E6040,
                                 lbl_803E604C, lbl_803E6048, lbl_803E6050);
        return 0;
    }

    if (((GameObject *)obj)->anim.seqId == WMNEWCRYSTAL_OBJECT_GREEN && state->active != 0) {
        ObjPath_GetPointLocalPosition((int)obj, 0, &params.x, &params.y, &params.z);
        params.x *= ((GameObject *)obj)->anim.rootMotionScale;
        params.y *= ((GameObject *)obj)->anim.rootMotionScale;
        params.z *= ((GameObject *)obj)->anim.rootMotionScale;
        params.pathPoint = 1;
        objfx_spawnDirectionalBurst(obj, 5, 1, 1, 10, &params, 0, lbl_803E6054, lbl_803E6058);

        ObjPath_GetPointLocalPosition((int)obj, 1, &params.x, &params.y, &params.z);
        params.x *= ((GameObject *)obj)->anim.rootMotionScale;
        params.y *= ((GameObject *)obj)->anim.rootMotionScale;
        params.z *= ((GameObject *)obj)->anim.rootMotionScale;
        params.pathPoint = 0;
        objfx_spawnDirectionalBurst(obj, 5, 1, 1, 10, &params, 0, lbl_803E6054, lbl_803E6058);
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wmnewcrystal_render(int p1, int p2, int p3, int p4, int p5, s8 vis) {
    objRenderFn_8003b8f4(lbl_803E605C);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wmnewcrystal_init(int *obj, u8 *init) {
    WmNewCrystalState *inner = *(WmNewCrystalState **)((char *)obj + 0xb8);
    ((GameObject *)obj)->animEventCallback = (void *)wmnewcrystal_SeqFn;
    if ((*gMapEventInterface)->getMode(*(s8 *)((char *)obj + 0xac)) > 1) {
        GameBit_Set(WMNEWCRYSTAL_GAMEBIT_ACTIVE, 1);
        inner->active = 1;
    }
}
#pragma scheduling reset
#pragma peephole reset
