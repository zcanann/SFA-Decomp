#include "main/dll/VF/vf_shared.h"

extern f32 lbl_803E608C;
extern f32 lbl_803E6094;
extern f32 lbl_803E6098;
extern f32 lbl_803E60A0;
extern void hitDetectFn_800658a4(int obj, f32 *out, int flags, f32 x, f32 y, f32 z);
extern void Sfx_StopObjectChannel(int obj, int channel);

#define VFPMINIFIRE_SMOKE_EFFECT 0x38a
#define VFPMINIFIRE_SPARK_EFFECT 0x38b
#define VFPMINIFIRE_BURST_EFFECT 0x38e
#define VFPMINIFIRE_EFFECT_FLAGS 0x80001
#define VFPMINIFIRE_BURST_COUNT 10
#define SFXqu_longsob2 0x103

typedef struct VfpMinifireState {
    f32 baseY;
    u8 pad4[6];
    u8 burstStarted;
} VfpMinifireState;

typedef struct VfpMinifirePartfxArgs {
    s16 rx;
    s16 ry;
    s16 rz;
    s16 pad;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} VfpMinifirePartfxArgs;

#define VFPMINIFIRE_SPAWN(obj, id, args, flags) \
    (*(void (**)(int, int, VfpMinifirePartfxArgs *, int, int, int))(*gPartfxInterface + 8))( \
        (obj), (id), (args), (flags), -1, 0)

int vfpminifire_getExtraSize(void) { return 0xc; }

int vfpminifire_getObjectTypeId(void) { return 0x0; }

void vfpminifire_hitDetect(void) {}

void vfpminifire_release(void) {}

void vfpminifire_initialise(void) {}

#pragma peephole off
#pragma scheduling off
void vfpminifire_render(int p1, int p2, int p3, int p4, int p5, s8 vis) {
    if (vis != 0 && *(u8 *)(p1 + 0x36) != 0) {
        fn_80053ED0(8);
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E6088);
        fn_80053EBC(8);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfpminifire_free(int obj) {
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfpminifire_update(int obj)
{
    VfpMinifireState *state = *(VfpMinifireState **)(obj + 0xb8);
    VfpMinifirePartfxArgs args;
    int linkedGfx;
    int i;

    if (lbl_803E608C == state->baseY) {
        hitDetectFn_800658a4(obj, (f32 *)state, 0, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10),
                             *(f32 *)(obj + 0x14));
        state->baseY = *(f32 *)(obj + 0x10) - state->baseY;
    }

    if (*(f32 *)(obj + 0x28) > lbl_803E6090) {
        *(f32 *)(obj + 0x28) += lbl_803E6094;
    }

    *(f32 *)(obj + 0xc) += *(f32 *)(obj + 0x24) * timeDelta;
    *(f32 *)(obj + 0x10) += *(f32 *)(obj + 0x28) * timeDelta;
    *(f32 *)(obj + 0x14) += *(f32 *)(obj + 0x2c) * timeDelta;

    args.x = lbl_803E608C;
    args.y = lbl_803E608C;
    args.z = lbl_803E608C;
    args.scale = lbl_803E6088;
    args.rz = 0;
    args.ry = 0;
    args.rx = 0;
    if (randomGetRange(0, 4) == 0) {
        VFPMINIFIRE_SPAWN(obj, VFPMINIFIRE_SMOKE_EFFECT, &args, VFPMINIFIRE_EFFECT_FLAGS);
    }

    args.x = (*(f32 *)(obj + 0xc) - *(f32 *)(obj + 0x80)) / lbl_803E6098;
    args.y = (*(f32 *)(obj + 0x10) - *(f32 *)(obj + 0x84)) / lbl_803E6098;
    args.z = (*(f32 *)(obj + 0x14) - *(f32 *)(obj + 0x88)) / lbl_803E6098;
    if (randomGetRange(0, 4) == 0) {
        VFPMINIFIRE_SPAWN(obj, VFPMINIFIRE_SMOKE_EFFECT, &args, VFPMINIFIRE_EFFECT_FLAGS);
    }

    args.x *= lbl_803E609C;
    args.y *= lbl_803E609C;
    args.z *= lbl_803E609C;
    if (randomGetRange(0, 4) == 0) {
        VFPMINIFIRE_SPAWN(obj, VFPMINIFIRE_SMOKE_EFFECT, &args, VFPMINIFIRE_EFFECT_FLAGS);
    }
    if (randomGetRange(0, 2) == 0) {
        VFPMINIFIRE_SPAWN(obj, VFPMINIFIRE_SPARK_EFFECT, &args, 1);
    }

    linkedGfx = *(int *)(obj + 0x54);
    if (linkedGfx != 0) {
        *(u8 *)(linkedGfx + 0x6e) = 0xb;
        *(u8 *)(linkedGfx + 0x6f) = 1;
        *(int *)(linkedGfx + 0x48) = 0x10;
        *(int *)(linkedGfx + 0x4c) = 0x10;
    }
    if ((linkedGfx != 0 && *(int *)(linkedGfx + 0x50) != 0) ||
        (*(f32 *)(obj + 0x10) < state->baseY && state->burstStarted == 0)) {
        state->burstStarted = 1;
        Sfx_StopObjectChannel(obj, 0x7f);
        for (i = VFPMINIFIRE_BURST_COUNT; i != 0; i--) {
            VFPMINIFIRE_SPAWN(obj, VFPMINIFIRE_BURST_EFFECT, &args, 1);
        }
    }

    if (state->burstStarted != 0) {
        s16 alpha = (u8)*(u8 *)(obj + 0x36) - (s16)(int)timeDelta;
        if (alpha < 0) {
            alpha = 0;
        }
        *(u8 *)(obj + 0x36) = (u8)alpha;
    }

    if (*(f32 *)(obj + 0x10) < state->baseY - lbl_803E60A0) {
        Obj_FreeObject(obj);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfpminifire_init(int *obj, u8 *init) {
    *(f32 *)((char *)obj + 0x28) = lbl_803E6090;
    *(f32 *)((char *)obj + 0x10) = lbl_803E60A4 + *(f32 *)((char *)init + 0xc);
    *(f32 *)((char *)obj + 8) = *(f32 *)((char *)obj + 8) * lbl_803E609C;
    (*(void (*)(int *, int, int, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 0x38c, 0, 2, -1, 0);
    Sfx_PlayFromObject((int)obj, SFXqu_longsob2);
    *(u16 *)((char *)obj + 0xb0) |= 0x2000;
}
#pragma scheduling reset
#pragma peephole reset
