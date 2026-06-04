#include "ghidra_import.h"
#include "main/dll/CF/CFcrystal.h"

extern undefined4 FUN_800068c4();
extern double FUN_80006a38();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175a0();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175d8();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern undefined4 FUN_80017680();
extern undefined4 FUN_80017688();
extern uint GameBit_Get(int eventId);
extern undefined4 FUN_8001771c();
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined8 ObjGroup_RemoveObject();
extern void ObjGroup_AddObject(int obj, int group);
extern void Obj_FreeObject(int obj);
extern void gameBitDecrement(int eventId);
extern void GameBit_Set(int eventId, int value);
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80061a80();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4 DAT_803de758;
extern f64 DOUBLE_803e4748;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dca40;
extern f32 FLOAT_803e4724;
extern f32 FLOAT_803e4728;
extern f32 FLOAT_803e4730;
extern f32 FLOAT_803e4734;
extern f32 FLOAT_803e4738;
extern f32 FLOAT_803e473c;
extern f32 FLOAT_803e4740;
extern f32 FLOAT_803e4750;
extern f32 FLOAT_803e4754;
extern f32 FLOAT_803e4758;
extern f32 FLOAT_803e475c;
extern f32 FLOAT_803e4760;
extern f32 FLOAT_803e476c;
extern f32 lbl_803E3AA0;
extern f32 lbl_803E3A98;
extern f32 lbl_803E3A9C;
extern f32 lbl_803E3AA8;
extern f64 lbl_803E3AB0;
extern f32 lbl_803E3AC0;
extern f32 lbl_803E3AC4;
extern f32 lbl_803E3AC8;
extern f32 lbl_803E3ACC;
extern f32 lbl_803E3AD0;
extern f32 lbl_803E3AD4;
extern f32 lbl_803E3AB8;
extern f32 lbl_803E3AD8;
extern f32 lbl_803E3ADC;
extern f32 lbl_803E3AE0;
extern f32 lbl_803E3AEC;
extern f32 lbl_803DBDD8;
extern u8 framesThisStep;
extern u8 lbl_803DDAD8;
extern void *gPartfxInterface;
extern f32 Curve_EvalBSpline(f32 t, void *control, int mode);
extern f32 Vec_distance(void *a, void *b);
extern int objCreateLight(int obj, int type);
extern void modelLightStruct_setField50(int light, int value);
extern void modelLightStruct_setColorsA8AC(int light, int r, int g, int b, int a);
extern void lightSetFieldBC_8001db14(int light, int value);
extern void lightSetField2FB(int light, int value);
extern void lightDistAttenFn_8001dc38(int light, f32 near, f32 far);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern f32 sqrtf(f32 value);
extern f32 fn_80293E80(f32 value);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
void LanternFireFly_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3AA0); }
#pragma peephole reset

void LanternFireFly_hitDetect(void) {}

#define LANTERN_SPAWN_FX(obj, id, a, b, c, d) \
    ((void (*)(int, int, int, int, int, int))(*(int *)(*(int *)gPartfxInterface + 8)))(obj, id, a, b, c, d)

#define LANTERN_SPAWN_FX_VEC(obj, id, a, b, c, d, vx, vy, vz) \
    ((void (*)(int, int, int, int, int, int, f32, f32, f32))(*(int *)(*(int *)gPartfxInterface + 8)))(obj, id, a, b, c, d, vx, vy, vz)

extern void fn_801868D0(int obj);
extern void fn_801869DC(int obj);

#pragma scheduling off
#pragma peephole off
void LanternFireFly_update(int obj)
{
    u8 *state;
    int player;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 stepScale;

    state = *(u8 **)(obj + 0xb8);
    player = FUN_80017a98();
    *(f32 *)(obj + 0x80) = *(f32 *)(obj + 0xc);
    *(f32 *)(obj + 0x84) = *(f32 *)(obj + 0x10);
    *(f32 *)(obj + 0x88) = *(f32 *)(obj + 0x14);

    if (lbl_803E3AA0 < *(f32 *)(state + 0x40)) {
        *(f32 *)(state + 0x40) -= lbl_803E3AA0;
        if (state[0x6c] < 4) {
            fn_801868D0(obj);
        } else if (state[0x6c] == 7) {
            state[0x6c] = 0;
        } else {
            state[0x6c]++;
        }
        fn_801869DC(obj);
    }

    *(f32 *)(obj + 0xc) = *(f32 *)(state + 0x54) + Curve_EvalBSpline(*(f32 *)(state + 0x40), state + 4, 0);
    *(f32 *)(obj + 0x10) = *(f32 *)(state + 0x58) + Curve_EvalBSpline(*(f32 *)(state + 0x40), state + 0x14, 0);
    *(f32 *)(obj + 0x14) = *(f32 *)(state + 0x5c) + Curve_EvalBSpline(*(f32 *)(state + 0x40), state + 0x24, 0);

    if ((state[0x70] >> 6) == 1) {
        *(f32 *)(state + 0x44) =
            (f32)(lbl_803E3AC4 * Vec_distance((void *)(obj + 0x18), (void *)(player + 0x18)) + lbl_803E3AC0);
    }
    *(f32 *)(state + 0x40) += *(f32 *)(state + 0x44) * FLOAT_803dc074;

    if ((state[0x6a] == 1 || state[0x6a] == 4) && (state[0x70] >> 6) == 1 && state[0x6e] == 0) {
        int light;

        state[0x6e] = 1;
        light = objCreateLight(obj, 1);
        if (light != 0) {
            modelLightStruct_setField50(light, 2);
            modelLightStruct_setColorsA8AC(light, 100, 0xff, 100, 0);
            lightSetFieldBC_8001db14(light, 1);
            lightDistAttenFn_8001dc38(light, lbl_803E3A98, lbl_803E3A9C);
            lightSetField2FB(light, 1);
        }
        *(int *)state = light;
        if ((state[0x70] >> 6) != 1) {
            lbl_803DDAD8 = 1;
        }
    }

    dx = *(f32 *)(obj + 0xc) - *(f32 *)(obj + 0x80);
    dy = *(f32 *)(obj + 0x10) - *(f32 *)(obj + 0x84);
    dz = *(f32 *)(obj + 0x14) - *(f32 *)(obj + 0x88);
    stepScale = lbl_803E3AA0 / ((f32)(s32)(sqrtf(dx * dx + dy * dy + dz * dz) / lbl_803E3AC8) + 1.0f);

    if ((state[0x70] >> 6) == 1) {
        Sfx_KeepAliveLoopedObjectSound(obj, 0x43b);
        if (lbl_803DBDD8 < (f32)*(int *)(state + 0x60)) {
            if (state[0x6a] == 1 || state[0x6a] == 4) {
                LANTERN_SPAWN_FX(obj, 0x19f, 0, 1, -1, 0);
                LANTERN_SPAWN_FX(obj, 0x1a0, 0, 1, -1, 0);
            } else {
                LANTERN_SPAWN_FX(obj, 0x1bd, 0, 1, -1, 0);
            }
        }
        *(int *)(state + 0x60) -= framesThisStep;
        if (*(int *)(state + 0x60) < 0) {
            gameBitDecrement(0x698);
            Obj_FreeObject(obj);
            return;
        }
        *(f32 *)(state + 0x54) = *(f32 *)(player + 0x18);
        *(f32 *)(state + 0x58) = lbl_803E3AA8 + *(f32 *)(player + 0x1c);
        *(f32 *)(state + 0x5c) = *(f32 *)(player + 0x20);
        if (*(int *)state != 0 && *(int *)(state + 0x60) < 0xb4) {
            f32 atten;

            atten = (f32)*(int *)(state + 0x60) *
                fn_80293E80((lbl_803E3ACC * (f32)(*(int *)(state + 0x60) << 0xb)) / lbl_803E3AD0);
            Sfx_KeepAliveLoopedObjectSound(0, 0x460);
            lightDistAttenFn_8001dc38(*(int *)state, atten, lbl_803E3AD4 + atten);
        }
    } else {
        LANTERN_SPAWN_FX_VEC(obj, 0x19f, 0, 1, -1, 0, dx * stepScale, dy * stepScale, dz * stepScale);
        LANTERN_SPAWN_FX(obj, 0x1a0, 0, 1, -1, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

#undef LANTERN_SPAWN_FX
#undef LANTERN_SPAWN_FX_VEC

#pragma scheduling off
#pragma peephole off
void LanternFireFly_init(int obj, int def)
{
    u8 *state;
    f32 zero;
    s16 randValue;
    int flagValue;

    state = *(u8 **)(obj + 0xB8);
    ObjGroup_AddObject(obj, 0x30);

    zero = lbl_803E3AB8;
    *(f32 *)(state + 0x04) = zero;
    *(f32 *)(state + 0x14) = zero;
    *(f32 *)(state + 0x24) = zero;
    *(f32 *)(state + 0x08) = zero;
    *(f32 *)(state + 0x18) = zero;
    *(f32 *)(state + 0x28) = zero;
    *(f32 *)(state + 0x0C) = zero;
    *(f32 *)(state + 0x1C) = zero;
    *(f32 *)(state + 0x2C) = zero;
    *(f32 *)(state + 0x10) = zero;
    *(f32 *)(state + 0x20) = zero;
    *(f32 *)(state + 0x30) = zero;

    *(int *)(state + 0x00) = 0;
    *(u8 *)(state + 0x6E) = 0;
    *(f32 *)(state + 0x44) = lbl_803E3AD8;
    *(f32 *)(state + 0x48) = lbl_803E3ADC;
    *(f32 *)(state + 0x40) = lbl_803E3AA0;
    *(u8 *)(state + 0x6C) = 0;
    *(u8 *)(state + 0x6B) = 0;
    randValue = (s16)randomGetRange(0x1F4, 0x5DC);
    *(s16 *)(state + 0x66) = randValue;
    randValue = (s16)randomGetRange(0, 0xFDE8);
    *(s16 *)(state + 0x64) = randValue;
    *(s16 *)(state + 0x68) = 4;
    *(u8 *)(state + 0x6A) = 4;
    *(f32 *)(state + 0x4C) = lbl_803E3AB8;
    *(f32 *)(state + 0x50) = lbl_803E3AE0;
    *(f32 *)(state + 0x54) = *(f32 *)(def + 0x08);
    *(f32 *)(state + 0x58) = *(f32 *)(def + 0x0C);
    *(f32 *)(state + 0x5C) = *(f32 *)(def + 0x10);
    flagValue = 0;
    *(u8 *)(state + 0x6F) = flagValue;
    *(u8 *)(state + 0x70) = (u8)((*(u8 *)(state + 0x70) & 0x3F) | (flagValue << 6));
}
#pragma peephole reset
#pragma scheduling reset

void LanternFireFly_release(void) {}
void LanternFireFly_initialise(void) {}

extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int size, int type);
extern int loadObjectAtObject(int *obj);
extern f32 lbl_803E3AE8;

#pragma scheduling off
#pragma peephole off
int FireFlyLantern_spawnFireFly(int *obj) {
    u8 *q;
    if (Obj_IsLoadingLocked() == 0) return 0;
    q = (u8 *)Obj_AllocObjectSetup(36, 1084);
    *(s16 *)q = 1084;
    *(u8 *)(q + 2) = 9;
    *(u8 *)(q + 4) = 2;
    *(u8 *)(q + 6) = 0xff;
    *(u8 *)(q + 5) = 4;
    *(u8 *)(q + 7) = 8;
    *(f32 *)(q + 8) = *(f32 *)((char *)obj + 0xc);
    *(f32 *)(q + 12) = lbl_803E3AE8 + *(f32 *)((char *)obj + 0x10);
    *(f32 *)(q + 16) = *(f32 *)((char *)obj + 0x14);
    *(u8 *)(q + 0x19) = 4;
    *(s16 *)(q + 0x1a) = 0x514;
    *(s16 *)(q + 0x1c) = 40;
    *(u8 *)(q + 0x18) = 30;
    return loadObjectAtObject(obj);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int FireFlyLantern_SeqFn(int obj, int unused, int events)
{
    u8 *state;
    u8 *slot;
    void *child;
    int i;
    f32 yOffset;

    state = *(u8 **)(obj + 0xB8);
    for (i = 0; i < *(u8 *)(events + 0x8B); i++) {
        if ((*(u8 *)(events + i + 0x81) == 1) && (*(u8 *)(state + 0x1C) != 0)) {
            child = *(void **)(state + (*(u8 *)(state + 0x1C) * 4) - 4);
            if (child != 0) {
                (*(void (*)(void *))(*(int *)(*(int *)(*(int *)((u8 *)child + 0x68)) + 0x24)))(child);
            }
            *(u8 *)(state + 0x1C) = (u8)(*(u8 *)(state + 0x1C) - 1);
            *(u8 *)(state + 0x1D) = (u8)(*(u8 *)(state + 0x1D) - 1);
            GameBit_Set(*(s16 *)(state + 0x20), *(u8 *)(state + 0x1D));
        }
    }

    *(u8 *)(state + 0x1E) = (u8)((*(u8 *)(state + 0x1E) & 0x7F) | 0x80);
    yOffset = lbl_803E3AEC;
    slot = state;
    for (i = 0; i < *(u8 *)(state + 0x1C); i++) {
        child = *(void **)slot;
        (*(void (*)(void *, f32, f32, f32))(*(int *)(*(int *)(*(int *)((u8 *)child + 0x68)) + 0x28)))(
            child, *(f32 *)(obj + 0xC), yOffset + *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
        slot += 4;
    }

    return 0;
}
#pragma peephole reset
#pragma scheduling reset

/* 8b "li r3, N; blr" returners. */
int FireFlyLantern_getExtraSize(void) { return 0x24; }
int FireFlyLantern_getObjectTypeId(void) { return 0x8; }

extern void *getTrickyObject(void);
extern void trickyImpress(void *trickyObj);

#pragma scheduling off
#pragma peephole off
void FireFlyLantern_free(int obj) {
    void *tricky = getTrickyObject();
    if (tricky != NULL) {
        trickyImpress(tricky);
    }
    ObjGroup_RemoveObject(obj, 15);
}
#pragma peephole reset
#pragma scheduling reset

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E3AF0;
#pragma scheduling off
#pragma peephole off
void FireFlyLantern_render(void) { objRenderFn_8003b8f4(lbl_803E3AF0); }
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void FireFlyLantern_update(int obj)
{
    u8 *state;
    u8 *def;
    void *child;
    int i;
    int shouldFree;
    u8 *slot;

    state = *(u8 **)(obj + 0xB8);
    def = *(u8 **)(obj + 0x4C);
    shouldFree = 0;

    if (*(s8 *)(def + 0x19) == 1) {
        if (*(u8 *)(state + 0x1C) != 0) {
            child = *(void **)state;
            if (child != 0) {
                (*(void (*)(void *))(*(int *)(*(int *)(*(int *)((u8 *)child + 0x68)) + 0x24)))(child);
            }
            gameBitDecrement(*(s16 *)(state + 0x20));
        }
        shouldFree = 1;
    } else if ((*(u8 *)(state + 0x1E) >> 7) != 0) {
        i = 0;
        slot = state;
        while (i < *(u8 *)(state + 0x1C)) {
            Obj_FreeObject(*(int *)slot);
            slot += 4;
            i++;
        }
        shouldFree = 1;
    }

    if (shouldFree != 0) {
        Obj_FreeObject(obj);
    }
}
#pragma peephole reset
#pragma scheduling reset
