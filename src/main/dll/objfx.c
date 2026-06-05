#include "ghidra_import.h"
#include "main/dll/fx_800944A0_shared.h"

extern f32 lbl_8030F9D8[];
extern s16 lbl_803DB788[4];
extern f64 lbl_803DF360;
extern f32 fcos16(u16 angle);

#pragma scheduling off
#pragma peephole off
void WM_newcrystalFn_800969b0(void *obj, s16 *state, u8 flags, f32 period, f32 xMul, f32 yMul, f32 xOff, f32 yOff)
{
    PartfxParams params;
    int i;
    int j;
    f32 cHalf;
    f32 invPeriod;
    f32 cOne;
    f32 cZero;
    int spawnFlags;
    f32 phase;

    cZero = lbl_803DF35C;
    cOne = lbl_803DF354;
    invPeriod = lbl_803DF350 / period;
    cHalf = lbl_803DF358;

    for (i = 0; i < 4; i++) {
        state[0x12 + i] = (s32)(invPeriod + (f32)(i * randomGetRange(120, 127)));
        state[0xe + i] = (s32)((f32)state[0x12 + i] * timeDelta + (f32)state[0xe + i]);
        phase = fcos16(state[0xe + i]);
        *(f32 *)((char *)state + 0xc + i * 4) = lbl_8030F9D8[i] * ((cOne + phase) * cHalf);

        state[0x16 + i] = (s32)(timeDelta * (f32)lbl_803DB788[i] + (f32)state[0x16 + i]);
        *(u16 *)state = state[0x16 + i];
        *(f32 *)((char *)state + 8) = *(f32 *)((char *)state + 0xc + i * 4);

        for (j = 0; j < 0xffff; j += 0x7fff) {
            params.vec[0] = *(f32 *)((char *)state + 8) * xMul + xOff;
            params.vec[1] = *(f32 *)((char *)state + 8) * yMul + yOff;
            params.vec[2] = cZero;
            *(u16 *)state += 0x7fff;
            mathFn_80021ac8(state, params.vec);
            params.vec[0] += *(f32 *)((char *)obj + 0xc);
            params.vec[1] += *(f32 *)((char *)obj + 0x10);
            params.vec[2] += *(f32 *)((char *)obj + 0x14);
            params.f8 = cOne;
            spawnFlags = 0x200001;
            if (flags != 0) {
                spawnFlags |= 0x20000000;
            }
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7ec, &params, spawnFlags, -1, 0);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void objfx_spawnRandomBurst(void *obj, u8 type, u8 count, void *origin, u8 flagByte, f32 mult) {
    PartfxParams params;
    ParticlePairTbl partbl = *(ParticlePairTbl *)lbl_802C212C;
    u16 rvec[3];
    int i;
    int n;
    f32 f26;
    f32 cScale = lbl_803DF368;
    f32 cOne = lbl_803DF354;
    f32 cZero = lbl_803DF35C;
    u8 fc = framesThisStep;

    if (fc > 3) {
        fc = 3;
    }
    n = fc * count;
    for (i = 0; i < n; i++) {
        f26 = (f32)randomGetRange(0, 1000) / cScale;
        rvec[0] = (u16)randomGetRange(0, 0xffff);
        rvec[1] = (u16)randomGetRange(0, 0xffff);
        rvec[2] = (u16)randomGetRange(0, 0xffff);
        params.vec[0] = mult * (cOne - f26 * (f26 * f26));
        params.vec[1] = cZero;
        params.vec[2] = cZero;
        mathFn_80021ac8(rvec, params.vec);
        if (origin != NULL) {
            params.vec[0] += *(f32 *)((char *)origin + 0xc);
            params.vec[1] += *(f32 *)((char *)origin + 0x10);
            params.vec[2] += *(f32 *)((char *)origin + 0x14);
        }
        params.f6 = (s16)partbl.e[type].a;
        params.pad[1] = (s16)partbl.e[type].b;
        params.pad[2] = flagByte;
        params.f8 = cOne;
        switch (type) {
        case 0xa:
        case 0xb:
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7e3, &params, 2, -1, 0);
            break;
        case 9:
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7e4, &params, 2, -1, 0);
            break;
        default:
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7e2, &params, 2, -1, 0);
            break;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void objfx_spawnHitEmitterAtPos(f32 *pos, u8 a, u8 b, u8 c, u8 d) {
    int args[4];
    ParticleEmit s1;
    int *res;
    s1.scale = lbl_803DF354;
    s1.h1c = 0;
    s1.h1a = 0;
    s1.h18 = 0;
    s1.x = pos[0];
    s1.y = pos[1];
    s1.z = pos[2];
    res = Resource_Acquire(0x5a, 1);
    args[0] = a;
    args[1] = b;
    args[2] = c;
    args[3] = d;
    (*(void (*)(int, int, void *, int, int, void *))(*(int *)(*(int *)res + 4)))(0, 1, &s1, 0x401, -1, args);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void hitDetectFn_80097070(void *obj, u8 a, u8 b, u8 count, void *p7, f32 fval) {
    PartfxParams params;
    Tbl11 table = *(Tbl11 *)lbl_802C2114;
    u16 ps[3];
    int i;
    *(int *)ps = lbl_803DF340;
    ps[2] = lbl_803DF344;
    if (a == 0) {
        return;
    }
    if (b == 0) {
        return;
    }
    params.f8 = fval;
    params.f6 = (s16)table.v[b];
    if (p7 != NULL) {
        params.vec[0] = *(f32 *)((char *)p7 + 0xc);
        params.vec[1] = *(f32 *)((char *)p7 + 0x10);
        params.vec[2] = *(f32 *)((char *)p7 + 0x14);
    } else {
        params.vec[0] = lbl_803DF35C;
        params.vec[1] = lbl_803DF35C;
        params.vec[2] = lbl_803DF35C;
    }
    for (i = 0; i < count; i++) {
        (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
            obj, ps[a], &params, 2, -1, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void objfx_spawnMaskedHitEffect(void *obj, u8 a, u8 b, u8 mask, void *p7, f32 fval) {
    PartfxParams params;
    Tbl11 table1 = *(Tbl11 *)lbl_802C20EC;
    Tbl7 table2 = *(Tbl7 *)lbl_802C2104;
    if (a == 0) {
        return;
    }
    if (b == 0) {
        return;
    }
    if ((mask & (u16)(int)gExpgfxFrameTimerA) == 0) {
        return;
    }
    params.f8 = fval;
    params.f6 = (s16)table1.v[b];
    if (p7 != NULL) {
        params.vec[0] = *(f32 *)((char *)p7 + 0xc);
        params.vec[1] = *(f32 *)((char *)p7 + 0x10);
        params.vec[2] = *(f32 *)((char *)p7 + 0x14);
    } else {
        params.vec[0] = lbl_803DF35C;
        params.vec[1] = lbl_803DF35C;
        params.vec[2] = lbl_803DF35C;
    }
    (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
        obj, table2.v[a], &params, 2, -1, 0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void objfx_spawnDirectionalBurst(void *obj, u8 idx, u8 kind, u8 mode, u8 chance, void *origin,
                    int flags, f32 f8val, f32 mult) {
    PartfxParams params;
    ParticleTblA tA = *(ParticleTblA *)((char *)lbl_802C1FD8 + 0xd0);
    ParticleTbl8 tB = *(ParticleTbl8 *)((char *)lbl_802C1FD8 + 0xe4);
    ParticleTbl8 tC = *(ParticleTbl8 *)((char *)lbl_802C1FD8 + 0xf4);
    ParticleTbl8 tD = *(ParticleTbl8 *)((char *)lbl_802C1FD8 + 0x104);
    u16 rvec[3];
    int i;
    f32 f30;

    params.f8 = f8val;
    params.f6 = (s16)tA.v[kind];
    params.pad[1] = 0x3c;
    for (i = 0; i < 4; i++) {
        if (randomGetRange(0, 0x63) >= chance) {
            continue;
        }
        f30 = (f32)randomGetRange(0, 1000) / lbl_803DF368;
        switch (mode) {
        case 1:
            rvec[0] = (u16)randomGetRange(0, 0xffff);
            rvec[1] = (u16)randomGetRange(0, 0xffff);
            rvec[2] = (u16)randomGetRange(0, 0xffff);
            params.vec[0] = mult * (lbl_803DF354 - f30 * (f30 * f30));
            break;
        case 2:
            rvec[0] = 0;
            rvec[1] = (u16)randomGetRange(0, 0xffff);
            rvec[2] = 0;
            params.vec[0] = mult * (lbl_803DF354 - f30 * (f30 * f30));
            break;
        case 3:
            rvec[0] = (u16)randomGetRange(0, 0xffff);
            rvec[1] = 0;
            rvec[2] = 0;
            params.vec[0] = mult * (lbl_803DF354 - f30 * (f30 * f30));
            break;
        case 4:
            rvec[0] = 0;
            rvec[1] = 0;
            rvec[2] = (u16)randomGetRange(0, 0xffff);
            params.vec[0] = mult * (lbl_803DF354 - f30 * (f30 * f30));
            break;
        case 5:
            rvec[0] = (u16)randomGetRange(0x7fff, 0xffff);
            rvec[1] = 0;
            rvec[2] = (u16)randomGetRange(0, 0xffff);
            params.vec[0] = mult * (lbl_803DF354 - f30 * (f30 * f30));
            break;
        case 6:
            rvec[0] = (u16)randomGetRange(0, 0xffff);
            rvec[1] = (u16)randomGetRange(0, 0xffff);
            rvec[2] = (u16)randomGetRange(0, 0xffff);
            params.vec[0] = f30 * mult;
            break;
        case 7:
            rvec[0] = (u16)randomGetRange(0, 0xffff);
            rvec[1] = (u16)randomGetRange(0, 0xffff);
            rvec[2] = (u16)randomGetRange(0, 0xffff);
            params.vec[0] = mult * (lbl_803DF354 - f30 * (f30 * (f30 * (f30 * f30))));
            break;
        }
        params.vec[1] = lbl_803DF35C;
        params.vec[2] = lbl_803DF35C;
        mathFn_80021ac8(rvec, params.vec);
        if (origin != NULL) {
            params.vec[0] += *(f32 *)((char *)origin + 0xc);
            params.vec[1] += *(f32 *)((char *)origin + 0x10);
            params.vec[2] += *(f32 *)((char *)origin + 0x14);
        }
        params.pad[2] = (s16)tC.v[idx];
        params.pad[0] = (s16)tD.v[idx];
        (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
            obj, tB.v[idx], &params, flags | 2, -1, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void objfx_spawnArcedBurst(void *obj, u8 idx, u8 kind, u8 mode, u8 chance,
                            void *origin, int flags, f32 f8val, f32 angBase,
                            f32 lo, f32 hi) {
    PartfxParams params;
    ParticleTblA tA = *(ParticleTblA *)((char *)lbl_802C1FD8 + 0x8c);
    ParticleTbl8 tB = *(ParticleTbl8 *)((char *)lbl_802C1FD8 + 0xa0);
    ParticleTbl8 tC = *(ParticleTbl8 *)((char *)lbl_802C1FD8 + 0xb0);
    ParticleTbl8 tD = *(ParticleTbl8 *)((char *)lbl_802C1FD8 + 0xc0);
    u16 rvec[3];
    int i;
    f32 fdelta;
    f32 f30;
    f32 f29;

    params.f8 = f8val;
    params.f6 = (s16)tA.v[kind];
    params.pad[1] = 0x3c;
    fdelta = angBase - lo;
    for (i = 0; i < 4; i++) {
        u16 val;
        f32 a;
        if (randomGetRange(0, 0x63) >= chance) {
            continue;
        }
        rvec[0] = (u16)randomGetRange(0, 0xffff);
        rvec[1] = 0;
        rvec[2] = 0;
        f30 = (f32)randomGetRange(1, 1000) / lbl_803DF368;
        f29 = (f32)randomGetRange(0, 1000) / lbl_803DF368;
        params.vec[1] = lbl_803DF35C;
        params.vec[2] = lbl_803DF35C;
        switch (mode) {
        case 1:
            params.vec[0] = lbl_803DF354 - f30 * f30;
            break;
        case 2:
            f29 = f29 * (f29 * f29);
            params.vec[0] = lbl_803DF354 - f30 * f30;
            break;
        case 3:
            f29 = lbl_803DF354 - f29 * (f29 * f29);
            params.vec[0] = lbl_803DF354 - f30 * f30;
            break;
        case 4:
            val = (u16)(int)(lbl_803DF350 * f29);
            a = lbl_803DF36C * (f32)(u32)val / lbl_803DF370;
            f29 = lbl_803DF358 * (lbl_803DF354 + (f32)sin(a));
            params.vec[0] = lbl_803DF354 - f30 * f30;
            break;
        case 5:
            val = (u16)(int)(lbl_803DF350 * f29);
            a = lbl_803DF36C * (f32)(u32)val / lbl_803DF370;
            f29 = lbl_803DF358 * (lbl_803DF354 + fn_80293E80(a));
            params.vec[0] = lbl_803DF354 - f30 * f30;
            break;
        case 6:
            params.vec[0] = f30 * f30;
            break;
        case 7:
            params.vec[0] = lbl_803DF354 - f30 * (f30 * (f30 * (f30 * f30)));
            break;
        }
        params.vec[0] = params.vec[0] * (f29 * fdelta + lo);
        mathFn_80021ac8(rvec, params.vec);
        params.vec[1] = (f29 - lbl_803DF358) * hi;
        if (origin != NULL) {
            params.vec[0] += *(f32 *)((char *)origin + 0xc);
            params.vec[1] += *(f32 *)((char *)origin + 0x10);
            params.vec[2] += *(f32 *)((char *)origin + 0x14);
        }
        params.pad[2] = (s16)tC.v[idx];
        params.pad[0] = (s16)tD.v[idx];
        (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
            obj, tB.v[idx], &params, flags | 2, -1, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void objfx_spawnBoxBurst(void *obj, u8 idx, u8 kind, u8 mode, u8 chance, void *origin,
                         int flags, f32 f8val, f32 mulX, f32 mulY, f32 mulZ) {
    PartfxParams params;
    ParticleTblA tA = *(ParticleTblA *)((char *)lbl_802C1FD8 + 0x48);
    ParticleTbl8 tB = *(ParticleTbl8 *)((char *)lbl_802C1FD8 + 0x5c);
    ParticleTbl8 tC = *(ParticleTbl8 *)((char *)lbl_802C1FD8 + 0x6c);
    ParticleTbl8 tD = *(ParticleTbl8 *)((char *)lbl_802C1FD8 + 0x7c);
    int i;

    params.f8 = f8val;
    params.f6 = (s16)tA.v[kind];
    params.pad[1] = 0x3c;
    for (i = 0; i < 4; i++) {
        u16 val;
        f32 a;
        if (randomGetRange(0, 0x63) >= chance) {
            continue;
        }
        params.vec[0] = (f32)randomGetRange(0, 1000) / lbl_803DF368;
        params.vec[1] = (f32)randomGetRange(0, 1000) / lbl_803DF368;
        params.vec[2] = (f32)randomGetRange(0, 1000) / lbl_803DF368;
        switch (mode) {
        case 1:
            params.vec[0] -= lbl_803DF358;
            params.vec[1] -= lbl_803DF358;
            params.vec[2] -= lbl_803DF358;
            break;
        case 2:
            params.vec[0] -= lbl_803DF358;
            params.vec[1] = params.vec[1] * (params.vec[1] * params.vec[1]) - lbl_803DF358;
            params.vec[2] -= lbl_803DF358;
            break;
        case 3:
            params.vec[0] -= lbl_803DF358;
            params.vec[1] =
                (lbl_803DF354 - params.vec[1] * (params.vec[1] * params.vec[1])) - lbl_803DF358;
            params.vec[2] -= lbl_803DF358;
            break;
        case 4:
            params.vec[0] -= lbl_803DF358;
            val = (u16)(int)(lbl_803DF350 * params.vec[1]);
            a = lbl_803DF36C * (f32)(u32)val / lbl_803DF370;
            params.vec[1] = lbl_803DF358 * sin(a);
            params.vec[2] -= lbl_803DF358;
            break;
        case 5:
            params.vec[0] -= lbl_803DF358;
            val = (u16)(int)(lbl_803DF350 * params.vec[1]);
            a = lbl_803DF36C * (f32)(u32)val / lbl_803DF370;
            params.vec[1] = lbl_803DF358 * fn_80293E80(a);
            params.vec[2] -= lbl_803DF358;
            break;
        case 6:
            params.vec[0] -= lbl_803DF358;
            params.vec[1] -= lbl_803DF358;
            params.vec[2] -= lbl_803DF358;
            break;
        case 7:
            params.vec[0] -= lbl_803DF358;
            params.vec[1] -= lbl_803DF358;
            params.vec[2] -= lbl_803DF358;
            break;
        }
        params.vec[0] = params.vec[0] * mulX;
        params.vec[1] = params.vec[1] * mulY;
        params.vec[2] = params.vec[2] * mulZ;
        if (origin != NULL) {
            params.vec[0] += *(f32 *)((char *)origin + 0xc);
            params.vec[1] += *(f32 *)((char *)origin + 0x10);
            params.vec[2] += *(f32 *)((char *)origin + 0x14);
        }
        params.pad[2] = (s16)tC.v[idx];
        params.pad[0] = (s16)tD.v[idx];
        (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
            obj, tB.v[idx], &params, flags | 2, -1, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void objShowButtonGlow(void *obj, u8 mode, f32 intensity) {
    PartfxParams params;
    int i;

    params.f8 = intensity;
    if (mode == 0) {
        return;
    }
    switch (mode) {
    case 1:
        params.f6 = 0xc8c;
        for (i = 0; i < 0x28; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7c8, &params, 1, -1, 0);
        }
        params.f6 = 1;
        (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
            obj, 0x7f3, &params, 1, -1, 0);
        (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
            obj, 0x7f3, &params, 1, -1, 0);
        break;
    case 2:
        params.f6 = 0xc8d;
        for (i = 0; i < 0x28; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7c8, &params, 1, -1, 0);
        }
        params.f6 = 0;
        (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
            obj, 0x7f3, &params, 1, -1, 0);
        (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
            obj, 0x7f3, &params, 1, -1, 0);
        (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
            obj, 0x7f3, &params, 1, -1, 0);
        break;
    case 3:
        params.f6 = 0xc8e;
        for (i = 0; i < 0x28; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7c8, &params, 1, -1, 0);
        }
        params.f6 = 2;
        (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
            obj, 0x7f3, &params, 1, -1, 0);
        (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
            obj, 0x7f3, &params, 1, -1, 0);
        break;
    case 4:
        params.f6 = 0;
        for (i = 0; i < 0x14; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7f2, &params, 1, -1, 0);
        }
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void objfx_spawnFrameTimedHitPulse(void *obj, u8 a, u8 b, f32 c, f32 d) {
    Tbl5 t1 = *(Tbl5 *)lbl_802C1FF8;
    Tbl5 t2 = *(Tbl5 *)lbl_802C200C;
    f32 vec[3];
    int frame;
    if (a == 0) {
        return;
    }
    if (b == 0) {
        return;
    }
    if (b >= 5) {
        return;
    }
    if (gExpgfxFrameTimerB != lbl_803DF35C) {
        frame = 0;
    } else {
        frame = (u8)t2.v[b];
    }
    vec[0] = lbl_803DF35C;
    vec[1] = d;
    vec[2] = lbl_803DF35C;
    if (a == 1) {
        fn_80098B18(obj, c, (u8)t1.v[b], frame, 0, vec);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void objfx_spawnLightPulse(void *obj, u8 type, int a3, u8 mode, void *light, f32 fa, f32 fb) {
    PartfxParams params;
    f32 lvec[3];
    f32 proj[3];
    int screen[3];
    int i;
    int depth;
    int n = framesThisStep > 3 ? 3 : framesThisStep;

    params.f8 = fa;
    if (fb <= lbl_803DF380) {
        fb = lbl_803DF380;
    }
    params.vec[0] = fb;
    switch (type) {
    case 1:
        params.f6 = 0x159;
        params.pad[2] = 1;
        for (i = 0; i < (u8)n; i++) {
            (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7be, &params, 2, -1, light);
        }
        break;
    case 2:
        params.f6 = 0x159;
        params.pad[2] = 0;
        for (i = 0; i < (u8)n; i++) {
            (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7be, &params, 2, -1, light);
        }
        break;
    case 3:
        params.f6 = 0x8e;
        for (i = 0; i < (u8)n; i++) {
            (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7c0, &params, 2, -1, light);
        }
        break;
    case 4: {
        int flags = 2;
        if ((*(s16 *)((char *)obj + 6) & 0x40080) != 0) {
            flags |= 0x20000000;
        }
        params.f6 = 0xc0e;
        params.pad[2] = 0;
        for (i = 0; i < (u8)n; i++) {
            (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7eb, &params, flags, -1, light);
        }
        break;
    }
    }

    if (mode != 0) {
        if (light != NULL) {
            lvec[0] = *(f32 *)((char *)light + 0xc);
            lvec[1] = *(f32 *)((char *)light + 0x10);
            lvec[2] = *(f32 *)((char *)light + 0x14);
            mathFn_80021ac8(obj, lvec);
            Camera_ProjectWorldPointWithOffset(
                &proj[2], &proj[1], &proj[0],
                *(f32 *)((char *)obj + 0x18) + lvec[0] - playerMapOffsetX,
                *(f32 *)((char *)obj + 0x1c) + lvec[1],
                *(f32 *)((char *)obj + 0x20) + lvec[2] - playerMapOffsetZ, lbl_803DF384);
        } else {
            Camera_ProjectWorldPointWithOffset(
                &proj[2], &proj[1], &proj[0],
                *(f32 *)((char *)obj + 0x18) - playerMapOffsetX,
                *(f32 *)((char *)obj + 0x1c),
                *(f32 *)((char *)obj + 0x20) - playerMapOffsetZ, lbl_803DF384);
        }
        Camera_NdcToScreen(&screen[2], &screen[1], &screen[0], proj[2], proj[1], proj[0]);
        depth = maybeReadDepthBuffer(screen[2], screen[1], obj);
        if (screen[0] > depth) {
            switch (mode) {
            case 1:
                mode = 4;
                break;
            case 2:
                mode = 5;
                break;
            case 3:
                mode = 6;
                break;
            }
        }
        switch (mode) {
        case 1:
            params.f6 = type == 1 ? 0xc75 : 0xc74;
            for (i = 0; i < (u8)n; i++) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                    obj, 0x7bf, &params, 2, -1, light);
            }
            break;
        case 2:
            params.f6 = 0x605;
            for (i = 0; i < (u8)n; i++) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                    obj, 0x7bf, &params, 2, -1, light);
            }
            break;
        case 3:
            params.f6 = type == 1 ? 0xc75 : 0xc74;
            for (i = 0; i < (u8)n; i++) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                    obj, 0x7c1, &params, 2, -1, light);
            }
            break;
        case 4:
            params.f6 = type == 1 ? 0xc75 : 0xc74;
            for (i = 0; i < (u8)n; i++) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                    obj, 0x7c4, &params, 2, -1, light);
            }
            break;
        case 5:
            params.f6 = 0x605;
            for (i = 0; i < (u8)n; i++) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                    obj, 0x7c4, &params, 2, -1, light);
            }
            break;
        case 6:
            params.f6 = type == 1 ? 0xc75 : 0xc74;
            for (i = 0; i < (u8)n; i++) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                    obj, 0x7c5, &params, 2, -1, light);
            }
            break;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void objfx_spawnFlaggedTrailBurst(void *obj, u8 mode, int p5, int p6, int p7, f32 fval) {
    PartfxFlags params;
    int i;
    u8 count;

    if (framesThisStep > 3) {
        count = 3;
    } else {
        count = framesThisStep;
    }
    params.f6 = (s16)p5;
    params.f4 = (s16)p6;
    params.f8 = fval;
    switch (mode) {
    case 1:
        params.a = 0;
        params.b = 0;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b7, &params, 1, -1, p7);
        }
        break;
    case 2:
        params.a = 1;
        params.b = 0;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b7, &params, 1, -1, p7);
        }
        break;
    case 3:
        params.a = 0;
        params.b = 1;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b7, &params, 1, -1, p7);
        }
        break;
    case 4:
        params.a = 1;
        params.b = 1;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b7, &params, 1, -1, p7);
        }
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void projectileParticleFxFn_80099660(void *obj, int mode) {
    PartfxParams ps;
    f32 tailScale;
    f32 scale;
    int i;

    switch (mode) {
    case 0:
        scale = lbl_803DF358;
        for (i = 10; i < 20; i += 2) {
            ps.f6 = (s16)i;
            ps.f8 = scale;
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7a0, &ps, 1, -1, 0);
        }
        tailScale = lbl_803DF390;
        break;
    case 1:
        scale = lbl_803DF354;
        for (i = 10; i < 20; i += 2) {
            ps.f6 = (s16)i;
            ps.f8 = scale;
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7a0, &ps, 1, -1, 0);
        }
        for (i = 0; i < 20; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7a0, 0, 1, -1, 0);
        }
        tailScale = lbl_803DF354;
        break;
    case 2:
        scale = lbl_803DF354;
        for (i = 10; i < 20; i += 2) {
            ps.f6 = (s16)i;
            ps.f8 = scale;
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7a1, &ps, 1, -1, 0);
        }
        for (i = 0; i < 20; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7a1, 0, 1, -1, 0);
        }
        tailScale = lbl_803DF354;
        break;
    case 3:
        scale = lbl_803DF358;
        for (i = 10; i < 20; i += 2) {
            ps.f6 = (s16)i;
            ps.f8 = scale;
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7a6, &ps, 1, -1, 0);
        }
        tailScale = lbl_803DF390;
        break;
    case 4:
        scale = lbl_803DF354;
        for (i = 10; i < 20; i += 2) {
            ps.f6 = (s16)i;
            ps.f8 = scale;
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7a6, &ps, 1, -1, 0);
        }
        for (i = 0; i < 20; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7a6, 0, 1, -1, 0);
        }
        tailScale = lbl_803DF354;
        break;
    case 6:
        scale = lbl_803DF358;
        for (i = 10; i < 20; i += 2) {
            ps.f6 = (s16)i;
            ps.f8 = scale;
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7a1, &ps, 1, -1, 0);
        }
        tailScale = lbl_803DF390;
        break;
    default:
        return;
    }
    (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
        obj, 0x79f, 0, 1, -1, &tailScale);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void itemPickupDoParticleFx(void *obj, int mode, u8 count, f32 fval) {
    PartfxParams params;
    int i;

    params.f8 = fval;
    if (mode == 0) {
        return;
    }
    switch (mode) {
    case 1:
        params.f6 = 0x79;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b1, &params, 1, -1, 0);
        }
        break;
    case 2:
        params.f6 = 0xc13;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b1, &params, 1, -1, 0);
        }
        break;
    case 3:
        params.f6 = 0x71;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b1, &params, 1, -1, 0);
        }
        break;
    case 4:
        params.f6 = 0xdb;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b1, &params, 1, -1, 0);
        }
        break;
    case 5:
        params.f6 = 0x77;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b1, &params, 1, -1, 0);
        }
        break;
    case 6:
        params.f6 = 0x7b;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b1, &params, 1, -1, 0);
        }
        break;
    case 7:
        params.f6 = 0xda;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b1, &params, 1, -1, 0);
        }
        break;
    case 8:
        params.f6 = 0xdd;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7cc, &params, 1, -1, 0);
        }
        break;
    case 10:
        params.f6 = 0xde;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7cc, &params, 1, -1, 0);
        }
        break;
    case 9:
        params.f6 = 0xdf;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7cc, &params, 1, -1, 0);
        }
        break;
    default:
        params.f6 = 0x5c;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b1, &params, 1, -1, 0);
        }
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void objParticleFn_80099d84(void *obj, u8 type, void *light, f32 scale, f32 fextra) {
    f32 p8 = fextra;
    PartfxParams params;
    ColorTbl colors = *(ColorTbl *)lbl_802C1FD8;
    f32 zoff = lbl_803DF394;
    u8 *cbuf;

    params.f8 = scale;
    params.pad[0] = 0;
    params.pad[2] = 0;
    params.pad[1] = 0;
    params.f6 = 0xc0a;
    switch (type) {
    case 1:
        params.vec[0] = scale * (f32)randomGetRange(-10, 10);
        params.vec[1] = scale * (f32)randomGetRange(-10, 10);
        params.vec[2] = scale * (f32)randomGetRange(-10, 10);
        (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
            obj, 0x32f, &params, 2, -1, &p8);
        break;
    case 2:
        params.vec[0] = scale * (f32)randomGetRange(-10, 10);
        params.vec[1] = scale * (f32)randomGetRange(-10, 10);
        params.vec[2] = scale * (f32)randomGetRange(-10, 10);
        (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
            obj, 0x330, &params, 2, -1, &p8);
        break;
    case 3:
        (*(void (*)(void *, int, void *, int, int))(*(int *)(*lbl_803DCAB4 + 0xc)))(
            obj, 0x32f, &p8, 0x19, 0);
        break;
    case 4:
        (*(void (*)(void *, int, void *, int, int))(*(int *)(*lbl_803DCAB4 + 0xc)))(
            obj, 0x330, &p8, 0x19, 0);
        break;
    case 5:
        params.f6 = 0xc0a;
        (*(void (*)(void *, int, void *, int, void *))(*(int *)(*lbl_803DCAB4 + 0xc)))(
            obj, 0x7cd, &p8, 0x32, &params);
        break;
    case 6:
        params.f6 = 0xc0d;
        (*(void (*)(void *, int, void *, int, void *))(*(int *)(*lbl_803DCAB4 + 0xc)))(
            obj, 0x7ce, &p8, 0x50, &params);
        break;
    case 7:
        params.f6 = 0x605;
        params.pad[2] = 1;
        (*(void (*)(void *, int, void *, int, void *))(*(int *)(*lbl_803DCAB4 + 0xc)))(
            obj, 0x7cf, &p8, 0x19, &params);
        zoff = lbl_803DF35C;
        break;
    case 8:
        params.f6 = 0x605;
        params.pad[2] = 0;
        (*(void (*)(void *, int, void *, int, void *))(*(int *)(*lbl_803DCAB4 + 0xc)))(
            obj, 0x7cf, &p8, 0x19, &params);
        zoff = lbl_803DF35C;
        break;
    }

    if (light != NULL) {
        modelLightStruct_setLightKind(light, 2);
        lightVecFn_8001dd88(light, *(f32 *)((char *)obj + 0x18),
                            *(f32 *)((char *)obj + 0x1c) + zoff,
                            *(f32 *)((char *)obj + 0x20));
        cbuf = (u8 *)&colors;
        modelLightStruct_setColorsA8AC(light, cbuf[type * 3], cbuf[type * 3 + 1],
                                       cbuf[type * 3 + 2], 0xff);
        modelLightStruct_setColors100104(light, cbuf[type * 3], cbuf[type * 3 + 1],
                                         cbuf[type * 3 + 2], 0xff);
        lightDistAttenFn_8001dc38(light, lbl_803DF34C, lbl_803DF398);
        lightSetField4D(light, 0);
        modelLightStruct_setEnabled(light, lbl_803DF35C, 1);
        modelLightStruct_setEnabled(light, lbl_803DF354, 0);
        modelLightStruct_startColorFade(light, 0, 0);
        modelLightStruct_setAffectsAabbLightSelection(light, 1);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern u8 lbl_8030FA30[];
extern f32 lbl_803DF39C;

#pragma scheduling off
#pragma peephole off
void objLightFn_8009a1dc(f32 scale, void *obj, void *origin, u8 type, void *light)
{
    u8 args[40];
    int i;

    switch (type) {
        case 1:
            args[0] = 1;
            for (i = 10; (u8)i != 0; i--) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x325, origin, 0x200001, -1, args);
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x323, origin, 0x200001, -1, args);
            }
            for (i = 4; (u8)i != 0; i--) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x326, origin, 0x200001, -1, args);
            }
            break;
        case 2:
            args[0] = 2;
            for (i = 13; (u8)i != 0; i--) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x325, origin, 0x200001, -1, args);
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x323, origin, 0x200001, -1, args);
            }
            for (i = 6; (u8)i != 0; i--) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x326, origin, 0x200001, -1, args);
            }
            break;
        case 3:
            args[0] = 3;
            for (i = 30; (u8)i != 0; i--) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x325, origin, 0x200001, -1, args);
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x323, origin, 0x200001, -1, args);
            }
            for (i = 8; (u8)i != 0; i--) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x326, origin, 0x200001, -1, args);
            }
            break;
        case 4:
            for (i = 7; (u8)i != 0; i--) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x328, origin, 0x200001, -1, NULL);
            }
            break;
        case 5:
            args[0] = 4;
            for (i = 10; (u8)i != 0; i--) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x323, origin, 0x200001, -1, args);
            }
            for (i = 4; (u8)i != 0; i--) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x326, origin, 0x200001, -1, args);
            }
            break;
        case 6:
            args[0] = 5;
            for (i = 10; (u8)i != 0; i--) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x323, origin, 0x200001, -1, args);
            }
            for (i = 4; (u8)i != 0; i--) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x326, origin, 0x200001, -1, args);
            }
            break;
        case 7:
            args[0] = 6;
            for (i = 10; (u8)i != 0; i--) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x323, origin, 0x200001, -1, args);
            }
            for (i = 4; (u8)i != 0; i--) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x326, origin, 0x200001, -1, args);
            }
            break;
        case 8:
            args[0] = 7;
            for (i = 10; (u8)i != 0; i--) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x323, origin, 0x200001, -1, args);
            }
            for (i = 4; (u8)i != 0; i--) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x326, origin, 0x200001, -1, args);
            }
            break;
        case 9:
            args[0] = 8;
            for (i = 10; (u8)i != 0; i--) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x323, origin, 0x200001, -1, args);
            }
            for (i = 4; (u8)i != 0; i--) {
                (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x326, origin, 0x200001, -1, args);
            }
            break;
    }

    if (light != NULL) {
        modelLightStruct_setLightKind(light, 2);
        lightVecFn_8001dd88(light, *(f32 *)((char *)origin + 0xc),
                            lbl_803DF384 + *(f32 *)((char *)origin + 0x10),
                            *(f32 *)((char *)origin + 0x14));
        modelLightStruct_setColorsA8AC(light, lbl_8030FA30[type * 3], lbl_8030FA30[type * 3 + 1], lbl_8030FA30[type * 3 + 2], 0xff);
        modelLightStruct_setColors100104(light, lbl_8030FA30[type * 3], lbl_8030FA30[type * 3 + 1], lbl_8030FA30[type * 3 + 2], 0xff);
        lightDistAttenFn_8001dc38(light, lbl_803DF394, lbl_803DF39C);
        lightSetField4D(light, 0);
        modelLightStruct_setEnabled(light, lbl_803DF35C, 1);
        modelLightStruct_setEnabled(light, lbl_803DF358, 0);
        modelLightStruct_startColorFade(light, 0, 0);
        modelLightStruct_setAffectsAabbLightSelection(light, 1);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8009A8C8(u8 *obj, f32 thresh) {
    u8 *player = Obj_GetPlayerObject();
    if (player == NULL) {
        return;
    }
    if (*(u16 *)(player + 0xb0) & 0x1000) {
        return;
    }
    {
        f32 d = Camera_DistanceToCurrentViewPosition(*(f32 *)(obj + 0x18), *(f32 *)(obj + 0x1c), *(f32 *)(obj + 0x20));
        if (d <= thresh) {
            f32 t = lbl_803DF354 - d / thresh;
            CameraShake_Start(lbl_803DF3A0 * t, lbl_803DF384 * t, lbl_803DF3A4);
            doRumble(lbl_803DF3A8 * t);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DIMexplosionFn_8009a96c(u8 *src, f32 vx, f32 vy, f32 vz, f32 fval, u8 a, u8 flag4,
                             u8 flag8, u8 flag10, u8 doShake, u8 flag20, u8 f1cinit) {
    u8 *obj;
    if (Obj_IsLoadingLocked() != 0) {
        obj = Obj_AllocObjectSetup(0x24, 0x253);
        *(u8 *)(obj + 4) = 2;
        *(u8 *)(obj + 5) = 1;
        *(f32 *)(obj + 8) = vx;
        *(f32 *)(obj + 0xc) = vy;
        *(f32 *)(obj + 0x10) = vz;
        *(s8 *)(obj + 0x19) = (s8)a;
        *(s16 *)(obj + 0x1a) = (s16)(lbl_803DF3AC * fval);
        *(s16 *)(obj + 0x1c) = (u8)f1cinit;
        if (flag4 != 0) {
            *(s16 *)(obj + 0x1c) |= 4;
        }
        if (flag8 != 0) {
            *(s16 *)(obj + 0x1c) |= 8;
        }
        if (flag10 != 0) {
            *(s16 *)(obj + 0x1c) |= 0x10;
        }
        if (flag20 != 0) {
            *(s16 *)(obj + 0x1c) |= 0x20;
        }
        if (doShake != 0) {
            u8 *player = Obj_GetPlayerObject();
            if (player != NULL && (*(u16 *)(player + 0xb0) & 0x1000) == 0) {
                f32 d = Camera_DistanceToCurrentViewPosition(*(f32 *)(src + 0x18),
                                                             *(f32 *)(src + 0x1c),
                                                             *(f32 *)(src + 0x20));
                if (d <= lbl_803DF3B0) {
                    f32 t = lbl_803DF354 - d / lbl_803DF3B0;
                    CameraShake_Start(lbl_803DF3A0 * t, lbl_803DF384 * t, lbl_803DF3A4);
                    doRumble(lbl_803DF3A8 * t);
                }
            }
        }
        Obj_SetupObject(obj, 5, *(s8 *)(src + 0xac), -1, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void spawnExplosion(u8 *src, f32 fval, u8 a, u8 flag4, u8 flag8, u8 flag10, u8 doShake,
                    u8 flag20, u8 f1cinit) {
    u8 *obj;
    if (Obj_IsLoadingLocked() != 0) {
        obj = Obj_AllocObjectSetup(0x24, 0x253);
        *(u8 *)(obj + 4) = 2;
        *(u8 *)(obj + 5) = 1;
        *(f32 *)(obj + 8) = *(f32 *)(src + 0x18);
        *(f32 *)(obj + 0xc) = *(f32 *)(src + 0x1c);
        *(f32 *)(obj + 0x10) = *(f32 *)(src + 0x20);
        *(s8 *)(obj + 0x19) = (s8)a;
        *(s16 *)(obj + 0x1a) = (s16)(lbl_803DF3AC * fval);
        *(s16 *)(obj + 0x1c) = (u8)f1cinit;
        if (flag4 != 0) {
            *(s16 *)(obj + 0x1c) |= 4;
        }
        if (flag8 != 0) {
            *(s16 *)(obj + 0x1c) |= 8;
        }
        if (flag10 != 0) {
            *(s16 *)(obj + 0x1c) |= 0x10;
        }
        if (flag20 != 0) {
            *(s16 *)(obj + 0x1c) |= 0x20;
        }
        if (doShake != 0) {
            u8 *player = Obj_GetPlayerObject();
            if (player != NULL && (*(u16 *)(player + 0xb0) & 0x1000) == 0) {
                f32 d = Camera_DistanceToCurrentViewPosition(*(f32 *)(src + 0x18),
                                                             *(f32 *)(src + 0x1c),
                                                             *(f32 *)(src + 0x20));
                if (d <= lbl_803DF3B0) {
                    f32 t = lbl_803DF354 - d / lbl_803DF3B0;
                    CameraShake_Start(lbl_803DF3A0 * t, lbl_803DF384 * t, lbl_803DF3A4);
                    doRumble(lbl_803DF3A8 * t);
                }
            }
        }
        Obj_SetupObject(obj, 5, *(s8 *)(src + 0xac), -1, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset


extern f32 lbl_803DF388;
extern f32 lbl_803DF38C;

#pragma scheduling off
#pragma peephole off
void fn_80098B18(void *obj, f32 scale, int type, int count, int mode, f32 *vec) {
    PartfxParams params;
    int i;
    int j;
    int effB;
    int t;
    int n;

    if (framesThisStep > 3) {
        n = 3;
    } else {
        n = framesThisStep;
    }

    params.f8 = scale;
    if (vec != NULL) {
        params.vec[0] = vec[0];
        params.vec[1] = vec[1];
        params.vec[2] = vec[2];
    } else {
        f32 z = lbl_803DF35C;
        params.vec[0] = z;
        params.vec[1] = z;
        params.vec[2] = z;
    }

    t = (u8)type;
    switch (t) {
    case 3:
        params.f8 = params.f8 * lbl_803DF388;
        effB = 1968;
        break;
    case 9:
    case 10:
        mode = 0;
        count = 0;
        break;
    case 12:
    case 13:
    case 14:
        mode = 0;
        if (count != 0) {
            count = 8;
        }
        break;
    default:
        effB = 1967;
        break;
    }

    if ((u8)count != 0) {
        switch ((u8)count) {
        case 1:
            params.f6 = -20536;
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1965, &params, 1, -1, 0);
            break;
        case 2:
            params.f6 = 10000;
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1965, &params, 1, -1, 0);
            break;
        case 3:
            params.f6 = 500;
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1965, &params, 1, -1, 0);
            break;
        case 4:
            params.f6 = -1;
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1965, &params, 1, -1, 0);
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1966, &params, 1, -1, 0);
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1966, &params, 1, -1, 0);
            break;
        case 5:
            params.f6 = 32767;
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1965, &params, 1, -1, 0);
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1966, &params, 1, -1, 0);
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1966, &params, 1, -1, 0);
            break;
        case 6:
            params.f6 = 10000;
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1965, &params, 1, -1, 0);
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1966, &params, 1, -1, 0);
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1966, &params, 1, -1, 0);
            break;
        case 7:
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1966, &params, 1, -1, 0);
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1966, &params, 1, -1, 0);
            break;
        case 8:
            if (params.f8 < lbl_803DF358) {
                params.f8 = lbl_803DF358;
            }
            params.pad[2] = 90;
            for (i = 0; i < (u8)n * 2; i++) {
                (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1981, &params, 1, -1, 0);
            }
            break;
        }
    }

    if ((u8)mode != 0) {
        switch ((u8)mode) {
        case 1:
            params.f6 = 127;
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, effB, &params, 1, -1, 0);
            break;
        case 2:
            params.f6 = 192;
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, effB, &params, 1, -1, 0);
            break;
        case 3:
            params.f6 = 255;
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, effB, &params, 1, -1, 0);
            break;
        }
    }

    params.f8 = scale;
    if ((u8)type != 0) {
        switch (t) {
        case 1:
            params.f6 = 3085;
            for (j = 0; j < (u8)n; j++) {
                (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1960, &params, 1, -1, 0);
            }
            break;
        case 2:
            params.f6 = 3082;
            for (j = 0; j < (u8)n; j++) {
                (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1961, &params, 1, -1, 0);
            }
            break;
        case 3:
            params.f6 = 3082;
            for (j = 0; j < (u8)n; j++) {
                (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1962, &params, 1, -1, 0);
            }
            break;
        case 4:
            params.f6 = 3086;
            for (j = 0; j < (u8)n; j++) {
                (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1963, &params, 1, -1, 0);
            }
            break;
        case 5:
            params.f6 = 132;
            for (j = 0; j < (u8)n; j++) {
                (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1963, &params, 1, -1, 0);
            }
            break;
        case 6:
            params.f6 = 3087;
            for (j = 0; j < (u8)n; j++) {
                (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1963, &params, 1, -1, 0);
            }
            break;
        case 7:
            params.f6 = 100;
            for (j = 0; j < (u8)n; j++) {
                (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1964, &params, 1, -1, 0);
            }
            break;
        case 8:
            params.f6 = 3198;
            for (j = 0; j < (u8)n; j++) {
                (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1964, &params, 1, -1, 0);
            }
            break;
        case 9:
            if (params.f8 < lbl_803DF358) {
                params.f8 = lbl_803DF358;
            }
            for (j = 0; j < (u8)n * 2; j++) {
                params.f6 = 0;
                (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1973, &params, 1, -1, 0);
                params.f6 = 1;
                (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1973, &params, 1, -1, 0);
            }
            break;
        case 10:
            if (params.f8 < lbl_803DF358) {
                params.f8 = lbl_803DF358;
            }
            for (j = 0; j < (u8)n * 2; j++) {
                params.f6 = 0;
                (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1974, &params, 1, -1, 0);
                params.f6 = 1;
                (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1974, &params, 1, -1, 0);
            }
            break;
        case 11:
            params.f6 = 100;
            for (j = 0; j < (u8)n; j++) {
                (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1964, &params, 1, -1, 0);
            }
            break;
        case 12:
            if (params.f8 < lbl_803DF38C) {
                params.f8 = lbl_803DF38C;
            }
            params.pad[2] = 50;
            for (j = 0; j < (u8)n * 2; j++) {
                params.f6 = 0;
                (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1979, &params, 1, -1, 0);
                params.f6 = 1;
                (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1979, &params, 1, -1, 0);
            }
            break;
        case 13:
            if (params.f8 < lbl_803DF358) {
                params.f8 = lbl_803DF358;
            }
            params.pad[2] = 90;
            for (j = 0; j < (u8)n * 2; j++) {
                params.f6 = 0;
                (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1980, &params, 1, -1, 0);
                params.f6 = 1;
                (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1980, &params, 1, -1, 0);
            }
            break;
        case 14:
            if (params.f8 < lbl_803DF358) {
                params.f8 = lbl_803DF358;
            }
            params.pad[2] = 240;
            for (j = 0; j < (u8)n * 2; j++) {
                params.f6 = 0;
                (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1980, &params, 1, -1, 0);
                params.f6 = 1;
                (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 1980, &params, 1, -1, 0);
            }
            break;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
