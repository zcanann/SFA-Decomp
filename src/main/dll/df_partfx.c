#include "main/dll/df_partfx.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/objanim.h"
#include "main/resource.h"
#include "main/screen_transition.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80006950();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern int FUN_80017730();
extern undefined4 FUN_80017754();
extern undefined4 FUN_80017778();
extern undefined4 FUN_80017a88();
extern undefined4 FUN_8006f9a8();
extern undefined4 FUN_8006fd90();
extern int FUN_800c9030();
extern undefined4 FUN_8025da88();
extern undefined4 FUN_8025db38();
extern undefined8 FUN_8028682c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4 DAT_8039d0b8;
extern undefined4 DAT_8039d0bc;
extern undefined4 DAT_803dd5d0;
extern ScreenTransitionInterface **gScreenTransitionInterface;
extern EffectInterface **gPartfxInterface;
extern undefined4* DAT_803dd71c;
extern undefined4 DAT_803de090;
extern undefined4 DAT_803de0ac;
extern undefined4 DAT_803de0ad;
extern undefined4 DAT_803de0ae;
extern undefined4 DAT_803de0af;
extern undefined4 DAT_803de0b4;
extern undefined4 DAT_803de0b8;
extern undefined4 DAT_803de0bc;
extern undefined4 DAT_803de0cc;
extern f64 DOUBLE_803e1178;
extern f64 DOUBLE_803e11a0;
extern f64 DOUBLE_803e11d0;
extern f64 DOUBLE_803e1218;
extern f32 lbl_803DC074;
extern f32 lbl_803DE0A0;
extern f32 lbl_803DE0A4;
extern f32 lbl_803DE0A8;
extern f32 lbl_803E1168;
extern f32 lbl_803E1184;
extern f32 lbl_803E118C;
extern f32 lbl_803E1190;
extern f32 lbl_803E1194;
extern f32 lbl_803E1198;
extern f32 lbl_803E119C;
extern f32 lbl_803E11A8;
extern f32 lbl_803E11AC;
extern f32 lbl_803E11B0;
extern f32 lbl_803E11B4;
extern f32 lbl_803E11B8;
extern f32 lbl_803E11C0;
extern f32 lbl_803E11C4;
extern f32 lbl_803E11C8;
extern f32 lbl_803E11D8;
extern f32 lbl_803E11DC;
extern f32 lbl_803E11E0;
extern f32 lbl_803E11E4;
extern f32 lbl_803E11E8;
extern f32 lbl_803E11F0;
extern f32 lbl_803E11F4;
extern f32 lbl_803E11F8;
extern f32 lbl_803E11FC;
extern f32 lbl_803E1200;
extern f32 lbl_803E1204;
extern f32 lbl_803E1208;
extern f32 lbl_803E120C;
extern f32 lbl_803E1210;
extern f32 lbl_803E1214;
extern f32 lbl_803E1220;
extern f32 lbl_803E122C;
extern f32 lbl_803E1230;

/*
 * --INFO--
 *
 * Function: Checkpoint_func07
 * EN v1.0 Address: 0x800D6660
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x800D6844
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int* Checkpoint_find(int id, int* slot);
extern int getAngle(f32 dx, f32 dz);
extern f32 mathCosf(f32 x);
extern f32 mathSinf(f32 x);
extern f32 sqrtf(f32 x);
extern f32 lbl_803E04D8;
extern f32 lbl_803E04DC;
extern f32 lbl_803E04E8;
extern f32 lbl_803E0504;
extern f32 lbl_803E050C;
extern f32 lbl_803E0510;
extern f32 lbl_803E0514;
extern f32 lbl_803E0518;

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
int Checkpoint_func07(int* obj, int* state)
{
    int slotC;
    int slot8;
    char* cp;
    char* cp2;
    short ang;
    f32 cosv, sinv, cos2, sin2;
    f32 dist, dist2, nx, nz, offs, dz;
    f32 offs2, distA, distB, dx, dy, len, q, proj, proj2, t0, sum, frac, zero;

    if (*(int *)&((BaddieState *)state)->posY < 0) {
        *(int *)&((BaddieState *)state)->posZ = 0;
        *(f32*)((char*)state + 0xc) = lbl_803E04E8;
        if (*(int*)((char*)state + 0x10) < 0) {
            return 0;
        }
        *(int *)&((BaddieState *)state)->posY = *(int*)((char*)state + 0x10);
    }
    cp = (char*)Checkpoint_find(*(int *)&((BaddieState *)state)->posY, &slot8);
    if (cp == NULL) {
        *(int *)&((BaddieState *)state)->posY = -1;
        return 0;
    }
    cosv = mathSinf((lbl_803E04D8 * (f32)(*(u8*)(cp + 0x29) << 8)) / lbl_803E04DC);
    sinv = mathCosf((lbl_803E04D8 * (f32)(*(u8*)(cp + 0x29) << 8)) / lbl_803E04DC);
    offs = -(*(f32*)(cp + 8) * cosv + *(f32*)(cp + 0x10) * sinv);
    dist = offs + (cosv * ((GameObject *)obj)->anim.localPosX + sinv * ((GameObject *)obj)->anim.localPosZ);
    if (*(int*)(cp + 0x18) > -1 && dist >= lbl_803E04E8) {
        *(int *)&((BaddieState *)state)->posY = *(int*)(cp + 0x18);
        *(f32*)((char*)state + 0xc) = lbl_803E050C;
        *(int *)&((BaddieState *)state)->posZ = *(int *)&((BaddieState *)state)->posZ - 1;
        return *(u8*)(cp + 0x29);
    }
    if (*(int*)(cp + 0x20) < 0) {
        return *(u8*)(cp + 0x29);
    }
    cp2 = (char*)Checkpoint_find(*(int*)(cp + 0x20), &slotC);
    ang = getAngle(*(f32*)(cp2 + 8) - *(f32*)(cp + 8), *(f32*)(cp2 + 0x10) - *(f32*)(cp + 0x10));
    cos2 = mathSinf((lbl_803E04D8 * (f32)(*(u8*)(cp2 + 0x29) << 8)) / lbl_803E04DC);
    sin2 = mathCosf((lbl_803E04D8 * (f32)(*(u8*)(cp2 + 0x29) << 8)) / lbl_803E04DC);
    offs2 = -(*(f32*)(cp2 + 8) * cos2 + *(f32*)(cp2 + 0x10) * sin2);
    dist2 = offs2 + (cos2 * ((GameObject *)obj)->anim.localPosX + sin2 * ((GameObject *)obj)->anim.localPosZ);
    zero = lbl_803E04E8;
    if (dist2 < zero) {
        *(int *)&((BaddieState *)state)->posY = *(int*)(cp + 0x20);
        *(f32*)((char*)state + 0xc) = zero;
        *(int *)&((BaddieState *)state)->posZ = *(int *)&((BaddieState *)state)->posZ + 1;
        return ang;
    }
    distA = offs + (cosv * *(f32*)(cp2 + 8) + sinv * *(f32*)(cp2 + 0x10));
    distB = offs2 + (cos2 * *(f32*)(cp + 8) + sin2 * *(f32*)(cp + 0x10));
    if (((distA < zero && dist < zero) || (distA >= lbl_803E04E8 && dist >= lbl_803E04E8)) &&
        ((distB <= lbl_803E04E8 && dist2 <= lbl_803E04E8) || (distB > lbl_803E04E8 && dist2 > lbl_803E04E8))) {
        dx = *(f32*)(cp + 8) - *(f32*)(cp2 + 8);
        dy = *(f32*)(cp + 0xc) - *(f32*)(cp2 + 0xc);
        dz = *(f32*)(cp + 0x10) - *(f32*)(cp2 + 0x10);
        len = sqrtf(dz * dz + (dx * dx + dy * dy));
        if (len > lbl_803E04E8) {
            q = lbl_803E0504 / len;
            nx = dx * q;
            nz = dz * q;
        }
        proj = cosv * nx + sinv * nz;
        if (proj > lbl_803E0510 && proj < lbl_803E0514) {
            return ang;
        }
        t0 = -dist / proj;
        proj2 = cos2 * nx + sin2 * nz;
        if (proj2 > lbl_803E0510 && proj2 < lbl_803E0514) {
            return ang;
        }
        sum = t0 + dist2 / proj2;
        frac = lbl_803E04E8;
        if (lbl_803E04E8 != sum) {
            frac = t0 / sum;
        }
        *(f32*)((char*)state + 0xc) = frac;
        if (*(f32*)((char*)state + 0xc) < lbl_803E04E8) {
            *(f32*)((char*)state + 0xc) = lbl_803E04E8;
        }
        if (*(f32*)((char*)state + 0xc) >= lbl_803E0518) {
            *(f32*)((char*)state + 0xc) = lbl_803E0518;
        }
    }
    return ang;
}
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset


/*
 * --INFO--
 *
 * Function: FUN_800d7780
 * EN v1.0 Address: 0x800D7780
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x800D7CFC
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d7780(undefined param_1)
{
  DAT_803de0af = param_1;
  return;
}



/* Trivial 4b 0-arg blr leaves. */
void Checkpoint_release(void) {}
void Dummy04_func14_nop(void) {}
void Dummy04_func26_nop(void) {}
void Dummy04_func25_nop(void) {}
void Dummy04_func23_nop(void) {}
void Dummy04_func20_nop(void) {}
void Dummy04_func1F_nop(void) {}
void Dummy04_func1E_nop(void) {}
void Dummy04_func1C_nop(void) {}
void Dummy04_func1B_nop(void) {}
void Dummy04_func1A_nop(void) {}
void Dummy04_func19_nop(void) {}
void Dummy04_func18_nop(void) {}
void Dummy04_func17_nop(void) {}
void Dummy04_func16_nop(void) {}
void Dummy04_onSetupPlayer(void) {}
void Dummy04_func15_nop(void) {}
void Dummy04_func13_nop(void) {}
void Dummy04_func12_nop(void) {}
void Dummy04_func10_nop(void) {}
void Dummy04_func0E_nop(void) {}
void Dummy04_func0C_nop(void) {}
void Dummy04_onSelectSave(void) {}
void Dummy04_func08_nop(void) {}
void Dummy04_func07_nop(void) {}
void Dummy04_func04_nop(void) {}
void Dummy04_release(void) {}
void Dummy04_initialise(void) {}
void dll_0F_func19_nop(void) {}

/* 8b "li r3, N; blr" returners. */
int Dummy04_func24_ret_0(void) { return 0x0; }
int Dummy04_func22_ret_127(void) { return 0x7f; }
int Dummy04_func21_ret_0(void) { return 0x0; }
int Dummy04_func1D_ret_0(void) { return 0x0; }
int Dummy04_func11_ret_0(void) { return 0x0; }
int Dummy04_func0F_ret_0(void) { return 0x0; }
int Dummy04_func0D_ret_0(void) { return 0x0; }
int Dummy04_func0B_ret_0(void) { return 0x0; }
int Dummy04_func0A_ret_0(void) { return 0x0; }
int Dummy04_func05_ret_0(void) { return 0x0; }

/* sda21 accessors. */
extern u8 lbl_803DD42D;
u8 screenTransition_func07(void) { return lbl_803DD42D; }

/* Pattern wrappers. */
extern u32 lbl_803DD410;
void Checkpoint_reset(void) { lbl_803DD410 = 0x0; }

/* 12b 3-insn patterns. */
extern u32 lbl_803DD43C;
extern u32 lbl_803DD438;
void player_setAnimIds(int unused1, int unused2, u32 a, u32 b) { lbl_803DD43C = a; lbl_803DD438 = b; }

/* misc 8b leaves */
extern f32 lbl_803DD420;
f32 screenTransition_getAlpha(void) { return lbl_803DD420; }

/* Pattern wrappers. */
int Dummy04_func03_ret_m1(void) { return -0x1; }

/* sda21 writers. */
extern u8 lbl_803DD42F;
#pragma peephole off
void setScreenTransitionPause(u32 pause) { lbl_803DD42F = (u8)pause; }
#pragma peephole reset

/* fcmp-eq-to-bool. */
extern f32 lbl_803E0558;
u32 isScreenTransitionActive(void) { return lbl_803E0558 == lbl_803DD420; }

/* multi-store leaf (single float broadcast). */
extern f32 lbl_803E0570;
void player_clearXZvel(int *obj, int *state) {
    f32 z = lbl_803E0570;
    ((GameObject *)obj)->anim.velocityX = z;
    ((GameObject *)obj)->anim.velocityZ = z;
    ((BaddieState *)state)->animSpeedC = z;
    ((BaddieState *)state)->animSpeedA = z;
    ((BaddieState *)state)->animSpeedB = z;
}

/* Checkpoint table initialiser. */
extern u32 lbl_8039CA98[];
extern void *lbl_803DD41C;
extern void *lbl_803DD418;
extern void Sfx_PlayFromObject(int* obj, int sfxId);
extern f32 lbl_803E0588;
extern f32 lbl_803E0564;
extern f32 lbl_803E0560;
extern f32 lbl_803E055C;
extern f32 lbl_803DD424;
extern f32 lbl_803DD428;
extern u8 lbl_803DD42C;
extern u8 lbl_803DD42E;
extern void player_followCurve(int* obj, int* state, f32 a, f32 b, f32 t, int p5);
extern f32 lbl_803E05B4;
extern f32 lbl_803E05B8;

#pragma scheduling off
#pragma peephole off
void player_playSoundFn0F(int* obj, int* state, int bit, int idx, int* sfxTable)
{
    register int flags;
    register int mask;
    mask = 1 << bit;
    flags = *(int *)&((BaddieState *)state)->eventFlags;
    if ((flags & mask) != 0) {
        *(int *)&((BaddieState *)state)->eventFlags = flags & ~mask;
        Sfx_PlayFromObject(obj, (u16)sfxTable[idx]);
    }
}

void player_playSoundFn10(int* obj, int* state, int bit, int idx, int* sfxTable)
{
    register int flags;
    register int mask;
    mask = 1 << bit;
    flags = *(int *)&((BaddieState *)state)->eventFlags;
    if ((flags & mask) != 0) {
        *(int *)&((BaddieState *)state)->eventFlags = flags & ~mask;
        Sfx_PlayFromObject(obj, (u16)sfxTable[idx]);
    }
}

void player_render2(s16* obj, int* state, f32 f1, f32 f2)
{
    f32 cur = ((BaddieState *)state)->unk2A8;
    f32 new_ = f2 * f1 + cur;
    if (new_ > lbl_803E0588) {
        new_ = lbl_803E0588;
    }
    {
        f32 delta = new_ - cur;
        if (delta > lbl_803E0570) {
            *obj = *obj + (s32)(((BaddieState *)state)->unk300 * delta);
        }
    }
    ((BaddieState *)state)->unk2A8 = new_;
}

void player_modelMtxFn(f32* mtx, int* state, f32 f1, f32 f2)
{
    f32 cur = ((BaddieState *)state)->unk2AC;
    f32 new_ = f2 * f1 + cur;
    if (new_ > lbl_803E0588) {
        new_ = lbl_803E0588;
    }
    {
        f32 delta = new_ - cur;
        if (delta > lbl_803E0570) {
            *(f32*)((char*)mtx + 12) = *(f32*)((char*)state + 756) * delta + *(f32*)((char*)mtx + 12);
            *(f32*)((char*)mtx + 16) = *(f32*)((char*)state + 760) * delta + *(f32*)((char*)mtx + 16);
            *(f32*)((char*)mtx + 20) = ((BaddieState *)state)->pathStep * delta + *(f32*)((char*)mtx + 20);
            ((BaddieState *)state)->unk2AC = new_;
        }
    }
}

void player_findCurve(int* obj, int* state, int p3)
{
    *(int*)((char*)state + 0x33c) =
        (*gRomCurveInterface)->find(&p3, 1, *(s8*)((char*)state + 0x344),
                                    ((GameObject *)obj)->anim.localPosX,
                                    ((GameObject *)obj)->anim.localPosY,
                                    ((GameObject *)obj)->anim.localPosZ);
}

void screenTransitionFn_800d7b04(int duration, int type)
{
    lbl_803DD420 = lbl_803E0558;
    lbl_803DD424 = lbl_803E0564 / (f32)duration;
    lbl_803DD428 = lbl_803E0560;
    lbl_803DD42C = (u8)type;
    lbl_803DD42E = 5;
}

void screenTransition_fadeFrom(int duration, int type, f32 from)
{
    lbl_803DD420 = lbl_803E0558 * from;
    lbl_803DD424 = -(lbl_803E055C * from) / (f32)duration;
    lbl_803DD428 = lbl_803E0560;
    lbl_803DD42C = (u8)type;
    lbl_803DD42E = 1;
}

#pragma opt_common_subs off
void screenTransition_screenFade(int duration, int type)
{
    if (lbl_803DD424 >= lbl_803E0560 || lbl_803E0560 == lbl_803DD420) {
        lbl_803DD420 = lbl_803E0558;
    }
    lbl_803DD424 = lbl_803E0564 / (f32)duration;
    lbl_803DD428 = lbl_803E0560;
    lbl_803DD42C = (u8)type;
    lbl_803DD42E = 1;
}
#pragma opt_common_subs reset

#pragma opt_common_subs off
void screenTransition_Do(int duration, int type)
{
    if (lbl_803DD424 <= lbl_803E0560 || lbl_803E0558 == lbl_803DD420) {
        lbl_803DD420 = lbl_803E0560;
    }
    lbl_803DD424 = lbl_803E055C / (f32)duration;
    lbl_803DD428 = lbl_803E0560;
    lbl_803DD42C = (u8)type;
    lbl_803DD42E = 0;
}
#pragma opt_common_subs reset

void dll_0F_func0B(int* obj, int* state, f32 f1, f32 f2, f32 f3)
{
    if (*(f32*)((char*)state + 664) > lbl_803E05B4) {
        f32 q = (f2 * f1) / f3;
        *(s16*)obj = (f32)*(s16*)obj + lbl_803E05B8 * q;
    }
}

void player_updateCurve(int* obj, int* state, f32 t)
{
    int idx = *(int*)((char*)state + 828);
    if (idx == -1) {
        *(f32*)((char*)state + 700) = lbl_803E0570;
    } else {
        int* curve = (int *)(*gRomCurveInterface)->getById(idx);
        if (curve == NULL) {
            *(f32*)((char*)state + 700) = lbl_803E0570;
        } else {
            player_followCurve(obj, state, *(f32*)((char*)curve + 8), *(f32*)((char*)curve + 16), t, 1);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E0574;
extern f32 lbl_803E0578;
extern f32 lbl_803E057C;
extern f32 lbl_803E0580;
extern f32 lbl_803E0584;

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void player_followCurve(int* obj, int* state, f32 cx, f32 cz, f32 t, int p5)
{
    f32 dx, dz, dist, max;

    *(u32*)state &= ~0x100000;
    dx = ((GameObject *)obj)->anim.localPosX - cx;
    dz = ((GameObject *)obj)->anim.localPosZ - cz;
    dist = sqrtf(dx * dx + dz * dz);
    *(f32*)((char*)state + 0x2bc) = dist;
    max = lbl_803E0578;
    if (*(f32*)((char*)state + 0x2bc) < lbl_803E0580) {
        max = lbl_803E0584 * *(f32*)((char*)state + 0x2bc);
        ((BaddieState *)state)->animSpeedC = ((BaddieState *)state)->animSpeedC * lbl_803E0574;
    }
    if (dist > max) {
        f32 q = dist / max;
        dx = dx / q;
        dz = dz / q;
    }
    ((BaddieState *)state)->unk290 = dx;
    ((BaddieState *)state)->unk28C = -dz;
    ((BaddieState *)state)->unk290 = ((BaddieState *)state)->unk290 * t;
    ((BaddieState *)state)->unk28C = ((BaddieState *)state)->unk28C * t;
    if (((BaddieState *)state)->unk290 > lbl_803E0578) {
        ((BaddieState *)state)->unk290 = lbl_803E0578;
    }
    if (((BaddieState *)state)->unk290 < lbl_803E057C) {
        ((BaddieState *)state)->unk290 = lbl_803E057C;
    }
    if (((BaddieState *)state)->unk28C > lbl_803E0578) {
        ((BaddieState *)state)->unk28C = lbl_803E0578;
    }
    if (((BaddieState *)state)->unk28C < lbl_803E057C) {
        ((BaddieState *)state)->unk28C = lbl_803E057C;
    }
}
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

extern u8 lbl_803DD434;
extern f32 lbl_803E05A4;
extern f32 lbl_803E05A8;
extern f32 lbl_803E05AC;
extern f32 lbl_803E05B0;

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void dll_0F_func13(s16* obj, int* state, int angle, f32 t, f32 scale)
{
    f32 ang, vx, vz, q, w, dist, c, s;

    *(s8*)((char*)state + 0x34c) |= 1;
    if ((s8)lbl_803DD434 == 0) {
        ang = (lbl_803E05A4 * (f32)angle) / lbl_803E05A8;
        vx = scale * (((BaddieState *)state)->unk298 * -mathSinf(ang));
        vz = scale * (((BaddieState *)state)->unk298 * -mathCosf(ang));
        if (((BaddieState *)state)->unk298 < lbl_803E05AC) {
            vx = lbl_803E0570;
            vz = vx;
        }
        ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX
            + (t * (vx - ((GameObject *)obj)->anim.velocityX)) / ((BaddieState *)state)->velSmoothTime;
        ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ
            + (t * (vz - ((GameObject *)obj)->anim.velocityZ)) / ((BaddieState *)state)->velSmoothTime;
    } else {
        *(s8*)((char*)state + 0x34c) &= ~1;
    }
    q = ((GameObject *)obj)->anim.velocityX * ((GameObject *)obj)->anim.velocityX;
    w = ((GameObject *)obj)->anim.velocityZ * ((GameObject *)obj)->anim.velocityZ;
    dist = sqrtf(q + w);
    ((BaddieState *)state)->animSpeedC = dist;
    if (((BaddieState *)state)->animSpeedC < lbl_803E05B0) {
        f32 z = lbl_803E0570;
        ((BaddieState *)state)->animSpeedC = z;
        ((GameObject *)obj)->anim.velocityX = z;
        ((GameObject *)obj)->anim.velocityZ = z;
    }
    c = mathSinf((lbl_803E05A4 * (f32)*obj) / lbl_803E05A8);
    s = mathCosf((lbl_803E05A4 * (f32)*obj) / lbl_803E05A8);
    ((BaddieState *)state)->animSpeedB = ((GameObject *)obj)->anim.velocityX * s - ((GameObject *)obj)->anim.velocityZ * c;
    ((BaddieState *)state)->animSpeedA = -((GameObject *)obj)->anim.velocityZ * s - ((GameObject *)obj)->anim.velocityX * c;
}
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
void Checkpoint_initialise(void) {
    lbl_803DD410 = 0;
    lbl_803DD41C = lbl_8039CA98;
    lbl_803DD418 = (void*)((u8*)lbl_8039CA98 + 0x28);
}
#pragma scheduling reset

/* Checkpoint_Add: sorted insertion of (entry->_14 as key, entry as pointer) into lbl_8039C458 table. */
typedef struct CheckpointSlot {
    u32 key;
    void *entry;
} CheckpointSlot;
extern CheckpointSlot lbl_8039C458[];
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void Checkpoint_Add(int *entry) {
    int i = 0;
    CheckpointSlot *p = lbl_8039C458;
    int count = lbl_803DD410;
    while (i < count && (u32)entry[5] > p[i].key) {
        i++;
    }
    {
        CheckpointSlot *end = &lbl_8039C458[count];
        while (count > i) {
            end->entry = (end - 1)->entry;
            end->key   = (end - 1)->key;
            end--;
            count--;
        }
    }
    lbl_803DD410 = lbl_803DD410 + 1;
    lbl_8039C458[i].entry = entry;
    lbl_8039C458[i].key   = entry[5];
}
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
void player_updateParticles(int *p1, int p2, int p3, int count, int mode)
{
    while (count != 0 && p1 != NULL) {
        if (mode == 0) {
            (*gPartfxInterface)->spawnObject(p1, p3, NULL, 2, -1, NULL);
        } else if (mode == 1) {
            (*gPartfxInterface)->spawnObject(p1, p3, NULL, 2, -1, NULL);
        } else if (mode == 2) {
            (*gPartfxInterface)->spawnObject(p1, p3, NULL, 4, -1, NULL);
        }
        count--;
    }
}

#pragma scheduling reset

#pragma scheduling off
void player_doProjGfx(int *p1, int p2, int p3, int count, int p5, int mode)
{
    void *res = Resource_Acquire((u16)(p3 + 0x58), 1);
    while (count != 0) {
        if (mode == 0) {
            (*(void (*)(int *, int, int, int, int, int))(*(int *)(*(int *)res + 4)))(p1, 0, 0, 1, -1, 0);
        } else if (mode == 1) {
            (*(void (*)(int *, int, int, int, int, int))(*(int *)(*(int *)res + 4)))(p1, 0, 0, 2, -1, 0);
        } else if (mode == 2) {
            (*(void (*)(int *, int, int, int, int, int))(*(int *)(*(int *)res + 4)))(p1, 0, 0, 4, -1, 0);
        }
        count--;
    }
    Resource_Release(res);
}
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void Checkpoint_remove(int *obj) {
    int count;
    int i = 0;
    CheckpointSlot *p = lbl_8039C458;
    CheckpointSlot *e;

    count = lbl_803DD410;

    while (i < count && (u32)*(int *)&((GameObject *)obj)->anim.localPosZ != p[i].key) {
        i++;
    }
    if (i >= count) return;
    count = lbl_803DD410 - 1;
    lbl_803DD410 = count;
    e = &lbl_8039C458[i];
    while (i < count) {
        e->entry = (e + 1)->entry;
        e->key   = (e + 1)->key;
        e++;
        i++;
    }
}
#pragma opt_common_subs reset
extern f32 timeDelta;
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void player_rotateTowardEnemy(int *obj, int *ctx, int spd) {
    int *enemy;
    f32 dx;
    f32 dz;
    int diff;
    enemy = (int *)ctx[0x2d0 / 4];
    if (enemy != 0) {
        if ((u32)enemy[0x30 / 4] == (u32)obj[0x30 / 4]) {
            dx = *(f32 *)((char *)enemy + 0xc) - ((GameObject *)obj)->anim.localPosX;
            dz = *(f32 *)((char *)enemy + 0x14) - ((GameObject *)obj)->anim.localPosZ;
        } else {
            dx = ((GameObject *)obj)->anim.worldPosX - *(f32 *)((char *)enemy + 0x18);
            dz = ((GameObject *)obj)->anim.worldPosZ - *(f32 *)((char *)enemy + 0x20);
        }
        diff = (u16)getAngle(-dx, -dz) - (u16)((GameObject *)obj)->anim.rotX;
        if (diff > 0x8000) {
            diff -= 0xffff;
        }
        if (diff < -0x8000) {
            diff += 0xffff;
        }
        ((GameObject *)obj)->anim.rotX =
            (s16)(((GameObject *)obj)->anim.rotX +
                  (int)((f32)diff * timeDelta / (lbl_803E0584 * (f32)spd)));
    }
}
#pragma opt_common_subs reset
extern f32 lbl_803E058C;
extern void setMatrixFromObjectPos(f32 *mtx, void *desc);
extern void Matrix_TransformPoint(f32 *mtx, f32 x, f32 y, f32 z, f32 *ox, f32 *oy, f32 *oz);
extern void objMove(int *obj, f32 vx, f32 vy, f32 vz);
struct PartDesc {
    s16 ang[3];
    f32 sc[4];
};
#pragma scheduling off
#pragma peephole off
void player_applyVelocityStep(int *p, int *ctx, f32 t) {
    int flags;
    int b;
    struct PartDesc desc;
    f32 mtx[16];
    f32 outY;
    f32 outX;
    f32 outZ;
    flags = ctx[0];
    if ((flags & 0x2000000) != 0) {
        return;
    }
    if ((flags & 0x200000) == 0) {
        ((GameObject *)p)->anim.velocityY = ((GameObject *)p)->anim.velocityY * lbl_803E058C;
        ((GameObject *)p)->anim.velocityY =
            -(((BaddieState *)ctx)->unk2A4 * t) + ((GameObject *)p)->anim.velocityY;
    }
    b = *(s8 *)((char *)ctx + 0x34c);
    if ((b & 1) == 0 || (b & 4) != 0) {
        desc.ang[0] = ((GameObject *)p)->anim.rotX;
        desc.ang[1] = ((GameObject *)p)->anim.rotY;
        desc.ang[2] = 0;
        desc.sc[0] = lbl_803E0588;
        desc.sc[1] = lbl_803E0570;
        desc.sc[2] = lbl_803E0570;
        desc.sc[3] = lbl_803E0570;
        setMatrixFromObjectPos(mtx, &desc);
        if ((ctx[0] & 0x10000) != 0) {
            Matrix_TransformPoint(mtx, ((BaddieState *)ctx)->animSpeedB, *(f32 *)((char *)ctx + 0x288),
                                  -((BaddieState *)ctx)->animSpeedA, &outX, &((GameObject *)p)->anim.velocityY,
                                  &outZ);
        } else {
            Matrix_TransformPoint(mtx, ((BaddieState *)ctx)->animSpeedB, lbl_803E0570,
                                  -((BaddieState *)ctx)->animSpeedA, &outX, &outY, &outZ);
        }
        ((GameObject *)p)->anim.velocityX = outX;
        ((GameObject *)p)->anim.velocityZ = outZ;
    }
    objMove(p, ((GameObject *)p)->anim.velocityX * t, ((GameObject *)p)->anim.velocityY * t,
            ((GameObject *)p)->anim.velocityZ * t);
}
extern f32 lbl_803E0590;
extern f32 lbl_803E0594;
extern s16 lbl_803DD44C;
#pragma scheduling off
#pragma peephole off
void fn_800D8414(int *obj, int *ctx) {
    int diff;
    *(f32 *)&((BaddieState *)ctx)->trackedObj = ((BaddieState *)ctx)->unk298;
    ((BaddieState *)ctx)->unk298 =
        sqrtf(((BaddieState *)ctx)->unk290 * ((BaddieState *)ctx)->unk290 +
              ((BaddieState *)ctx)->unk28C * ((BaddieState *)ctx)->unk28C);
    if (((BaddieState *)ctx)->unk298 > lbl_803E0578) {
        ((BaddieState *)ctx)->unk298 = lbl_803E0578;
    }
    ((BaddieState *)ctx)->unk298 = ((BaddieState *)ctx)->unk298 / lbl_803E0578;
    lbl_803DD44C = (s16)getAngle(((BaddieState *)ctx)->unk290, -((BaddieState *)ctx)->unk28C);
    lbl_803DD44C = (s16)(lbl_803DD44C - ((BaddieState *)ctx)->unk330);
    diff = lbl_803DD44C - (u16)((GameObject *)obj)->anim.rotX;
    if (diff > 0x8000) {
        diff -= 0xffff;
    }
    if (diff < -0x8000) {
        diff += 0xffff;
    }
    ((BaddieState *)ctx)->unk336 = (s16)(int)((f32)diff / lbl_803E0590);
    if (diff < 0) {
        *(s16 *)((char *)ctx + 0x334) = -((BaddieState *)ctx)->unk336;
    } else {
        *(s16 *)((char *)ctx + 0x334) = ((BaddieState *)ctx)->unk336;
    }
    diff += 0x10000;
    if (((BaddieState *)ctx)->unk298 < lbl_803E0594) {
        *(u8 *)((char *)ctx + 0x34b) = 0;
    } else {
        diff -= 0x6000;
        if (diff < 0) {
            diff += 0xffff;
        }
        if (diff > 0xffff) {
            diff -= 0xffff;
        }
        *(u8 *)((char *)ctx + 0x34b) = (u8)(4 - diff / 0x4000);
    }
}
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void player_getExtraSize(int *a, int *ctx, f32 px, f32 pz, f32 lo, f32 hi, f32 spd) {
    f32 dx;
    f32 dz;
    f32 mag;
    dx = *(f32 *)((char *)a + 0xc) - px;
    dz = *(f32 *)((char *)a + 0x14) - pz;
    mag = sqrtf(dx * dx + dz * dz);
    *(f32 *)((char *)ctx + 0x2bc) = mag;
    if (lbl_803E0570 != mag) {
        dx = dx / mag;
        dz = dz / mag;
    }
    if (*(f32 *)((char *)ctx + 0x2bc) > lo + hi) {
        ((BaddieState *)ctx)->unk290 = dx * spd;
        ((BaddieState *)ctx)->unk28C = -dz * spd;
    } else {
        ((BaddieState *)ctx)->animSpeedC = ((BaddieState *)ctx)->animSpeedC * lbl_803E0574;
        ((BaddieState *)ctx)->unk290 = lbl_803E0570;
        ((BaddieState *)ctx)->unk28C = lbl_803E0570;
    }
    if (((BaddieState *)ctx)->unk290 > lbl_803E0578) {
        ((BaddieState *)ctx)->unk290 = lbl_803E0578;
    }
    if (((BaddieState *)ctx)->unk290 < lbl_803E057C) {
        ((BaddieState *)ctx)->unk290 = lbl_803E057C;
    }
    if (((BaddieState *)ctx)->unk28C > lbl_803E0578) {
        ((BaddieState *)ctx)->unk28C = lbl_803E0578;
    }
    if (((BaddieState *)ctx)->unk28C < lbl_803E057C) {
        ((BaddieState *)ctx)->unk28C = lbl_803E057C;
    }
}
#pragma opt_common_subs reset
extern f32 lbl_803E05A0;
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void player_animFn16(int *obj, int *ctx, int moveA, int moveB) {
    f32 mag;
    f32 tmp;
    f32 q1, q2;
    f64 ratio;
    int idx;
    if ((s8)lbl_803DD434 != 0) {
        if (((BaddieState *)ctx)->animSpeedA > lbl_803E0570 && ((GameObject *)obj)->anim.currentMove != (int)lbl_803DD43C) {
            ObjAnim_SetCurrentMove((int)obj, lbl_803DD43C, ((GameObject *)obj)->anim.currentMoveProgress, 0);
            ((BaddieState *)ctx)->moveDone = 0;
        } else if (((BaddieState *)ctx)->animSpeedA < lbl_803E0570 && ((GameObject *)obj)->anim.currentMove != (int)lbl_803DD438) {
            ObjAnim_SetCurrentMove((int)obj, lbl_803DD438, ((GameObject *)obj)->anim.currentMoveProgress, 0);
            ((BaddieState *)ctx)->moveDone = 0;
        }
        q1 = ((BaddieState *)ctx)->animSpeedA * ((BaddieState *)ctx)->animSpeedA;
        q2 = ((BaddieState *)ctx)->animSpeedB * ((BaddieState *)ctx)->animSpeedB;
        mag = sqrtf(q1 + q2);
        if (ObjAnim_SampleRootCurvePhase(mag, (ObjAnimComponent *)obj, &tmp) != 0) {
            ((BaddieState *)ctx)->moveSpeed = tmp;
        }
        ratio = lbl_803E0570;
        if (ratio != mag) {
            ratio = ((BaddieState *)ctx)->animSpeedB / mag;
        }
        tmp = ratio;
        idx = (int)(lbl_803E05A0 * (f32)ratio);
        if (idx < 0) {
            idx = -idx;
        }
        if ((f32)idx > lbl_803E05A0) {
            idx = 0x4000;
        }
        if (((BaddieState *)ctx)->animSpeedB > lbl_803E0570) {
            Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent *)obj, moveB, idx);
        } else {
            Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent *)obj, moveA, idx);
        }
    }
}
#pragma opt_common_subs reset
typedef struct {
    u8 r;
    u8 g;
    u8 b;
    u8 a;
} HudColor;
extern u8 gDvdErrorPauseActive;
extern f32 lbl_803E0568;
extern void GXGetScissor(int *x, int *y, int *w, int *h);
extern void GXSetScissor(int x, int y, int w, int h);
extern void hudDrawRect(int x, int y, int w, int h, HudColor col);
extern void setHudOpacity(int op);
extern void screenRectFn_800d7568(int p1, int p2, int p3, u8 r, u8 g, u8 b);
#pragma opt_common_subs off
void screenTransition_do2(int p1, int p2, int p3) {
    int sx;
    int sy;
    int sw;
    int sh;
    HudColor col;
    if (lbl_803DD42E != 0) {
        lbl_803DD42E = lbl_803DD42E - 1;
        return;
    }
    if (lbl_803DD42F == 0 && lbl_803DD428 >= lbl_803E0568) {
        (*gScreenTransitionInterface)->step(0x1e, lbl_803DD42C);
        lbl_803DD428 = lbl_803E0560;
    }
    lbl_803DD420 = lbl_803DD424 * timeDelta + lbl_803DD420;
    if (lbl_803DD420 < lbl_803E0560) {
        lbl_803DD420 = lbl_803E0560;
        lbl_803DD42D = 1;
        if (lbl_803DD42C == 5) {
            setHudOpacity(0xff);
        }
        return;
    }
    if (lbl_803DD420 > lbl_803E0558) {
        lbl_803DD420 = lbl_803E0558;
        lbl_803DD42D = 1;
        if (lbl_803DD42F == 0) {
            lbl_803DD428 = lbl_803DD428 + timeDelta;
        }
        if (lbl_803DD42C != 5) {
            setHudOpacity(0xff);
        }
    } else {
        lbl_803DD42D = 0;
    }
    if (gDvdErrorPauseActive != 0) {
        return;
    }
    switch (lbl_803DD42C) {
    case 1:
        GXGetScissor(&sx, &sy, &sw, &sh);
        GXSetScissor(0, 0, 0x280, 0x1e0);
        col.b = 0;
        col.g = 0;
        col.r = 0;
        col.a = (int)lbl_803DD420;
        hudDrawRect(sx, sy, sw, sh, col);
        GXSetScissor(sx, sy, sw, sh);
        break;
    case 2:
        GXGetScissor(&sx, &sy, &sw, &sh);
        GXSetScissor(0, 0, 0x280, 0x1e0);
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = (int)lbl_803DD420;
        hudDrawRect(sx, sy, sw, sh, col);
        GXSetScissor(sx, sy, sw, sh);
        break;
    case 3:
        screenRectFn_800d7568(p1, p2, p3, 0xff, 0xff, 0xff);
        break;
    case 4:
        GXGetScissor(&sx, &sy, &sw, &sh);
        GXSetScissor(0, 0, 0x280, 0x1e0);
        col.r = 0xff;
        col.g = 0;
        col.b = 0;
        col.a = (int)lbl_803DD420;
        hudDrawRect(sx, sy, sw, sh, col);
        GXSetScissor(sx, sy, sw, sh);
        break;
    }
}
#pragma opt_common_subs reset

extern f32 lbl_803E0540;
extern f32 lbl_803E0544;
extern f32 lbl_803E0548;
extern void Camera_GetCurrentViewport(int *x1, int *y1, int *x2, int *y2);

void screenRectFn_800d7568(int p1, int p2, int p3, u8 r, u8 g, u8 b)
{
    int vx;
    int vy;
    int vr;
    int vb;
    int sx;
    int sy;
    int sw;
    int sh;
    HudColor col;
    uint uVar1, uVar3, uVar5, uVar7, uVar8, uVar9, uVar10, uVar11, uVar12, H;
    u8 step, a8;
    int iVar6;
    f32 conv;

    GXGetScissor(&sx, &sy, &sw, &sh);
    Camera_GetCurrentViewport(&vx, &vy, &vr, &vb);
    uVar5 = (vr - vx) & 0xffff;
    H = (vb - vy) & 0xffff;
    if (lbl_803DD420 > lbl_803E0540) {
        uVar12 = 0xff;
        uVar11 = (int)(lbl_803DD420 - lbl_803E0540);
    } else {
        uVar12 = (int)(lbl_803E0544 * lbl_803DD420);
        uVar11 = 0;
    }
    uVar1 = (uVar5 >> 1) & 0xffff;
    uVar11 = uVar11 & 0xffff;
    conv = (f32)(int)(uVar11 * uVar1);
    uVar7 = (uint)(int)(conv * lbl_803E0548) & 0xffff;
    if (uVar7 == uVar1) {
        int sh2;
        int sw2;
        int sy2;
        int sx2;
        HudColor col2;
        GXGetScissor(&sx2, &sy2, &sw2, &sh2);
        GXSetScissor(0, 0, 0x280, 0x1e0);
        col2.r = r;
        col2.g = b;
        col2.b = g;
        col2.a = (int)lbl_803DD420;
        hudDrawRect(sx2, sy2, sw2, sh2, col2);
        GXSetScissor(sx2, sy2, sw2, sh2);
    } else {
        uVar10 = (uVar1 - uVar7) & 0xffff;
        uVar8 = (uVar1 + uVar7) & 0xffff;
        uVar7 = ((uVar1 - 1) - uVar7) & 0xffff;
        GXSetScissor(vx, vy, vr - vx, vb - vy);
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = uVar12;
        hudDrawRect(vx + uVar7 + 1, vy, vx + uVar8, vb, col);
        step = (int)uVar10 / ((int)uVar1 / 6);
        if (step == 0) {
            step = 1;
        }
        a8 = uVar12;
        for (uVar9 = 0; uVar3 = uVar9 & 0xffff, (int)uVar3 < (int)(uVar10 - step); uVar9 += step) {
            col.r = 0xff;
            col.g = 0xff;
            col.b = 0xff;
            col.a = ((int)(a8 * (uVar1 - uVar3)) / (int)uVar1) & 0xff;
            iVar6 = vx + (uVar8 & 0xffff);
            hudDrawRect(iVar6, vy, step + iVar6, vb, col);
            iVar6 = vx + (uVar7 & 0xffff);
            hudDrawRect((iVar6 - step) + 1, vy, iVar6 + 1, vb, col);
            uVar8 += step;
            uVar7 -= step;
        }
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = ((int)(a8 * (uVar1 - uVar3)) / (int)uVar1) & 0xff;
        hudDrawRect(vx + (uVar8 & 0xffff), vy, vr, vb, col);
        hudDrawRect(vx, vy, vx + (uVar7 & 0xffff) + 1, vb, col);
        uVar7 = (H >> 1) & 0xffff;
        conv = (f32)(int)(uVar11 * uVar7);
        uVar11 = (uint)(int)(conv * lbl_803E0548) & 0xffff;
        uVar1 = (uVar7 - uVar11) & 0xffff;
        uVar10 = (uVar7 + uVar11) & 0xffff;
        uVar11 = ((uVar7 - 1) - uVar11) & 0xffff;
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = uVar12;
        hudDrawRect(vx, vy + uVar11 + 1, vr, vy + uVar10, col);
        step = (int)uVar1 / (int)(uVar7 >> 3);
        if (step == 0) {
            step = 1;
        }
        for (uVar12 = 0; uVar8 = uVar12 & 0xffff, (int)uVar8 < (int)(uVar1 - step); uVar12 += step) {
            col.r = 0xff;
            col.g = 0xff;
            col.b = 0xff;
            col.a = ((int)(a8 * (uVar7 - uVar8)) / (int)uVar7) & 0xff;
            iVar6 = vy + (uVar10 & 0xffff);
            hudDrawRect(vx, iVar6, vr, step + iVar6, col);
            iVar6 = vy + (uVar11 & 0xffff);
            hudDrawRect(vx, (iVar6 - step) + 1, vr, iVar6 + 1, col);
            uVar10 += step;
            uVar11 -= step;
        }
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = ((int)(a8 * (uVar7 - uVar8)) / (int)uVar7) & 0xff;
        hudDrawRect(vx, vy + (uVar10 & 0xffff), vr, vb, col);
        hudDrawRect(vx, vy, vr, vy + (uVar11 & 0xffff) + 1, col);
        GXSetScissor(sx, sy, sw, sh);
    }
}

extern f64 lbl_803E0520;
extern f32 lbl_803E051C;
extern f32 lbl_803E0528;
extern f32 lbl_803E052C;
extern f32 lbl_803E0530;
extern f32 lbl_803E0534;
extern f32 lbl_803E0538;

void Checkpoint_func06(int* obj, int* state, int filter)
{
    int stack[64];
    char visited[200];
    int cur;
    int slot;
    int k, count, i, j;
    char* cp;
    char* p;
    char* n;
    char* e;
    f32 cos1, sin1, cos2, sin2;
    f32 dist1, dist2, nx, nz, offs1, dz;
    f32 offs2, distA, distB, dx, dy, len, q, t0, sum, frac, b1, width;
    f32 px, py, pz, outX, outY;
    f32 ddx, ddy, ddz;

    count = 0;
    for (i = 0; i < (int)lbl_803DD410; i++) {
        visited[i] = 0;
    }
    cp = (char*)Checkpoint_find(*(int*)((char*)state + 0x10), &cur);
    if (cp != NULL) {
        stack[count++] = cur;
    } else {
        for (i = 0; i < (int)lbl_803DD410; i++) {
            e = (char*)lbl_8039C458[i].entry;
            if (visited[i] == 0 && (filter == -1 || *(s8*)(e + 0x28) == filter)) {
                ddx = *(f32*)(e + 8) - ((GameObject *)obj)->anim.localPosX;
                ddy = *(f32*)(e + 0xc) - ((GameObject *)obj)->anim.localPosY;
                ddz = *(f32*)(e + 0x10) - ((GameObject *)obj)->anim.localPosZ;
                if (ddz * ddz + (ddx * ddx + ddy * ddy) < lbl_803E051C) {
                    stack[count++] = i;
                    for (j = i; j < (int)lbl_803DD410; j++) {
                        if (filter == *(s8*)((char*)lbl_8039C458[j].entry + 0x28)) {
                            visited[j] = 1;
                        }
                    }
                }
            }
        }
    }
    for (i = 0; i < (int)lbl_803DD410; i++) {
        visited[i] = 0;
    }
    for (;;) {
        if (count > 0) {
            count--;
            cur = stack[count];
            cp = (char*)lbl_8039C458[cur].entry;
        } else {
            *(int*)((char*)state + 0x10) = -1;
            return;
        }
        if (cp == NULL) {
            return;
        }
        p = cp;
        for (k = 0; k < 2; k++) {
            n = (char*)Checkpoint_find(*(int*)(p + 0x20), &slot);
            if (n != NULL) {
                cos1 = mathSinf((lbl_803E04D8 * (f32)(*(u8*)(cp + 0x29) << 8)) / lbl_803E04DC);
                sin1 = mathCosf((lbl_803E04D8 * (f32)(*(u8*)(cp + 0x29) << 8)) / lbl_803E04DC);
                offs1 = -(*(f32*)(cp + 8) * cos1 + *(f32*)(cp + 0x10) * sin1);
                cos2 = mathSinf((lbl_803E04D8 * (f32)(*(u8*)(n + 0x29) << 8)) / lbl_803E04DC);
                sin2 = mathCosf((lbl_803E04D8 * (f32)(*(u8*)(n + 0x29) << 8)) / lbl_803E04DC);
                offs2 = -(*(f32*)(n + 8) * cos2 + *(f32*)(n + 0x10) * sin2);
                dist1 = offs1 + (cos1 * ((GameObject *)obj)->anim.localPosX + sin1 * ((GameObject *)obj)->anim.localPosZ);
                dist2 = offs2 + (cos2 * ((GameObject *)obj)->anim.localPosX + sin2 * ((GameObject *)obj)->anim.localPosZ);
                distA = offs1 + (cos1 * *(f32*)(n + 8) + sin1 * *(f32*)(n + 0x10));
                distB = offs2 + (cos2 * *(f32*)(cp + 8) + sin2 * *(f32*)(cp + 0x10));
                if (((distA <= lbl_803E04E8 && dist1 <= lbl_803E04E8) || (distA > lbl_803E04E8 && dist1 > lbl_803E04E8)) &&
                    ((distB <= lbl_803E04E8 && dist2 <= lbl_803E04E8) || (distB > lbl_803E04E8 && dist2 > lbl_803E04E8))) {
                    dx = *(f32*)(cp + 8) - *(f32*)(n + 8);
                    dy = *(f32*)(cp + 0xc) - *(f32*)(n + 0xc);
                    dz = *(f32*)(cp + 0x10) - *(f32*)(n + 0x10);
                    len = sqrtf(dz * dz + (dx * dx + dy * dy));
                    if (len > lbl_803E0520) {
                        q = lbl_803E0504 / len;
                        nx = dx * q;
                        nz = dz * q;
                    }
                    q = cos1 * nx + sin1 * nz;
                    t0 = -dist1 / q;
                    sum = t0 + dist2 / (cos2 * nx + sin2 * nz);
                    if (sum > lbl_803E0528 || sum < lbl_803E052C) {
                        frac = t0 / sum;
                    } else {
                        frac = lbl_803E04E8;
                    }
                    if (frac < lbl_803E04E8) {
                        frac = lbl_803E04E8;
                    }
                    if (frac >= lbl_803E0518) {
                        frac = lbl_803E0518;
                    }
                    b1 = (f32)*(u8*)(cp + 0x2a);
                    width = frac * ((f32)*(u8*)(n + 0x2a) - b1) + b1;
                    px = -(dx * frac - *(f32*)(cp + 8));
                    py = -(dy * frac - *(f32*)(cp + 0xc));
                    pz = -(dz * frac - *(f32*)(cp + 0x10));
                    outY = (((GameObject *)obj)->anim.localPosY - py) / width;
                    outX = (-(px * nz - pz * nx) + (((GameObject *)obj)->anim.localPosX * nz - ((GameObject *)obj)->anim.localPosZ * nx)) / width;
                    if (outX < lbl_803E0530 || outX > lbl_803E0534 || outY < lbl_803E0538 || outY > lbl_803E0534) {
                    } else {
                        *(int*)((char*)state + 0x10) = *(int*)(cp + 0x14);
                        *(int *)&((BaddieState *)state)->posX = *(int*)(cp + 0x14);
                        *(f32*)((char*)state + 0) = outX;
                        *(f32*)((char*)state + 4) = outY;
                        *(f32*)((char*)state + 8) = frac;
                        *(s16*)((char*)state + 0x20) = *(s8*)(cp + 0x28);
                        return;
                    }
                }
            }
            p += 4;
        }
        if (visited[cur] == 0) {
            p = cp + 4;
            for (k = 1; k >= 0; k--) {
                n = (char*)Checkpoint_find(*(int*)(p + 0x18), &slot);
                if (n != NULL && visited[slot] == 0 && count < 0x3c) {
                    stack[count++] = slot;
                }
                n = (char*)Checkpoint_find(*(int*)(p + 0x20), &slot);
                if (n != NULL && visited[slot] == 0 && count < 0x3c) {
                    stack[count++] = slot;
                }
                p -= 4;
            }
            visited[cur] = 1;
        }
    }
}
