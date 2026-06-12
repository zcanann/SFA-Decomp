#include "main/dll/df_partfx.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/resource.h"
#include "main/screen_transition.h"


extern ScreenTransitionInterface** gScreenTransitionInterface;
extern EffectInterface** gPartfxInterface;
extern undefined4 DAT_803de0af;

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
extern int getAngle(f32 dx, f32 dz);
extern f32 sqrtf(f32 x);

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
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
void Checkpoint_release(void);

void Dummy04_func14_nop(void);

void Dummy04_func26_nop(void);

void Dummy04_func25_nop(void);

void Dummy04_func23_nop(void);

void Dummy04_func20_nop(void);

void Dummy04_func1F_nop(void);

void Dummy04_func1E_nop(void);

void Dummy04_func1C_nop(void);

void Dummy04_func1B_nop(void);

void Dummy04_func1A_nop(void);

void Dummy04_func19_nop(void);

void Dummy04_func18_nop(void);

void Dummy04_func17_nop(void);

void Dummy04_func16_nop(void);

void Dummy04_onSetupPlayer(void);

void Dummy04_func15_nop(void);

void Dummy04_func13_nop(void);

void Dummy04_func12_nop(void);

void Dummy04_func10_nop(void);

void Dummy04_func0E_nop(void);

void Dummy04_func0C_nop(void);

void Dummy04_onSelectSave(void);

void Dummy04_func08_nop(void);

void Dummy04_func07_nop(void);

void Dummy04_func04_nop(void);

void Dummy04_release(void);

void Dummy04_initialise(void);

void dll_0F_func19_nop(void);

/* 8b "li r3, N; blr" returners. */
int Dummy04_func24_ret_0(void);
int Dummy04_func22_ret_127(void);
int Dummy04_func21_ret_0(void);
int Dummy04_func1D_ret_0(void);
int Dummy04_func11_ret_0(void);
int Dummy04_func0F_ret_0(void);
int Dummy04_func0D_ret_0(void);
int Dummy04_func0B_ret_0(void);
int Dummy04_func0A_ret_0(void);
int Dummy04_func05_ret_0(void);

/* sda21 accessors. */
extern u8 lbl_803DD42D;
u8 screenTransition_func07(void) { return lbl_803DD42D; }

/* Pattern wrappers. */
extern u32 lbl_803DD410;

/* 12b 3-insn patterns. */
extern u32 lbl_803DD43C;
extern u32 lbl_803DD438;

void player_setAnimIds(int unused1, int unused2, u32 a, u32 b);

/* misc 8b leaves */
extern f32 screenTransitionAlpha;
f32 screenTransition_getAlpha(void) { return screenTransitionAlpha; }

/* Pattern wrappers. */
int Dummy04_func03_ret_m1(void);

/* sda21 writers. */
extern u8 screenTransitionPause;
#pragma peephole off
void setScreenTransitionPause(u32 pause) { screenTransitionPause = (u8)pause; }
#pragma peephole reset

/* fcmp-eq-to-bool. */
extern f32 lbl_803E0558;
u32 isScreenTransitionActive(void) { return lbl_803E0558 == screenTransitionAlpha; }

/* multi-store leaf (single float broadcast). */
extern f32 lbl_803E0570;

void player_clearXZvel(int* obj, int* state);

/* Checkpoint table initialiser. */
extern u32 lbl_8039CA98[];
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
void player_playSoundFn0F(int* obj, int* state, int bit, int idx, int* sfxTable);

void player_playSoundFn10(int* obj, int* state, int bit, int idx, int* sfxTable);

void player_render2(s16* obj, int* state, f32 f1, f32 f2);

void player_modelMtxFn(f32* mtx, int* state, f32 f1, f32 f2);

void player_findCurve(int* obj, int* state, int p3);

void screenTransitionFn_800d7b04(int duration, int type)
{
    screenTransitionAlpha = lbl_803E0558;
    lbl_803DD424 = lbl_803E0564 / (f32)duration;
    lbl_803DD428 = lbl_803E0560;
    lbl_803DD42C = (u8)type;
    lbl_803DD42E = 5;
}

void screenTransition_fadeFrom(int duration, int type, f32 from)
{
    screenTransitionAlpha = lbl_803E0558 * from;
    lbl_803DD424 = -(lbl_803E055C * from) / (f32)duration;
    lbl_803DD428 = lbl_803E0560;
    lbl_803DD42C = (u8)type;
    lbl_803DD42E = 1;
}

#pragma opt_common_subs off
void screenTransition_screenFade(int duration, int type)
{
    if (lbl_803DD424 >= lbl_803E0560 || lbl_803E0560 == screenTransitionAlpha)
    {
        screenTransitionAlpha = lbl_803E0558;
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
    if (lbl_803DD424 <= lbl_803E0560 || lbl_803E0558 == screenTransitionAlpha)
    {
        screenTransitionAlpha = lbl_803E0560;
    }
    lbl_803DD424 = lbl_803E055C / (f32)duration;
    lbl_803DD428 = lbl_803E0560;
    lbl_803DD42C = (u8)type;
    lbl_803DD42E = 0;
}
#pragma opt_common_subs reset

void dll_0F_func0B(int* obj, int* state, f32 f1, f32 f2, f32 f3);

void player_updateCurve(int* obj, int* state, f32 t);
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
void player_followCurve(int* obj, int* state, f32 cx, f32 cz, f32 t, int p5);
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
void dll_0F_func13(s16* obj, int* state, int angle, f32 t, f32 scale);
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
void Checkpoint_initialise(void);
#pragma scheduling reset

/* Checkpoint_Add: sorted insertion of (entry->_14 as key, entry as pointer) into lbl_8039C458 table. */

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
void player_updateParticles(int* p1, int p2, int p3, int count, int mode);

#pragma scheduling reset

#pragma scheduling off
void player_doProjGfx(int* p1, int p2, int p3, int count, int p5, int mode);
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void Checkpoint_remove(int* obj);
#pragma opt_common_subs reset
extern f32 timeDelta;
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void player_rotateTowardEnemy(int* obj, int* ctx, int spd);
#pragma opt_common_subs reset
extern f32 lbl_803E058C;
extern void setMatrixFromObjectPos(f32* mtx, void* desc);
extern void Matrix_TransformPoint(f32* mtx, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern void objMove(int* obj, f32 vx, f32 vy, f32 vz);

struct PartDesc
{
    s16 ang[3];
    f32 sc[4];
};
#pragma scheduling off
#pragma peephole off
void player_applyVelocityStep(int* p, int* ctx, f32 t);

extern f32 lbl_803E0590;
extern f32 lbl_803E0594;
extern s16 lbl_803DD44C;
#pragma scheduling off
#pragma peephole off
void fn_800D8414(int* obj, int* ctx);
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void player_getExtraSize(int* a, int* ctx, f32 px, f32 pz, f32 lo, f32 hi, f32 spd);
#pragma opt_common_subs reset
extern f32 lbl_803E05A0;
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void player_animFn16(int* obj, int* ctx, int moveA, int moveB);
#pragma opt_common_subs reset
typedef struct
{
    u8 r;
    u8 g;
    u8 b;
    u8 a;
} HudColor;

extern u8 gDvdErrorPauseActive;
extern f32 lbl_803E0568;
extern void GXGetScissor(int* x, int* y, int* w, int* h);
extern void GXSetScissor(int x, int y, int w, int h);
extern void hudDrawRect(int x, int y, int w, int h, HudColor col);
extern void setHudOpacity(int op);
extern void screenRectFn_800d7568(int p1, int p2, int p3, u8 r, u8 g, u8 b);
#pragma opt_common_subs off
void screenTransition_do2(int p1, int p2, int p3)
{
    int sx;
    int sy;
    int sw;
    int sh;
    HudColor col;
    if (lbl_803DD42E != 0)
    {
        lbl_803DD42E = lbl_803DD42E - 1;
        return;
    }
    if (screenTransitionPause == 0 && lbl_803DD428 >= lbl_803E0568)
    {
        (*gScreenTransitionInterface)->step(0x1e, lbl_803DD42C);
        lbl_803DD428 = lbl_803E0560;
    }
    screenTransitionAlpha = lbl_803DD424 * timeDelta + screenTransitionAlpha;
    if (screenTransitionAlpha < lbl_803E0560)
    {
        screenTransitionAlpha = lbl_803E0560;
        lbl_803DD42D = 1;
        if (lbl_803DD42C == 5)
        {
            setHudOpacity(0xff);
        }
        return;
    }
    if (screenTransitionAlpha > lbl_803E0558)
    {
        screenTransitionAlpha = lbl_803E0558;
        lbl_803DD42D = 1;
        if (screenTransitionPause == 0)
        {
            lbl_803DD428 = lbl_803DD428 + timeDelta;
        }
        if (lbl_803DD42C != 5)
        {
            setHudOpacity(0xff);
        }
    }
    else
    {
        lbl_803DD42D = 0;
    }
    if (gDvdErrorPauseActive != 0)
    {
        return;
    }
    switch (lbl_803DD42C)
    {
    case 1:
        GXGetScissor(&sx, &sy, &sw, &sh);
        GXSetScissor(0, 0, 0x280, 0x1e0);
        col.b = 0;
        col.g = 0;
        col.r = 0;
        col.a = (int)screenTransitionAlpha;
        hudDrawRect(sx, sy, sw, sh, col);
        GXSetScissor(sx, sy, sw, sh);
        break;
    case 2:
        GXGetScissor(&sx, &sy, &sw, &sh);
        GXSetScissor(0, 0, 0x280, 0x1e0);
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = (int)screenTransitionAlpha;
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
        col.a = (int)screenTransitionAlpha;
        hudDrawRect(sx, sy, sw, sh, col);
        GXSetScissor(sx, sy, sw, sh);
        break;
    }
}
#pragma opt_common_subs reset

extern f32 lbl_803E0540;
extern f32 lbl_803E0544;
extern f32 lbl_803E0548;
extern void Camera_GetCurrentViewport(int* x1, int* y1, int* x2, int* y2);

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
    uint halfSpan, cur, span, edge, hiEdge, step1, loEdge, inset, step0, H;
    u8 step, a8;
    int screenX;
    f32 conv;

    GXGetScissor(&sx, &sy, &sw, &sh);
    Camera_GetCurrentViewport(&vx, &vy, &vr, &vb);
    span = (vr - vx) & 0xffff;
    H = (vb - vy) & 0xffff;
    if (screenTransitionAlpha > lbl_803E0540)
    {
        step0 = 0xff;
        inset = (int)(screenTransitionAlpha - lbl_803E0540);
    }
    else
    {
        step0 = (int)(lbl_803E0544 * screenTransitionAlpha);
        inset = 0;
    }
    halfSpan = (span >> 1) & 0xffff;
    inset = inset & 0xffff;
    conv = (f32)(int)(inset * halfSpan);
    edge = (uint)(int)(conv * lbl_803E0548) & 0xffff;
    if (edge == halfSpan)
    {
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
        col2.a = (int)screenTransitionAlpha;
        hudDrawRect(sx2, sy2, sw2, sh2, col2);
        GXSetScissor(sx2, sy2, sw2, sh2);
    }
    else
    {
        loEdge = (halfSpan - edge) & 0xffff;
        hiEdge = (halfSpan + edge) & 0xffff;
        edge = ((halfSpan - 1) - edge) & 0xffff;
        GXSetScissor(vx, vy, vr - vx, vb - vy);
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = step0;
        hudDrawRect(vx + edge + 1, vy, vx + hiEdge, vb, col);
        step = (int)loEdge / ((int)halfSpan / 6);
        if (step == 0)
        {
            step = 1;
        }
        a8 = step0;
        for (step1 = 0; cur = step1 & 0xffff, (int)cur < (int)(loEdge - step); step1 += step)
        {
            col.r = 0xff;
            col.g = 0xff;
            col.b = 0xff;
            col.a = ((int)(a8 * (halfSpan - cur)) / (int)halfSpan) & 0xff;
            screenX = vx + (hiEdge & 0xffff);
            hudDrawRect(screenX, vy, step + screenX, vb, col);
            screenX = vx + (edge & 0xffff);
            hudDrawRect((screenX - step) + 1, vy, screenX + 1, vb, col);
            hiEdge += step;
            edge -= step;
        }
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = ((int)(a8 * (halfSpan - cur)) / (int)halfSpan) & 0xff;
        hudDrawRect(vx + (hiEdge & 0xffff), vy, vr, vb, col);
        hudDrawRect(vx, vy, vx + (edge & 0xffff) + 1, vb, col);
        edge = (H >> 1) & 0xffff;
        conv = (f32)(int)(inset * edge);
        inset = (uint)(int)(conv * lbl_803E0548) & 0xffff;
        halfSpan = (edge - inset) & 0xffff;
        loEdge = (edge + inset) & 0xffff;
        inset = ((edge - 1) - inset) & 0xffff;
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = step0;
        hudDrawRect(vx, vy + inset + 1, vr, vy + loEdge, col);
        step = (int)halfSpan / (int)(edge >> 3);
        if (step == 0)
        {
            step = 1;
        }
        for (step0 = 0; hiEdge = step0 & 0xffff, (int)hiEdge < (int)(halfSpan - step); step0 += step)
        {
            col.r = 0xff;
            col.g = 0xff;
            col.b = 0xff;
            col.a = ((int)(a8 * (edge - hiEdge)) / (int)edge) & 0xff;
            screenX = vy + (loEdge & 0xffff);
            hudDrawRect(vx, screenX, vr, step + screenX, col);
            screenX = vy + (inset & 0xffff);
            hudDrawRect(vx, (screenX - step) + 1, vr, screenX + 1, col);
            loEdge += step;
            inset -= step;
        }
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = ((int)(a8 * (edge - hiEdge)) / (int)edge) & 0xff;
        hudDrawRect(vx, vy + (loEdge & 0xffff), vr, vb, col);
        hudDrawRect(vx, vy, vr, vy + (inset & 0xffff) + 1, col);
        GXSetScissor(sx, sy, sw, sh);
    }
}

extern f64 lbl_803E0520;


/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

/* === moved from main/dll/objfsa.c [800D8F90-800D9DCC) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/baddie_state.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/game_object.h"
#include "main/objanim.h"


/* RomCurveWalker now lives in main/dll/curve_walker.h (lifted per the
 * deref-cleanup wave; curves.h re-exports it). */














static inline u8 Objfsa_IsWalkGroupActive(int groupIndex);




/*
 * --INFO--
 *
 * Function: player_setScale
 * EN v1.0 Address: 0x800D8F90
 * EN v1.0 Size: 256b
 * EN v1.1 Address: 0x800D8FE0
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 lbl_803DD440;

typedef struct PlayerMoveBuf
{
    f32 a;
    f32 b;
    f32 c;
    u8 padC[2];
    s16 angleDelta;
    u8 pad10[2];
    u8 flag;
    s8 ids[8];
    s8 count;
} PlayerMoveBuf;

#pragma scheduling off
#pragma peephole off
void player_setScale(f32 dt, short* moveState, uint* obj, uint flags);

/*
 * --INFO--
 *
 * Function: FUN_800d9090
 * EN v1.0 Address: 0x800D9090
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x800D9108
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_800d9de0
 * EN v1.0 Address: 0x800D9DE0
 * EN v1.0 Size: 1972b
 * EN v1.1 Address: 0x800DA4C8
 * EN v1.1 Size: 1772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800d9de0(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4, undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, float* param_9, float param_10, undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14, undefined4 param_15, undefined4 param_16);

/*
 * --INFO--
 *
 * Function: FUN_800da594
 * EN v1.0 Address: 0x800DA594
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x800DABB4
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_800da5e8
 * EN v1.0 Address: 0x800DA5E8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800DAC0C
 * EN v1.1 Size: 1628b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_800da700
 * EN v1.0 Address: 0x800DA700
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x800DB36C
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_800da850
 * EN v1.0 Address: 0x800DA850
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x800DB4B0
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_800db110
 * EN v1.0 Address: 0x800DB110
 * EN v1.0 Size: 480b
 * EN v1.1 Address: 0x800DBCD8
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_800db47c
 * EN v1.0 Address: 0x800DB47C
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x800DBF88
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_800db690
 * EN v1.0 Address: 0x800DB690
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x800DC158
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_800db820
 * EN v1.0 Address: 0x800DB820
 * EN v1.0 Size: 1096b
 * EN v1.1 Address: 0x800DC27C
 * EN v1.1 Size: 936b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_800dd3e4
 * EN v1.0 Address: 0x800DD3E4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800DD8CC
 * EN v1.1 Size: 2208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_800dd62c
 * EN v1.0 Address: 0x800DD62C
 * EN v1.0 Size: 2048b
 * EN v1.1 Address: 0x800DE41C
 * EN v1.1 Size: 1880b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_800ddf84
 * EN v1.0 Address: 0x800DDF84
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800DED20
 * EN v1.1 Size: 956b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_800ddf8c
 * EN v1.0 Address: 0x800DDF8C
 * EN v1.0 Size: 2572b
 * EN v1.1 Address: 0x800DF0DC
 * EN v1.1 Size: 2428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_800de998
 * EN v1.0 Address: 0x800DE998
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800DFA58
 * EN v1.1 Size: 2400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: curves_findNearObj
 * EN v1.0 Address: 0x800E0134
 * EN v1.0 Size: 696b
 * EN v1.1 Address: 0x800E03B8
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off

/*
 * --INFO--
 *
 * Function: FUN_800dece0
 * EN v1.0 Address: 0x800DECE0
 * EN v1.0 Size: 1476b
 * EN v1.1 Address: 0x800E0670
 * EN v1.1 Size: 1572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on



/*
 * --INFO--
 *
 * Function: curves_lengthFn24
 * EN v1.0 Address: 0x800E0E18
 * EN v1.0 Size: 1888b
 * EN v1.1 Address: 0x800E109C
 * EN v1.1 Size: 1888b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off

/*
 * --INFO--
 *
 * Function: curves_getPos
 * EN v1.0 Address: 0x800E1578
 * EN v1.0 Size: 592b
 * EN v1.1 Address: 0x800E17FC
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: walkGroupFn_800db3e4
 * EN v1.0 Address: 0x800DB3E4
 * EN v1.0 Size: 1268b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: isPointWithinPatchGroup
 * EN v1.0 Address: 0x800DB8D8
 * EN v1.0 Size: 372b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: getPatchGroup
 * EN v1.0 Address: 0x800DBA4C
 * EN v1.0 Size: 344b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: isInWalkGroupOrPatch
 * EN v1.0 Address: 0x800DBBA4
 * EN v1.0 Size: 344b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole on

/*
 * --INFO--
 *
 * Function: Objfsa_GetWalkGroupIndexAtPoint
 * EN v1.0 Address: 0x800DBCFC
 * EN v1.0 Size: 464b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off

/*
 * --INFO--
 *
 * Function: Objfsa_GetPatchGroupIdAtPoint
 * EN v1.0 Address: 0x800DBECC
 * EN v1.0 Size: 292b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: mathFn_800dbff0
 * EN v1.0 Address: 0x800DBFF0
 * EN v1.0 Size: 936b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: RomCurve_findProjectedCurveFromStart
 * EN v1.0 Address: 0x800DFE64
 * EN v1.0 Size: 720b
 * EN v1.1 Address: 0x800E1A4C
 * EN v1.1 Size: 860b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling on
#pragma peephole on
void player_release(void);

void player_initialise(void);













/* 8b "li r3, N; blr" returners. */

/* sda21 accessors. */
extern u32 playerOverride;
void player_setOverride(u32 x);

/* Pattern wrappers. */

/* player_init: memset constructor */
extern void* memset(void* dst, int val, u32 n);
extern f32 lbl_803E05BC;
#pragma scheduling off
#pragma peephole off
void player_init(int unused, void* obj, int a, int b);

/* fn_800D9F38 ? large init updating multiple float fields based on b's bytes */

int fn_800D9F38(void* a, void* b);

/* player_updateVel */
extern u8 lbl_803DD44E;
extern u8 lbl_803DD44F;
extern u8 lbl_803DD450;
extern f64 lbl_803E0598;
extern f32 lbl_803E05C0;
extern f32 lbl_803E05C4;
extern f32 lbl_803DD444;
extern f32 lbl_803DD448;
extern void fn_800D915C(int pos, int* obj, void* fnTable, f32 fval);
extern void setMatrixFromObjectPos(f32* matrix, void* objpos);
extern void Matrix_TransformPoint(f32* matrix, f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ);
extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);

void playerRunStateMachine(char* pos, char* state, float dt, int stateFns);

void player_update(char* pos, char* state, float dt, float pathDt, int stateFns, int auxStateFns);

void player_updateVel(char* p, char* obj, int unused);


/* RomCurve_setA4: similar to fn_800D9F38 branch2 with different consts */
extern f32 lbl_803E0610;

void RomCurve_setA4(void* a, void* b);







#pragma scheduling on
#pragma peephole on




#pragma scheduling off
#pragma peephole off










/* RomCurve_stepClamped: keep the curve phase just inside the endpoints, then advance it. */
#pragma peephole on



#pragma peephole off

#pragma peephole on


#pragma peephole off













/* UIController dispatch through the shared GameUI interface. */
#pragma scheduling on
#pragma peephole on

#pragma scheduling off
#pragma peephole off

/* player_setState */
void player_setState(void* ctx, void* p, int new_state);

/* walkPath_writeU16LE: split a path id into two little-endian bytes. */
void walkPath_writeU16LE(u32 v, u8* dst);

/* fn_800D9EE8: triple xor swap of 0x9c/0xa4, clamp *p */
#pragma scheduling on


#pragma scheduling off

void fn_800D915C(int p1, int* obj, void* fnTable, f32 fval);
