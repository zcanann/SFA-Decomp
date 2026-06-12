#include "main/dll/df_partfx.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/resource.h"
#include "main/screen_transition.h"

extern ScreenTransitionInterface** gScreenTransitionInterface;
extern undefined4 DAT_803de0af;


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

/* 8b "li r3, N; blr" returners. */

/* sda21 accessors. */
extern u8 lbl_803DD42D;
u8 screenTransition_func07(void) { return lbl_803DD42D; }

/* Pattern wrappers. */
extern u32 lbl_803DD410;

/* 12b 3-insn patterns. */

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

/* Checkpoint table initialiser. */
extern f32 lbl_803E0564;
extern f32 lbl_803E0560;
extern f32 lbl_803E055C;
extern f32 lbl_803DD424;
extern f32 lbl_803DD428;
extern u8 lbl_803DD42C;
extern u8 lbl_803DD42E;

#pragma scheduling off
#pragma peephole off

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

#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset
extern f32 timeDelta;
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset

#pragma scheduling off
#pragma peephole off

#pragma scheduling off
#pragma peephole off
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
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

#pragma scheduling off
#pragma peephole off

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

/* 8b "li r3, N; blr" returners. */

/* sda21 accessors. */

/* Pattern wrappers. */

/* player_init: memset constructor */
#pragma scheduling off
#pragma peephole off

/* fn_800D9F38 ? large init updating multiple float fields based on b's bytes */

/* player_updateVel */

/* RomCurve_setA4: similar to fn_800D9F38 branch2 with different consts */

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

/* walkPath_writeU16LE: split a path id into two little-endian bytes. */

/* fn_800D9EE8: triple xor swap of 0x9c/0xa4, clamp *p */
#pragma scheduling on

#pragma scheduling off

