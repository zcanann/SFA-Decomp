#include "main/game_object.h"
#include "main/screen_transition.h"

extern undefined4 DAT_803de0af;

void FUN_800d7780(undefined param_1)
{
    DAT_803de0af = param_1;
    return;
}

void Checkpoint_release(void);

extern u8 lbl_803DD42D;
u8 screenTransition_func07(void) { return lbl_803DD42D; }


extern f32 screenTransitionAlpha;
f32 screenTransition_getAlpha(void) { return screenTransitionAlpha; }

int Dummy04_func03_ret_m1(void);

extern u8 screenTransitionPause;
#pragma peephole off
void setScreenTransitionPause(u32 pause) { screenTransitionPause = (u8)pause; }
#pragma peephole reset

extern f32 lbl_803E0558;
u32 isScreenTransitionActive(void) { return lbl_803E0558 == screenTransitionAlpha; }

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

extern f32 timeDelta;

#pragma scheduling off
#pragma peephole off

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
/* p1/p2/p3 are only forwarded to screenRectFn_800d7568 (case 3); the signature is required for the calling convention. */
void screenTransition_do2(int p1, int p2, int p3)
{
    if (lbl_803DD42E != 0)
    {
        lbl_803DD42E--;
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
    {
        HudColor col;
        int sh;
        int sw;
        int sy;
        int sx;
        GXGetScissor(&sx, &sy, &sw, &sh);
        GXSetScissor(0, 0, 0x280, 0x1e0);
        col.b = 0;
        col.g = 0;
        col.r = 0;
        col.a = screenTransitionAlpha;
        hudDrawRect(sx, sy, sw, sh, col);
        GXSetScissor(sx, sy, sw, sh);
        break;
    }
    case 2:
    {
        HudColor col;
        int sh;
        int sw;
        int sy;
        int sx;
        GXGetScissor(&sx, &sy, &sw, &sh);
        GXSetScissor(0, 0, 0x280, 0x1e0);
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = screenTransitionAlpha;
        hudDrawRect(sx, sy, sw, sh, col);
        GXSetScissor(sx, sy, sw, sh);
        break;
    }
    case 3:
        screenRectFn_800d7568(p1, p2, p3, 0xff, 0xff, 0xff);
        break;
    case 4:
    {
        HudColor col;
        int sh;
        int sw;
        int sy;
        int sx;
        GXGetScissor(&sx, &sy, &sw, &sh);
        GXSetScissor(0, 0, 0x280, 0x1e0);
        col.r = 0xff;
        col.g = 0;
        col.b = 0;
        col.a = screenTransitionAlpha;
        hudDrawRect(sx, sy, sw, sh, col);
        GXSetScissor(sx, sy, sw, sh);
        break;
    }
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
    uint halfSpan;
    uint cur;
    uint span;
    uint edge;
    uint hiEdge;
    uint hStep;
    uint loEdge;
    uint inset;
    uint maxAlpha;
    uint H;
    u8 step;
    u8 fadeAlpha;
    int screenX;
    f32 conv;

    GXGetScissor(&sx, &sy, &sw, &sh);
    Camera_GetCurrentViewport(&vx, &vy, &vr, &vb);
    span = (vr - vx) & 0xffff;
    H = (vb - vy) & 0xffff;
    if (screenTransitionAlpha > lbl_803E0540)
    {
        maxAlpha = 0xff;
        inset = (int)(screenTransitionAlpha - lbl_803E0540);
    }
    else
    {
        maxAlpha = (int)(lbl_803E0544 * screenTransitionAlpha);
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
        col2.a = screenTransitionAlpha;
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
        col.a = maxAlpha;
        hudDrawRect(vx + edge + 1, vy, vx + hiEdge, vb, col);
        step = (int)loEdge / ((int)halfSpan / 6);
        if (step == 0)
        {
            step = 1;
        }
        fadeAlpha = maxAlpha;
        for (hStep = 0; cur = hStep & 0xffff, (int)cur < (int)(loEdge - step); hStep += step)
        {
            col.r = 0xff;
            col.g = 0xff;
            col.b = 0xff;
            col.a = ((int)(fadeAlpha * (halfSpan - cur)) / (int)halfSpan) & 0xff;
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
        col.a = ((int)(fadeAlpha * (halfSpan - cur)) / (int)halfSpan) & 0xff;
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
        col.a = maxAlpha;
        hudDrawRect(vx, vy + inset + 1, vr, vy + loEdge, col);
        step = (int)halfSpan / (int)(edge >> 3);
        if (step == 0)
        {
            step = 1;
        }
        for (maxAlpha = 0; hiEdge = maxAlpha & 0xffff, (int)hiEdge < (int)(halfSpan - step); maxAlpha += step)
        {
            col.r = 0xff;
            col.g = 0xff;
            col.b = 0xff;
            col.a = ((int)(fadeAlpha * (edge - hiEdge)) / (int)edge) & 0xff;
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
        col.a = ((int)(fadeAlpha * (edge - hiEdge)) / (int)edge) & 0xff;
        hudDrawRect(vx, vy + (loEdge & 0xffff), vr, vb, col);
        hudDrawRect(vx, vy, vr, vy + (inset & 0xffff) + 1, col);
        GXSetScissor(sx, sy, sw, sh);
    }
}

#pragma peephole reset
#pragma scheduling reset
