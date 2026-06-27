#include "main/game_object.h"
#include "main/screen_transition.h"
#include "dolphin/gx/GXCull.h"
#include "main/dll/dll_0016_screentransition.h"
extern u32 DAT_803de0af;

void FUN_800d7780(u8 value)
{
    DAT_803de0af = value;
    return;
}

void Checkpoint_release(void);

extern u8 gScreenTransitionDone;
u8 screenTransition_func07(void) { return gScreenTransitionDone; }

extern f32 screenTransitionAlpha;
f32 screenTransition_getAlpha(void) { return screenTransitionAlpha; }

int Dummy04_func03_ret_m1(void);

extern u8 screenTransitionPause;
#pragma peephole off
void setScreenTransitionPause(u32 pause) { screenTransitionPause = pause; }
#pragma peephole reset

extern f32 gScreenTransitionAlphaMax;
u32 isScreenTransitionActive(void) { return gScreenTransitionAlphaMax == screenTransitionAlpha; }

extern f32 lbl_803E0564;
extern f32 lbl_803E0560;
extern f32 lbl_803E055C;
extern f32 gScreenTransitionAlphaStep;
extern f32 gScreenTransitionHoldTimer;
extern u8 gScreenTransitionType;
extern u8 gScreenTransitionDelay;

#pragma scheduling off
#pragma peephole off

void screenTransitionFn_800d7b04(int duration, int type)
{
    screenTransitionAlpha = gScreenTransitionAlphaMax;
    gScreenTransitionAlphaStep = lbl_803E0564 / duration;
    gScreenTransitionHoldTimer = lbl_803E0560;
    gScreenTransitionType = type;
    gScreenTransitionDelay = 5;
}

void screenTransition_fadeFrom(int duration, int type, f32 from)
{
    screenTransitionAlpha = gScreenTransitionAlphaMax * from;
    gScreenTransitionAlphaStep = -(lbl_803E055C * from) / duration;
    gScreenTransitionHoldTimer = lbl_803E0560;
    gScreenTransitionType = type;
    gScreenTransitionDelay = 1;
}

#pragma opt_common_subs off
void screenTransition_screenFade(int duration, int type)
{
    if (gScreenTransitionAlphaStep >= lbl_803E0560 || lbl_803E0560 == screenTransitionAlpha)
    {
        screenTransitionAlpha = gScreenTransitionAlphaMax;
    }
    gScreenTransitionAlphaStep = lbl_803E0564 / duration;
    gScreenTransitionHoldTimer = lbl_803E0560;
    gScreenTransitionType = type;
    gScreenTransitionDelay = 1;
}
#pragma opt_common_subs reset

#pragma opt_common_subs off
void screenTransition_Do(int duration, int type)
{
    if (gScreenTransitionAlphaStep <= lbl_803E0560 || gScreenTransitionAlphaMax == screenTransitionAlpha)
    {
        screenTransitionAlpha = lbl_803E0560;
    }
    gScreenTransitionAlphaStep = lbl_803E055C / duration;
    gScreenTransitionHoldTimer = lbl_803E0560;
    gScreenTransitionType = type;
    gScreenTransitionDelay = 0;
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
extern f32 gScreenTransitionHoldDuration;
extern void GXGetScissor(int* x, int* y, int* w, int* h);
extern void hudDrawRect(int x, int y, int w, int h, HudColor col);
extern void setHudOpacity(int op);

#pragma opt_common_subs off
void screenTransition_do2(int p1, int p2, int p3)
{
    if (gScreenTransitionDelay != 0)
    {
        gScreenTransitionDelay--;
        return;
    }
    if (screenTransitionPause == 0 && gScreenTransitionHoldTimer >= gScreenTransitionHoldDuration)
    {
        (*gScreenTransitionInterface)->step(0x1e, gScreenTransitionType);
        gScreenTransitionHoldTimer = lbl_803E0560;
    }
    screenTransitionAlpha = gScreenTransitionAlphaStep * timeDelta + screenTransitionAlpha;
    if (screenTransitionAlpha < lbl_803E0560)
    {
        screenTransitionAlpha = lbl_803E0560;
        gScreenTransitionDone = 1;
        if (gScreenTransitionType == SCREEN_TRANSITION_HUD)
        {
            setHudOpacity(0xff);
        }
        return;
    }
    if (screenTransitionAlpha > gScreenTransitionAlphaMax)
    {
        screenTransitionAlpha = gScreenTransitionAlphaMax;
        gScreenTransitionDone = 1;
        if (screenTransitionPause == 0)
        {
            gScreenTransitionHoldTimer = gScreenTransitionHoldTimer + timeDelta;
        }
        if (gScreenTransitionType != SCREEN_TRANSITION_HUD)
        {
            setHudOpacity(0xff);
        }
    }
    else
    {
        gScreenTransitionDone = 0;
    }
    if (gDvdErrorPauseActive != 0)
    {
        return;
    }
    switch (gScreenTransitionType)
    {
    case SCREEN_TRANSITION_BLACK:
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
    case SCREEN_TRANSITION_WHITE:
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
    case SCREEN_TRANSITION_WHITE_WIPE:
        screenRectFn_800d7568(p1, p2, p3, 0xff, 0xff, 0xff);
        break;
    case SCREEN_TRANSITION_RED:
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
    case SCREEN_TRANSITION_HUD:
        break;
    }
}
#pragma opt_common_subs reset

extern f32 gScreenTransitionAlphaMidpoint;
extern f32 lbl_803E0544;
extern f32 gScreenTransitionEdgeScale;
extern void Camera_GetCurrentViewport(int* x1, int* y1, int* x2, int* y2);

void screenRectFn_800d7568(int p1, int p2, int p3, u8 r, u8 g, u8 b)
{
    u32 H;
    int vx;
    int vy;
    int vr;
    int vb;
    int sx;
    int sy;
    int sw;
    int sh;
    HudColor col;
    u32 halfSpan;
    u32 cur;
    u32 span;
    u32 edge;
    u32 hiEdge;
    u32 hStep;
    u32 loEdge;
    u32 inset;
    u8 maxAlpha;
    u8 step;
    u8 fadeAlpha;
    f32 conv;

    GXGetScissor(&sx, &sy, &sw, &sh);
    Camera_GetCurrentViewport(&vx, &vy, &vr, &vb);
    span = (vr - vx) & 0xffff;
    H = (vb - vy) & 0xffff;
    if (screenTransitionAlpha > gScreenTransitionAlphaMidpoint)
    {
        maxAlpha = 0xff;
        inset = (int)(screenTransitionAlpha - gScreenTransitionAlphaMidpoint);
    }
    else
    {
        maxAlpha = lbl_803E0544 * screenTransitionAlpha;
        inset = 0;
    }
    halfSpan = (u16)(span >> 1);
    inset = inset & 0xffff;
    conv = (f32)(int)(inset * halfSpan);
    edge = (u32)(int)(conv * gScreenTransitionEdgeScale) & 0xffff;
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
            hudDrawRect(vx + (hiEdge & 0xffff), vy, step + (vx + (hiEdge & 0xffff)), vb, col);
            hudDrawRect((vx + (edge & 0xffff) - step) + 1, vy, vx + (edge & 0xffff) + 1, vb, col);
            hiEdge += step;
            edge -= step;
        }
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = ((int)(fadeAlpha * (halfSpan - cur)) / (int)halfSpan) & 0xff;
        hudDrawRect(vx + (hiEdge & 0xffff), vy, vr, vb, col);
        hudDrawRect(vx, vy, vx + (edge & 0xffff) + 1, vb, col);
        edge = (u16)(H >> 1);
        conv = (f32)(int)(inset * edge);
        inset = (u32)(int)(conv * gScreenTransitionEdgeScale) & 0xffff;
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
        for (hStep = 0; hiEdge = hStep & 0xffff, (int)hiEdge < (int)(halfSpan - step); hStep += step)
        {
            col.r = 0xff;
            col.g = 0xff;
            col.b = 0xff;
            col.a = ((int)(fadeAlpha * (edge - hiEdge)) / (int)edge) & 0xff;
            hudDrawRect(vx, vy + (loEdge & 0xffff), vr, step + (vy + (loEdge & 0xffff)), col);
            hudDrawRect(vx, (vy + (inset & 0xffff) - step) + 1, vr, vy + (inset & 0xffff) + 1, col);
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
