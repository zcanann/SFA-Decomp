#include "main/game_object.h"
#include "main/screen_transition.h"
#include "main/gx_scissor_api.h"
#include "main/dll/dll_0016_screentransition.h"
#include "main/camera.h"
#include "main/frame_timing.h"
#include "main/fileio.h"
#include "track/intersect_hud_api.h"

u8 screenTransitionPause;
u8 gScreenTransitionDelay;
u8 gScreenTransitionDone;
u8 gScreenTransitionType;
f32 gScreenTransitionHoldTimer;
f32 gScreenTransitionAlphaStep;
f32 screenTransitionAlpha;


extern f32 gScreenTransitionHoldDuration;

static inline void screenTransitionFadeBlack(void)
{
    GXColor col;
    u32 sx;
    u32 sy;
    u32 sw;
    u32 sh;
    GXGetScissor(&sx, &sy, &sw, &sh);
    GXSetScissor(0, 0, 0x280, 0x1e0);
    col.b = 0;
    col.g = 0;
    col.r = 0;
    col.a = screenTransitionAlpha;
    hudDrawRect(sx, sy, sw, sh, col);
    GXSetScissor(sx, sy, sw, sh);
}

static inline void screenTransitionFadeColor(u8 r, u8 g, u8 b)
{
    GXColor col;
    u32 sx;
    u32 sy;
    u32 sw;
    u32 sh;
    GXGetScissor(&sx, &sy, &sw, &sh);
    GXSetScissor(0, 0, 0x280, 0x1e0);
    col.r = r;
    col.g = g;
    col.b = b;
    col.a = screenTransitionAlpha;
    hudDrawRect(sx, sy, sw, sh, col);
    GXSetScissor(sx, sy, sw, sh);
}

extern f32 gScreenTransitionAlphaMidpoint;
extern f32 lbl_803E0544;
extern f32 gScreenTransitionEdgeScale;

/*
 * SCREEN_TRANSITION_WHITE_WIPE renderer: draws an opaque colored band across the
 * center of the viewport with alpha-fading strips expanding outward, first along
 * X (vertical band), then along Y (horizontal band). The band grows with the
 * transition alpha; when it covers the viewport this falls back to a plain fade.
 * The locals are reused across the two passes with shifted roles (matches the
 * retail register allocation):
 *   half:     pass 1 = half viewport width; pass 2 = fade extent (fadeSpan role)
 *   band:     pass 1 = band half-width, then left draw cursor; pass 2 = half height
 *   wipe:     pass 1 = wipe amount from alpha; pass 2 = band half-height, then top cursor
 *   fadeSpan: pass 1 = fade extent per side; pass 2 = bottom draw cursor
 *   outer:    pass 1 = right draw cursor; pass 2 = masked walk distance (dist role)
 * Note the (r, b, g) argument order on the fallback call is genuine retail
 * behavior (harmless: only ever invoked with r==g==b==0xFF).
 */
void screenRectFn_800d7568(int p1, int p2, int p3, u8 r, u8 g, u8 b)
{
    u32 height;
    s32 vx;
    s32 vy;
    u32 vr;
    s32 vb;
    u32 sx;
    u32 sy;
    u32 sw;
    u32 sh;
    GXColor col;
    u32 wipe;
    u32 dist;
    u32 width;
    u32 band;
    u32 half;
    u32 fadeSpan;
    u32 outer;
    u32 walked;
    u8 strip;
    u8 fadeAlpha;
    u8 maxAlpha;
    f32 conv;
    s32 w;
    s32 h;

    GXGetScissor(&sx, &sy, &sw, &sh);
    Camera_GetCurrentViewport(&vx, &vy, &vr, &vb);
    w = vr - vx;
    width = w & 0xffff;
    h = vb - vy;
    height = h & 0xffff;
    if (screenTransitionAlpha > gScreenTransitionAlphaMidpoint)
    {
        maxAlpha = 0xff;
        wipe = (int)(screenTransitionAlpha - gScreenTransitionAlphaMidpoint);
    }
    else
    {
        maxAlpha = lbl_803E0544 * screenTransitionAlpha;
        wipe = 0;
    }
    half = (u16)(width >> 1);
    wipe = wipe & 0xffff;
    conv = (f32)(int)(wipe * half);
    band = (u32)(int)(conv * gScreenTransitionEdgeScale) & 0xffff;
    if (band == half)
    {
        screenTransitionFadeColor(r, b, g);
    }
    else
    {
        fadeSpan = (half - band) & 0xffff;
        outer = (half + band) & 0xffff;
        band = ((half - 1) - band) & 0xffff;
        GXSetScissor(vx, vy, w, h);
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = maxAlpha;
        hudDrawRect(vx + band + 1, vy, vx + outer, vb, col);
        strip = (int)fadeSpan / ((int)half / 6);
        if (strip == 0)
        {
            strip = 1;
        }
        fadeAlpha = maxAlpha;
        for (walked = 0; dist = walked & 0xffff, (int)dist < (int)(fadeSpan - strip);)
        {
            col.r = 0xff;
            col.g = 0xff;
            col.b = 0xff;
            col.a = ((int)(fadeAlpha * (half - dist)) / (int)half) & 0xff;
            hudDrawRect(vx + (outer & 0xffff), vy, strip + (vx + (outer & 0xffff)), vb, col);
            hudDrawRect((vx + (band & 0xffff) - strip) + 1, vy, vx + (band & 0xffff) + 1, vb, col);
            walked += strip;
            outer += strip;
            band -= strip;
        }
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = ((int)(fadeAlpha * (half - dist)) / (int)half) & 0xff;
        hudDrawRect(vx + (outer & 0xffff), vy, vr, vb, col);
        hudDrawRect(vx, vy, vx + (band & 0xffff) + 1, vb, col);
        band = (u16)(height >> 1);
        conv = (f32)(int)(wipe * band);
        wipe = (u32)(int)(conv * gScreenTransitionEdgeScale) & 0xffff;
        half = (band - wipe) & 0xffff;
        fadeSpan = (band + wipe) & 0xffff;
        wipe = ((band - 1) - wipe) & 0xffff;
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = maxAlpha;
        hudDrawRect(vx, vy + wipe + 1, vr, vy + fadeSpan, col);
        strip = (int)half / (int)(band >> 3);
        if (strip == 0)
        {
            strip = 1;
        }
        for (walked = 0; outer = walked & 0xffff, (int)outer < (int)(half - strip);)
        {
            col.r = 0xff;
            col.g = 0xff;
            col.b = 0xff;
            col.a = ((int)(fadeAlpha * (band - outer)) / (int)band) & 0xff;
            hudDrawRect(vx, vy + (fadeSpan & 0xffff), vr, strip + (vy + (fadeSpan & 0xffff)), col);
            hudDrawRect(vx, (vy + (wipe & 0xffff) - strip) + 1, vr, vy + (wipe & 0xffff) + 1, col);
            walked += strip;
            fadeSpan += strip;
            wipe -= strip;
        }
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = ((int)(fadeAlpha * (band - outer)) / (int)band) & 0xff;
        hudDrawRect(vx, vy + (fadeSpan & 0xffff), vr, vb, col);
        hudDrawRect(vx, vy, vr, vy + (wipe & 0xffff) + 1, col);
        GXSetScissor(sx, sy, sw, sh);
    }
}


void setScreenTransitionPause(u32 pause)
{
    screenTransitionPause = pause;
}

u8 screenTransition_func07(void)
{
    return gScreenTransitionDone;
}

f32 screenTransition_getAlpha(void)
{
    return screenTransitionAlpha;
}

extern f32 gScreenTransitionAlphaMax;
extern f32 lbl_803E0564;
extern f32 lbl_803E055C;

void screenTransition_fadeFrom(int duration, int type, f32 from)
{
    screenTransitionAlpha = gScreenTransitionAlphaMax * from;
    gScreenTransitionAlphaStep = -(lbl_803E055C * from) / duration;
    gScreenTransitionHoldTimer = 0.0f;
    gScreenTransitionType = type;
    gScreenTransitionDelay = 1;
}


int isScreenTransitionActive(void)
{
    return gScreenTransitionAlphaMax == screenTransitionAlpha;
}


void screenTransitionFn_800d7b04(int duration, int type)
{
    screenTransitionAlpha = gScreenTransitionAlphaMax;
    gScreenTransitionAlphaStep = lbl_803E0564 / duration;
    gScreenTransitionHoldTimer = 0.0f;
    gScreenTransitionType = type;
    gScreenTransitionDelay = 5;
}

void screenTransition_fadeIn(int duration, int type)
{
    if (gScreenTransitionAlphaStep >= 0.0f || 0.0f == screenTransitionAlpha)
    {
        screenTransitionAlpha = gScreenTransitionAlphaMax;
    }
    gScreenTransitionAlphaStep = lbl_803E0564 / duration;
    gScreenTransitionHoldTimer = 0.0f;
    gScreenTransitionType = type;
    gScreenTransitionDelay = 1;
}

void screenTransition_fadeOut(int duration, int type)
{
    if (gScreenTransitionAlphaStep <= 0.0f || gScreenTransitionAlphaMax == screenTransitionAlpha)
    {
        screenTransitionAlpha = 0.0f;
    }
    gScreenTransitionAlphaStep = lbl_803E055C / duration;
    gScreenTransitionHoldTimer = 0.0f;
    gScreenTransitionType = type;
    gScreenTransitionDelay = 0;
}

void screenTransition_update(int p1, int p2, int p3)
{
    if (gScreenTransitionDelay != 0)
    {
        gScreenTransitionDelay--;
    }
    else
    {
        if (screenTransitionPause == 0 && gScreenTransitionHoldTimer >= gScreenTransitionHoldDuration)
        {
            (*gScreenTransitionInterface)->step(0x1e, gScreenTransitionType);
            gScreenTransitionHoldTimer = 0.0f;
        }
        screenTransitionAlpha = gScreenTransitionAlphaStep * timeDelta + screenTransitionAlpha;
        if (screenTransitionAlpha < 0.0f)
        {
            screenTransitionAlpha = 0.0f;
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
    }
    if (gDvdErrorPauseActive != 0)
    {
        return;
    }
    switch (gScreenTransitionType)
    {
    case SCREEN_TRANSITION_BLACK:
    {
        screenTransitionFadeBlack();
        break;
    }
    case SCREEN_TRANSITION_WHITE:
    {
        screenTransitionFadeColor(0xff, 0xff, 0xff);
        break;
    }
    case SCREEN_TRANSITION_WHITE_WIPE:
        screenRectFn_800d7568(p1, p2, p3, 0xff, 0xff, 0xff);
        break;
    case SCREEN_TRANSITION_RED:
    {
        screenTransitionFadeColor(0xff, 0, 0);
        break;
    }
    case SCREEN_TRANSITION_HUD:
        break;
    }
}


u32 lbl_80311340[14] = {
    0, 0, 0, 0x00080000,
    0, 0, 0, (u32)screenTransition_update,
    (u32)screenTransition_fadeOut, (u32)screenTransition_fadeIn, (u32)screenTransition_fadeFrom, (u32)screenTransition_func07,
    (u32)screenTransition_getAlpha, 0,
};
