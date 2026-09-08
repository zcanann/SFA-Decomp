#include "dlls/object_descriptor.h"
#include "game/objects/object.h"
#include "main/screen_transition.h"
#include "main/gx_scissor_api.h"
#include "main/dll/dll_0016_screentransition.h"
#include "main/camera.h"
#include "main/frame_timing.h"
#include "main/fileio.h"
#include "track/intersect_hud_api.h"

#define SCREEN_TRANSITION_ALPHA_MIDPOINT 127.0f
#define SCREEN_TRANSITION_ALPHA_SCALE    2.0f
#define SCREEN_TRANSITION_ALPHA_MAX      255.0f
#define SCREEN_TRANSITION_FADE_STEP      256.0f
#define SCREEN_TRANSITION_HOLD_DURATION  120.0f

u8 screenTransitionPause;
u8 gScreenTransitionDelay;
u8 gScreenTransitionDone;
u8 gScreenTransitionType;
f32 gScreenTransitionHoldTimer;
f32 gScreenTransitionAlphaStep;
f32 screenTransitionAlpha;

static inline void screenTransitionFadeBlack(void) {
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

static inline void screenTransitionFadeColor(u8 r, u8 g, u8 b) {
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

/*
 * SCREEN_TRANSITION_WHITE_WIPE renderer: draws an opaque colored band across the
 * center of the viewport with alpha-fading strips expanding outward, first along
 * X (vertical band), then along Y (horizontal band). The band grows with the
 * transition alpha; when it covers the viewport this falls back to a plain fade.
 * The fallback passes (r, b, g), as in retail; this renderer is called with white.
 */
void screenTransition_drawWhiteWipe(int p1, int p2, int p3, u8 r, u8 g, u8 b) {
    u8 maxAlpha;
    u32 verticalWalked;
    u32 horizontalFade;
    int horizontalLimit;
    int verticalLimit;
    u32 horizontalStep;
    s32 vx;
    s32 vy;
    u32 vr;
    s32 vb;
    u32 sx;
    u32 sy;
    u32 sw;
    u32 sh;
    GXColor col;
    u16 halfHeight;
    u32 alphaSpan;
    u32 wipeSpan;
    u32 verticalStep;
    u16 halfWidth;
    u32 top;
    u32 height;
    f32 conv;
    u32 bottom;
    u32 horizontalWalked;
    u32 right;
    u32 left;
    u32 verticalFade;
    s32 verticalDistance;
    u32 bandHalfWidth;
    u32 width;
    s32 viewHeight;
    s32 viewWidth;
    s32 horizontalDistance;
    u32 bandHalfHeight;
    u32 wipeAmount;
    u8 horizontalStrip;
    u8 verticalStrip;

    GXGetScissor(&sx, &sy, &sw, &sh);
    Camera_GetFullViewportRect(&vx, &vy, &vr, &vb);
    viewWidth = vr - vx;
    width = viewWidth & 0xffff;
    viewHeight = vb - vy;
    height = viewHeight & 0xffff;
    if (screenTransitionAlpha > SCREEN_TRANSITION_ALPHA_MIDPOINT) {
        maxAlpha = 0xff;
        wipeAmount = (int)(screenTransitionAlpha - SCREEN_TRANSITION_ALPHA_MIDPOINT);
    } else {
        maxAlpha = SCREEN_TRANSITION_ALPHA_SCALE * screenTransitionAlpha;
        wipeAmount = 0;
    }
    halfWidth = (u16)(width >> 1);
    wipeSpan = wipeAmount & 0xffff;
    conv = (f32)(int)(wipeSpan * halfWidth);
    bandHalfWidth = (u16)(conv / 128.0f);
    if (bandHalfWidth == halfWidth) {
        screenTransitionFadeColor(r, b, g);
    } else {
        horizontalFade = (halfWidth - bandHalfWidth) & 0xffff;
        right = (halfWidth + bandHalfWidth) & 0xffff;
        left = ((halfWidth - 1) - bandHalfWidth) & 0xffff;
        GXSetScissor(vx, vy, viewWidth, viewHeight);
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = maxAlpha;
        hudDrawRect(vx + left + 1, vy, vx + right, vb, col);
        horizontalStrip = (int)horizontalFade / ((int)halfWidth / 6);
        if (horizontalStrip == 0) {
            horizontalStrip = 1;
        }
        horizontalWalked = 0;
        alphaSpan = maxAlpha;
        horizontalStep = horizontalStrip;
        horizontalLimit = horizontalFade - horizontalStep;
        while ((horizontalDistance = horizontalWalked & 0xffff) < horizontalLimit) {
            col.r = 0xff;
            col.g = 0xff;
            col.b = 0xff;
            col.a = ((int)(alphaSpan * (halfWidth - horizontalDistance)) / (int)halfWidth) & 0xff;
            hudDrawRect(vx + (right & 0xffff), vy, horizontalStep + (vx + (right & 0xffff)), vb, col);
            hudDrawRect((vx + (left & 0xffff) - horizontalStep) + 1, vy, vx + (left & 0xffff) + 1, vb, col);
            horizontalWalked += horizontalStep;
            right += horizontalStep;
            left -= horizontalStep;
        }
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = ((int)(alphaSpan * (halfWidth - horizontalDistance)) / (int)halfWidth) & 0xff;
        hudDrawRect(vx + (right & 0xffff), vy, vr, vb, col);
        hudDrawRect(vx, vy, vx + (left & 0xffff) + 1, vb, col);
        halfHeight = (u16)(height >> 1);
        conv = (f32)(int)(wipeSpan * halfHeight);
        bandHalfHeight = (u16)(conv / 128.0f);
        verticalFade = (halfHeight - bandHalfHeight) & 0xffff;
        bottom = (halfHeight + bandHalfHeight) & 0xffff;
        top = ((halfHeight - 1) - bandHalfHeight) & 0xffff;
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = maxAlpha;
        hudDrawRect(vx, vy + top + 1, vr, vy + bottom, col);
        verticalStrip = (int)verticalFade / (int)((u32)halfHeight >> 3);
        if (verticalStrip == 0) {
            verticalStrip = 1;
        }
        verticalWalked = 0;
        verticalStep = verticalStrip;
        verticalLimit = verticalFade - verticalStep;
        while ((verticalDistance = verticalWalked & 0xffff) < verticalLimit) {
            col.r = 0xff;
            col.g = 0xff;
            col.b = 0xff;
            col.a = ((int)(alphaSpan * (halfHeight - verticalDistance)) / (int)halfHeight) & 0xff;
            hudDrawRect(vx, vy + (bottom & 0xffff), vr, verticalStep + (vy + (bottom & 0xffff)), col);
            hudDrawRect(vx, (vy + (top & 0xffff) - verticalStep) + 1, vr, vy + (top & 0xffff) + 1, col);
            verticalWalked += verticalStep;
            bottom += verticalStep;
            top -= verticalStep;
        }
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = ((int)(alphaSpan * (halfHeight - verticalDistance)) / (int)halfHeight) & 0xff;
        hudDrawRect(vx, vy + (bottom & 0xffff), vr, vb, col);
        hudDrawRect(vx, vy, vr, vy + (top & 0xffff) + 1, col);
        GXSetScissor(sx, sy, sw, sh);
    }
}

void setScreenTransitionPause(u32 pause) {
    screenTransitionPause = pause;
}

u8 screenTransition_isDone(void) {
    return gScreenTransitionDone;
}

f32 screenTransition_getAlpha(void) {
    return screenTransitionAlpha;
}

void screenTransition_fadeFrom(int duration, int type, f32 from) {
    screenTransitionAlpha = SCREEN_TRANSITION_ALPHA_MAX * from;
    gScreenTransitionAlphaStep = -(SCREEN_TRANSITION_FADE_STEP * from) / duration;
    gScreenTransitionHoldTimer = 0.0f;
    gScreenTransitionType = type;
    gScreenTransitionDelay = 1;
}

int isScreenTransitionActive(void) {
    return SCREEN_TRANSITION_ALPHA_MAX == screenTransitionAlpha;
}

void screenTransition_holdThenFadeIn(int duration, int type) {
    screenTransitionAlpha = SCREEN_TRANSITION_ALPHA_MAX;
    gScreenTransitionAlphaStep = -SCREEN_TRANSITION_FADE_STEP / duration;
    gScreenTransitionHoldTimer = 0.0f;
    gScreenTransitionType = type;
    gScreenTransitionDelay = 5;
}

void screenTransition_fadeIn(int duration, int type) {
    if (gScreenTransitionAlphaStep >= 0.0f || screenTransitionAlpha == 0.0f) {
        screenTransitionAlpha = SCREEN_TRANSITION_ALPHA_MAX;
    }
    gScreenTransitionAlphaStep = -SCREEN_TRANSITION_FADE_STEP / duration;
    gScreenTransitionHoldTimer = 0.0f;
    gScreenTransitionType = type;
    gScreenTransitionDelay = 1;
}

void screenTransition_fadeOut(int duration, int type) {
    if (gScreenTransitionAlphaStep <= 0.0f || SCREEN_TRANSITION_ALPHA_MAX == screenTransitionAlpha) {
        screenTransitionAlpha = 0.0f;
    }
    gScreenTransitionAlphaStep = SCREEN_TRANSITION_FADE_STEP / duration;
    gScreenTransitionHoldTimer = 0.0f;
    gScreenTransitionType = type;
    gScreenTransitionDelay = 0;
}

void screenTransition_update(int p1, int p2, int p3) {
    if (gScreenTransitionDelay != 0) {
        gScreenTransitionDelay--;
    } else {
        if (screenTransitionPause == 0 && gScreenTransitionHoldTimer >= SCREEN_TRANSITION_HOLD_DURATION) {
            (*gScreenTransitionInterface)->step(0x1e, gScreenTransitionType);
            gScreenTransitionHoldTimer = 0.0f;
        }
        screenTransitionAlpha = gScreenTransitionAlphaStep * timeDelta + screenTransitionAlpha;
        if (screenTransitionAlpha < 0.0f) {
            screenTransitionAlpha = 0.0f;
            gScreenTransitionDone = 1;
            if (gScreenTransitionType == SCREEN_TRANSITION_HUD) {
                setHudOpacity(0xff);
            }
            return;
        }
        if (screenTransitionAlpha > SCREEN_TRANSITION_ALPHA_MAX) {
            screenTransitionAlpha = SCREEN_TRANSITION_ALPHA_MAX;
            gScreenTransitionDone = 1;
            if (screenTransitionPause == 0) {
                gScreenTransitionHoldTimer += timeDelta;
            }
            if (gScreenTransitionType != SCREEN_TRANSITION_HUD) {
                setHudOpacity(0xff);
            }
        } else {
            gScreenTransitionDone = 0;
        }
    }
    if (gDvdErrorPauseActive != 0) {
        return;
    }
    switch (gScreenTransitionType) {
    case SCREEN_TRANSITION_BLACK: {
        screenTransitionFadeBlack();
        break;
    }
    case SCREEN_TRANSITION_WHITE: {
        screenTransitionFadeColor(0xff, 0xff, 0xff);
        break;
    }
    case SCREEN_TRANSITION_WHITE_WIPE:
        screenTransition_drawWhiteWipe(p1, p2, p3, 0xff, 0xff, 0xff);
        break;
    case SCREEN_TRANSITION_RED: {
        screenTransitionFadeColor(0xff, 0, 0);
        break;
    }
    case SCREEN_TRANSITION_HUD:
        break;
    }
}
typedef struct ScreenTransitionDllInterface {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    ObjectDescriptorCallback initialise;
    ObjectDescriptorCallback release;
    ObjectDescriptorCallback slot02;
    ObjectDescriptorCallback update;
    ObjectDescriptorCallback fadeOut;
    ObjectDescriptorCallback fadeIn;
    ObjectDescriptorCallback fadeFrom;
    ObjectDescriptorCallback isDone;
    ObjectDescriptorCallback getAlpha;
    ObjectDescriptorCallback slot09;
} ScreenTransitionDllInterface;

ScreenTransitionDllInterface screenTransition_funcs = {
    0,
    0,
    0,
    0x00080000,
    0,
    0,
    0,
    (ObjectDescriptorCallback)screenTransition_update,
    (ObjectDescriptorCallback)screenTransition_fadeOut,
    (ObjectDescriptorCallback)screenTransition_fadeIn,
    (ObjectDescriptorCallback)screenTransition_fadeFrom,
    (ObjectDescriptorCallback)screenTransition_isDone,
    (ObjectDescriptorCallback)screenTransition_getAlpha,
    0,
};
