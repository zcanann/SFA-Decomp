#include "main/dll/waterfx.h"
#include "main/dll/obj_collision_state.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "dolphin/gx/GXBump.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXDispList.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXManage.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTransform.h"
#include "dolphin/mtx.h"
#include "MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/sky_interface.h"
#include "main/shader_api.h"
#include "main/frame_timing.h"
#include "main/mm.h"
#include "main/vecmath.h"
#include "main/debug.h"
#include "main/lightmap_api.h"
#include "main/rcp_dolphin_api.h"
#include "track/intersect_api.h"
#include "main/texture.h"
#include "main/camera.h"
#include "main/resource.h"
#include "dolphin/os/OSCache.h"
#include "track/intersect_depth_state_api.h"

LightmapVertex* gWaterfxRippleVertices;
LightmapTriangle* gWaterfxRippleTriangles;
LightmapVertex* gWaterfxWakeVertices;
LightmapTriangle* gWaterfxWakeTriangles;
int gWaterfxRippleCount;
WaterCircularRipple* gWaterfxRipplePool;
int gWaterfxSplashCount;
WaterSplashBurst* gWaterfxSplashPool;
int gWaterfxWakeCount;
WaterMovementRipple* gWaterfxWakePool;
int gWaterfxDropCount;
WaterSplashDrop* gWaterfxDropPool;
Texture* gWaterfxRippleTexture;
Texture* gWaterfxSplashTexture0;
Texture* gWaterfxSplashTexture1;
Texture* gWaterfxWakeTexture;
f32 gWaterfxRippleScale;
void* gWaterfxSplashDisplayList;
u16 gWaterfxSplashDisplayListSize;
Vec* gWaterfxSplashPosArray;
f32 (*gWaterfxSplashTexCoordArray)[2];
u8 gWaterfxPendingImpactPositionValid;

f32 gWaterfxPendingImpactPosition[4];

volatile PPCWGPipe GXWGFifo : (0xCC008000);

#define WATERFX_TEXTURE_RIPPLE  0x56  /* gWaterfxRippleTexture */
#define WATERFX_TEXTURE_SPLASH0 0xc2a /* gWaterfxSplashTexture0 */
#define WATERFX_TEXTURE_SPLASH1 0xc2c /* gWaterfxSplashTexture1 */
#define WATERFX_TEXTURE_WAKE    0xc2d /* gWaterfxWakeTexture */

#define WATERFX_PHASE_START            0.100000024f
#define WATERFX_BAND_OFFSET_SCALE      0.9f
#define WATERFX_RIPPLE_FADE_RATE       0.5f
#define WATERFX_ONE                    1.0f
#define WATERFX_FADE_CURVE_SCALE       4.0f
#define WATERFX_BAND_LIMIT_BASE        0.05f
#define WATERFX_BAND_COUNT             7.0f
#define WATERFX_SPLASH_SIZE_SCALE      2.0f
#define WATERFX_ZERO                   0.0f
#define WATERFX_ALPHA_MAX              255.0f
#define WATERFX_PI                     3.142f
#define WATERFX_RING_SEGMENT_MAX       15.0f
#define WATERFX_DEFAULT_SCALE          0.01f
#define WATERFX_SPLASH_VELOCITY_SCALE  3.0f
#define WATERFX_SPLASH_LIFETIME_SCALE  16.0f
#define WATERFX_RIPPLE_GROW_SPEED      0.001f
#define WATERFX_WAKE_GROW_SPEED        0.004f
#define WATERFX_DROP_GRAVITY           -0.05f
#define WATERFX_DROP_DAMPING           0.97f
#define WATERFX_DROP_RIPPLE_SCALE      0.005f
#define WATERFX_SHALLOW_DEPTH          10.0f
#define WATERFX_SPLASH_SPEED_THRESHOLD 0.25f

static void waterfx_setupSplashDropPointRender(void) {
    GXColor col;
    u8 ignoredLightColor;
    GXSetPointSize(0x12, GX_TO_ONE);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXLoadPosMtxImm((MtxPtr)Camera_GetViewMatrix(), GX_PNMTX0);
    GXSetCurrentMtx(GX_PNMTX0);
    GXSetTevKColorSel(GX_TEVSTAGE0, GX_TEV_KCSEL_K0);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    GXSetNumIndStages(0);
    GXSetNumTexGens(0);
    GXSetNumTevStages(1);
    GXSetNumChans(1);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_KONST);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_KONST);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    gxSetZMode_(1, GX_LEQUAL, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetCullMode(GX_CULL_NONE);
    (*gSkyInterface)
        ->getCurrentAmbientAndLightColors(&col.r, &col.g, &col.b, &ignoredLightColor, &ignoredLightColor,
                                          &ignoredLightColor);
    col.r = (col.r >> 2) + 0x80;
    col.g = (col.g >> 2) + 0x80;
    col.b = (col.b >> 2) + 0x80;
    col.a = 0x80;
    GXSetTevKColor(GX_KCOLOR0, col);
}

static f32 waterfxBandEnvelope(f32 frac, f32 life, f32* phaseOut, f32* alphaOut) {
    f32 ph;
    f32 dd;
    f32 fade;
    f32 lim;

    ph = (WATERFX_PHASE_START + WATERFX_BAND_OFFSET_SCALE * frac) * life;
    dd = ph - WATERFX_RIPPLE_FADE_RATE;
    fade = WATERFX_ONE - WATERFX_FADE_CURVE_SCALE * (dd * dd);
    lim = WATERFX_BAND_LIMIT_BASE + WATERFX_BAND_OFFSET_SCALE * frac;
    if (life < lim) {
        *alphaOut = WATERFX_ONE;
    } else {
        *alphaOut = (WATERFX_ONE - life) / (WATERFX_ONE - lim);
    }
    *phaseOut = ph;
    return fade;
}

/*
 * Renders one splash burst as a ring of 8 expanding, fading sprite bands.
 * For each of the 8 bands it builds a model-view matrix (scaled by the burst
 * radius, bulged outward and lifted by a parabolic 'fade' arc, translated to
 * the impact point and multiplied by the camera view), loads it as a posmtx,
 * and writes that band's per-vertex alpha into the color array (s->bandColors).
 * The completed geometry is drawn twice (front then back cull) via the shared
 * display list.
 */
void waterfx_drawSplashBurst(WaterSplashBurst* s) {
    Mtx mtxD;
    Mtx scale;
    Mtx mtxB;
    Mtx mtxC;
    int i;

    PSMTXScale(scale, s->size, s->size, s->size);
    i = 0;
    for (; i < 8; i++) {
        f32 bandPhase;
        f32 dd;
        f32 lim;
        f32 sc;
        f32 fade;
        f32 alpha;
        struct {
            f32 life;
            f32 phase;
        } band;
        band.life = s->life;
        bandPhase = WATERFX_PHASE_START + WATERFX_BAND_OFFSET_SCALE * ((f32)i / WATERFX_BAND_COUNT);
        band.phase = bandPhase * band.life;
        dd = band.phase - 0.5f;
        fade = -(WATERFX_FADE_CURVE_SCALE * (dd * dd) - 1.0f);
        lim = WATERFX_BAND_LIMIT_BASE + WATERFX_BAND_OFFSET_SCALE * ((f32)i / WATERFX_BAND_COUNT);
        if (band.life < lim) {
            alpha = 1.0f;
        } else {
            alpha = (1.0f - band.life) / (1.0f - lim);
        }
        sc = 2.0f * band.phase + 1.0f;
        PSMTXScale(mtxB, sc, 1.0f, sc);
        PSMTXTrans(mtxC, 0.0f, 2.0f * fade, 0.0f);
        PSMTXConcat(mtxC, mtxB, mtxD);
        PSMTXConcat(scale, mtxD, mtxD);
        PSMTXTrans(mtxC, s->x - playerMapOffsetX, s->y, s->z - playerMapOffsetZ);
        PSMTXConcat(mtxC, mtxD, mtxD);
        PSMTXConcat((MtxPtr)Camera_GetViewMatrix(), mtxD, mtxD);
        GXLoadPosMtxImm(mtxD, i * 3);
        s->bandColors[i] = (u8)(int)(WATERFX_ALPHA_MAX * alpha);
    }
    DCStoreRange(s->bandColors, 32);
    GXSetArray(GX_VA_CLR0, s->bandColors, 4);
    GXSetCullMode(GX_CULL_FRONT);
    GXCallDisplayList(gWaterfxSplashDisplayList, gWaterfxSplashDisplayListSize);
    GXSetCullMode(GX_CULL_BACK);
    GXCallDisplayList(gWaterfxSplashDisplayList, gWaterfxSplashDisplayListSize);
}

static void waterfx_buildSplashDisplayList(void) {
    int m;
    Vec* pos;
    int i;
    int j;
    int k;
    void* dl;

    GXSetMisc(GX_MT_XF_FLUSH, 0);
    gWaterfxSplashPosArray = mmAlloc(192, 0, 0);
    gWaterfxSplashTexCoordArray = mmAlloc(1024, 0, 0);
    for (i = 0; i < 8; i++) {
        for (j = 0; j < 16; j++) {
            if (i == 0) {
                f32 ang;
                f32 sv;
                f32 cv;
                pos = &gWaterfxSplashPosArray[j];
                ang = WATERFX_PI * (f32)(j * 2) / WATERFX_RING_SEGMENT_MAX;
                sv = mathCosfPrecise(ang);
                cv = mathSinfPrecise(ang);
                pos->x = sv;
                pos->y = WATERFX_ZERO;
                pos->z = cv;
            }
            {
                int idx = i * 16 + j;
                f32* tex = gWaterfxSplashTexCoordArray[idx];
                tex[0] = j / WATERFX_RING_SEGMENT_MAX;
                tex[1] = i / WATERFX_BAND_COUNT;
            }
        }
    }
    DCStoreRange(gWaterfxSplashPosArray, 192);
    DCStoreRange(gWaterfxSplashTexCoordArray, 1024);
    dl = mmAlloc(2880, 0x7F7F7FFF, 0);
    gWaterfxSplashDisplayList = dl;
    DCInvalidateRange(dl, 2880);
    GXBeginDisplayList(gWaterfxSplashDisplayList, 2880);
    GXResetWriteGatherPipe();
    for (k = 0; k < 15; k++) {
        GXBegin(GX_TRIANGLESTRIP, GX_VTXFMT2, 16);
        for (m = 7; m >= 0; m--) {
            GXWGFifo.u8 = m * 3;
            GXWGFifo.u8 = m * 3;
            GXWGFifo.u16 = k;
            GXWGFifo.u16 = m;
            GXWGFifo.u16 = m * 16 + k;
            GXWGFifo.u8 = m * 3;
            GXWGFifo.u8 = m * 3;
            GXWGFifo.u16 = (k + 1) % 16;
            GXWGFifo.u16 = m;
            GXWGFifo.u16 = m * 16 + (k + 1) % 16;
        }
    }
    gWaterfxSplashDisplayListSize = GXEndDisplayList();
    GXSetMisc(GX_MT_XF_FLUSH, 8);
}

int waterfx_consumePendingImpactNearPoint(f32* vec, f32 dist) {
    if (gWaterfxPendingImpactPositionValid != 0 &&
        PSVECSquareDistance((Vec*)vec, (Vec*)gWaterfxPendingImpactPosition) < dist * dist) {
        gWaterfxPendingImpactPositionValid = 0;
        return 1;
    }
    gWaterfxPendingImpactPositionValid = 0;
    return 0;
}

void waterfx_spawnCircularRipple(f32 x, f32 y, f32 z, s16 yaw, f32 unknown0C, int intensity) {
    int i = 0;
    WaterCircularRipple* p = gWaterfxRipplePool;
    LightmapVertex* q;
    int j;
    while (i < WATERFX_POOL_SIZE && p->alpha != 0) {
        p++;
        i++;
    }
    if (i >= WATERFX_POOL_SIZE) {
        return;
    }
    j = i * 4;
    q = &gWaterfxRippleVertices[j];
    q->x = -300;
    q->y = 0;
    q->z = 300;
    q->a = 0xff;
    q->s = 0;
    q->t = 0;
    q = &gWaterfxRippleVertices[j + 1];
    q->x = -300;
    q->y = 0;
    q->z = -300;
    q->a = 0xff;
    q->s = 0;
    q->t = 0x7f;
    q = &gWaterfxRippleVertices[j + 2];
    q->x = 300;
    q->y = 0;
    q->z = -300;
    q->a = 0xff;
    q->s = 0x7f;
    q->t = 0x7f;
    q = &gWaterfxRippleVertices[j + 3];
    q->x = 300;
    q->y = 0;
    q->z = 300;
    q->a = 0xff;
    q->s = 0x7f;
    q->t = 0;
    gWaterfxRipplePool[i].unknown0C = unknown0C;
    gWaterfxRipplePool[i].alpha = 0xff;
    gWaterfxRipplePool[i].x = x;
    gWaterfxRipplePool[i].y = y;
    gWaterfxRipplePool[i].z = z;
    gWaterfxRipplePool[i].yaw = yaw;
    gWaterfxRipplePool[i].scale = gWaterfxRippleScale;
    gWaterfxRipplePool[i].fadeRate = WATERFX_RIPPLE_FADE_RATE * intensity;
    gWaterfxRippleCount++;
}

void waterfx_setRippleScale(int flag, f32 val) {
    if (flag != 0) {
        val = WATERFX_DEFAULT_SCALE;
    }
    gWaterfxRippleScale = val;
}

void waterfx_spawnMovementRipple(f32 x, f32 y, f32 z, s16 yaw, f32 unknown0C) {
    int i = 0;
    WaterMovementRipple* p = gWaterfxWakePool;
    LightmapVertex* q;
    WaterMovementRipple* entry;
    int j;
    while (i < WATERFX_POOL_SIZE && p->alpha != 0) {
        p++;
        i++;
    }
    if (i >= WATERFX_POOL_SIZE) {
        return;
    }
    j = i * 4;
    q = &gWaterfxWakeVertices[j];
    q[0].x = -200;
    q[0].y = 0;
    q[0].z = 400;
    q[0].a = 0xff;
    q[0].s = 0;
    q[0].t = 0;
    q[1].x = -200;
    q[1].y = 0;
    q[1].z = -200;
    q[1].a = 0xff;
    q[1].s = 0;
    q[1].t = 0x80;
    q[2].x = 200;
    q[2].y = 0;
    q[2].z = -200;
    q[2].a = 0xff;
    q[2].s = 0x80;
    q[2].t = 0x80;
    q[3].x = 200;
    q[3].y = 0;
    q[3].z = 400;
    q[3].a = 0xff;
    q[3].s = 0x80;
    q[3].t = 0;
    entry = gWaterfxWakePool + i;
    entry->x = x;
    entry->y = y;
    entry->z = z;
    entry->unknown0C = unknown0C;
    entry->scale = WATERFX_DEFAULT_SCALE;
    entry->alpha = 0xff;
    entry->yaw = yaw;
    entry->hidden = 0;
    gWaterfxWakeCount++;
}

void waterfx_spawnSplashBurst(GameObject* obj, f32 x, f32 y, f32 z, f32 size) {
    WaterSplashBurst* base;
    int i;
    WaterSplashBurst* slot;
    int rnd;
    if (WATERFX_ZERO == size) {
        size = WATERFX_SPLASH_VELOCITY_SCALE;
    }
    i = 0;
    base = gWaterfxSplashPool;
    while (i < WATERFX_MAX_SPLASHES && (base[i].dropCount != 0 || base[i].life < 1.0f)) {
        i++;
    }
    if (i >= WATERFX_MAX_SPLASHES) {
        return;
    }
    slot = &base[i];
    slot->x = x;
    slot->y = y;
    slot->z = z;
    gWaterfxSplashCount++;
    slot->size = size;
    rnd = randomGetRange((int)slot->size, (int)(WATERFX_SPLASH_SIZE_SCALE * slot->size));
    slot->dropCount = waterfx_spawnSplashDrops(&gWaterfxSplashPool[i], i, rnd, slot->size);
    slot->life = WATERFX_ZERO;
    slot->lifeSpeed = 1.0f / (WATERFX_SPLASH_LIFETIME_SCALE * sqrtf(slot->size));
}

int waterfx_spawnSplashDrops(WaterSplashBurst* src, int idx, int count, f32 v) {
    int cur;
    f32 scale;
    WaterSplashDrop* base;
    WaterSplashDrop* slot;
    int j;
    int i;
    cur = gWaterfxDropCount;
    if (count + cur > WATERFX_POOL_SIZE) {
        count = WATERFX_POOL_SIZE - cur;
    }
    if (count != 0) {
        i = 0;
        scale = WATERFX_RIPPLE_GROW_SPEED * v;
        for (; i < count; i++) {
            j = 0;
            base = gWaterfxDropPool;
            while (j < WATERFX_POOL_SIZE && base[j].parentIdx != -1) {
                j++;
            }
            if (j < WATERFX_POOL_SIZE) {
                slot = &base[j];
                slot->vx = randomGetRange(-250, 250);
                slot->vx *= scale;
                slot->vz = randomGetRange(-250, 250);
                slot->vz *= scale;
                slot->vy = randomGetRange(200, 300);
                slot->vy *= scale;
                slot->parentIdx = idx;
                slot->x = src->x;
                slot->y = src->y;
                slot->z = src->z;
                gWaterfxDropCount++;
            }
        }
    }
    return count;
}

void waterfx_render(int unusedDisplayList, int unusedMatrixList) {
    int triangleIndex;
    int rippleIndex;
    void* particle;
    int index;
    f32 lifeLimit;
    MatrixTransform transform;
    if (gWaterfxRippleCount != 0 || gWaterfxWakeCount != 0 || gWaterfxSplashCount != 0 || gWaterfxDropCount != 0) {
        GXSetCullMode(GX_CULL_NONE);
        if (gWaterfxRippleCount != 0) {
            setupReflectionBumpDistortTev(gWaterfxRippleTexture);
        }
        for (rippleIndex = 0; rippleIndex < WATERFX_POOL_SIZE; rippleIndex++) {
            particle = &gWaterfxRipplePool[rippleIndex];
            if (((WaterCircularRipple*)particle)->alpha != 0) {
                setTextColor((void*)unusedDisplayList, 0xff, 0xff, 0xff, (u8)((WaterCircularRipple*)particle)->alpha);
                transform.x = ((WaterCircularRipple*)particle)->x;
                transform.y = ((WaterCircularRipple*)particle)->y;
                transform.z = ((WaterCircularRipple*)particle)->z;
                transform.scale = ((WaterCircularRipple*)particle)->scale;
                transform.rotX = ((WaterCircularRipple*)particle)->yaw;
                transform.rotZ = 0;
                transform.rotY = 0;
                Camera_LoadModelViewMatrix(unusedDisplayList, unusedMatrixList, &transform, 1.0f, WATERFX_ZERO, NULL);
                loadReflectionTexMtxs();
                triangleIndex = rippleIndex * 2;
                lightmapDrawTriangleList(&gWaterfxRippleVertices[triangleIndex * 2],
                                         (u8*)&gWaterfxRippleTriangles[triangleIndex], 2);
            }
        }
        index = 0;
        if (gWaterfxSplashCount != 0) {
            setupWaterReflectionTev(gWaterfxSplashTexture0, gWaterfxSplashTexture1);
            GXSetArray(GX_VA_POS, gWaterfxSplashPosArray, 0xc);
            GXSetArray(GX_VA_TEX0, gWaterfxSplashTexCoordArray, 8);
            GXClearVtxDesc();
            GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
            GXSetVtxDesc(GX_VA_TEX0MTXIDX, GX_DIRECT);
            GXSetVtxDesc(GX_VA_POS, GX_INDEX16);
            GXSetVtxDesc(GX_VA_CLR0, GX_INDEX16);
            GXSetVtxDesc(GX_VA_TEX0, GX_INDEX16);
        }
        for (lifeLimit = 1.0f; index < WATERFX_MAX_SPLASHES; index++) {
            particle = &gWaterfxSplashPool[index];
            if (((WaterSplashBurst*)particle)->life < lifeLimit) {
                waterfx_drawSplashBurst((WaterSplashBurst*)particle);
            }
        }
        if (gWaterfxDropCount != 0) {
            waterfx_setupSplashDropPointRender();
        }
        for (index = 0; index < WATERFX_POOL_SIZE; index++) {
            particle = &gWaterfxDropPool[index];
            if (((WaterSplashDrop*)particle)->parentIdx != -1) {
                f32 vx, vy, vz;
                GXBegin(GX_POINTS, GX_VTXFMT2, 1);
                vz = ((WaterSplashDrop*)particle)->z - playerMapOffsetZ;
                vy = ((WaterSplashDrop*)particle)->y;
                vx = ((WaterSplashDrop*)particle)->x - playerMapOffsetX;
                GXWGFifo.f32 = vx;
                GXWGFifo.f32 = vy;
                GXWGFifo.f32 = vz;
            }
        }
        if (gWaterfxWakeCount != 0) {
            setupReflectionDistortTev(gWaterfxWakeTexture);
        }
        for (index = 0; index < WATERFX_POOL_SIZE; index++) {
            particle = &gWaterfxWakePool[index];
            if (((WaterMovementRipple*)particle)->alpha != 0 && ((WaterMovementRipple*)particle)->hidden == 0) {
                setTextColor((void*)unusedDisplayList, 0xff, 0xff, 0xff, (u8)((WaterMovementRipple*)particle)->alpha);
                transform.x = ((WaterMovementRipple*)particle)->x;
                transform.y = ((WaterMovementRipple*)particle)->y;
                transform.z = ((WaterMovementRipple*)particle)->z;
                transform.scale = ((WaterMovementRipple*)particle)->scale;
                transform.rotX = ((WaterMovementRipple*)particle)->yaw;
                transform.rotZ = 0;
                transform.rotY = 0;
                Camera_LoadModelViewMatrix(unusedDisplayList, unusedMatrixList, &transform, 1.0f, WATERFX_ZERO, NULL);
                loadReflectionTexMtxs();
                triangleIndex = index * 2;
                lightmapDrawTriangleList(&gWaterfxWakeVertices[triangleIndex * 2],
                                         (u8*)&gWaterfxWakeTriangles[triangleIndex], 2);
            }
        }
        Rcp_ResetRenderState();
    }
}

void waterfx_run(int frames) {
    int i;
    for (i = 0; i < WATERFX_POOL_SIZE; i++) {
        WaterCircularRipple* e = &gWaterfxRipplePool[i];
        if (e->alpha != 0) {
            e->scale += WATERFX_RIPPLE_GROW_SPEED * timeDelta;
            e->alpha = (s16)(e->alpha - framesThisStep * e->fadeRate);
            if (e->alpha < 0) {
                e->alpha = 0;
                gWaterfxRippleCount--;
            }
        }
    }
    for (i = 0; i < WATERFX_POOL_SIZE; i++) {
        WaterMovementRipple* g = &gWaterfxWakePool[i];
        if (g->alpha != 0) {
            g->scale += WATERFX_WAKE_GROW_SPEED * timeDelta;
            g->alpha = (s16)(g->alpha - framesThisStep * 2);
            if (g->alpha < 0) {
                g->alpha = 0;
                gWaterfxWakeCount--;
            }
        }
    }
    {
        for (i = 0; i < WATERFX_MAX_SPLASHES; i++) {
            WaterSplashBurst* s = &gWaterfxSplashPool[i];
            if (s->life < 1.0f) {
                s->life += s->lifeSpeed * timeDelta;
                if (s->life >= 1.0f) {
                    gWaterfxSplashCount--;
                }
            }
        }
    }
    for (i = 0; i < WATERFX_POOL_SIZE; i++) {
        WaterSplashBurst* wp;
        WaterSplashDrop* d = &gWaterfxDropPool[i];
        if (d->parentIdx != -1) {
            wp = &gWaterfxSplashPool[d->parentIdx];
            d->vy += WATERFX_DROP_GRAVITY * timeDelta;
            d->vx *= WATERFX_DROP_DAMPING;
            d->vy *= WATERFX_DROP_DAMPING;
            d->vz *= WATERFX_DROP_DAMPING;
            d->x += d->vx;
            d->y += d->vy;
            d->z += d->vz;
            if (d->y < wp->y) {
                wp->dropCount--;
                d->parentIdx = -1;
                gWaterfxDropCount--;
                gWaterfxRippleScale = WATERFX_DROP_RIPPLE_SCALE;
                waterfx_spawnCircularRipple(d->x, wp->y, d->z, 0, WATERFX_ZERO, 8);
            }
        }
    }
}

/*
 * Per-frame water-impact entry from a limb-bearing object. For every set bit
 * in limbMask it spawns a ripple at the corresponding impact position (and, in
 * shallow water when the object is moving fast enough, a splash burst), then
 * records that impact for waterfx_consumePendingImpactNearPoint to query.
 *
 * Ripple height is the object's local Y plus the collision query's water
 * depth. impactPositions contains one world-space vec3 per limb.
 */
void waterfx_spawnImpactSurface(GameObject* obj, u16 limbMask, Vec* impactPositions, ObjCollisionState* collision,
                                f32 speed) {
    ObjCollisionState* surf = collision;
    Vec* pos = impactPositions;
    while (limbMask != 0) {
        if (limbMask & 1) {
            f32 px = pos->x;
            f32 pz = pos->z;
            if (surf->resultWaterDepth < WATERFX_SHALLOW_DEPTH) {
                if (speed > WATERFX_SPLASH_SPEED_THRESHOLD) {
                    waterfx_spawnSplashBurst(obj, px, obj->anim.localPosY + surf->resultWaterDepth, pz, WATERFX_ZERO);
                }
            }
            gWaterfxRippleScale = WATERFX_DEFAULT_SCALE;
            waterfx_spawnCircularRipple(px, obj->anim.localPosY + surf->resultWaterDepth, pz, obj->anim.rotX,
                                        WATERFX_ZERO, 4);
            gWaterfxPendingImpactPosition[0] = px;
            gWaterfxPendingImpactPosition[1] = obj->anim.localPosY + surf->resultWaterDepth;
            gWaterfxPendingImpactPosition[2] = pz;
            gWaterfxPendingImpactPositionValid = 1;
        }
        limbMask >>= 1;
        pos++;
    }
}

void waterfx_onMapSetup(void) {
    int i;
    LightmapTriangle* vd;
    {
        vd = gWaterfxRippleTriangles;
        for (i = 0; i < WATERFX_POOL_SIZE; i++) {
            WaterCircularRipple* e;
            vd[0].vertexIndices[0] = 3;
            vd[0].vertexIndices[1] = 1;
            vd[0].vertexIndices[2] = 0;
            vd[1].vertexIndices[0] = 3;
            vd[1].vertexIndices[1] = 2;
            vd[1].vertexIndices[2] = 1;
            vd += 2;
            e = &gWaterfxRipplePool[i];
            e->x = 0.0f;
            e->y = 0.0f;
            e->z = 0.0f;
            e->unknown0C = 0.0f;
            e->scale = 0.01f;
            e->alpha = 0;
        }
    }
    {
        f32 initThreshold;
        f32 initPos;
        initPos = WATERFX_ZERO;
        initThreshold = 1.0f;
        for (i = 0; i < WATERFX_MAX_SPLASHES; i++) {
            WaterSplashBurst* s = &gWaterfxSplashPool[i];
            s->x = initPos;
            s->y = initPos;
            s->z = initPos;
            s->life = initThreshold;
            s->dropCount = 0;
        }
    }
    {
        f32 initScale;
        f32 initPos;
        vd = gWaterfxWakeTriangles;
        initPos = WATERFX_ZERO;
        initScale = WATERFX_DEFAULT_SCALE;
        for (i = 0; i < WATERFX_POOL_SIZE; i++) {
            WaterMovementRipple* g;
            vd[0].vertexIndices[0] = 3;
            vd[0].vertexIndices[1] = 1;
            vd[0].vertexIndices[2] = 0;
            vd[1].vertexIndices[0] = 3;
            vd[1].vertexIndices[1] = 2;
            vd[1].vertexIndices[2] = 1;
            vd += 2;
            g = &gWaterfxWakePool[i];
            g->x = initPos;
            g->y = initPos;
            g->z = initPos;
            g->unknown0C = initPos;
            g->scale = initScale;
            g->alpha = 0;
            g->yaw = 0;
        }
    }
    {
        f32 initPos = WATERFX_ZERO;
        for (i = 0; i < WATERFX_POOL_SIZE; i++) {
            WaterSplashDrop* d = &gWaterfxDropPool[i];
            d->parentIdx = -1;
            d->vx = initPos;
            d->vy = initPos;
            d->vz = initPos;
            d->x = initPos;
            d->y = initPos;
            d->z = initPos;
        }
    }
}

void waterfx_release(void) {
    if (gWaterfxRippleTriangles != NULL) {
        mm_free(gWaterfxRippleTriangles);
    }
    if (gWaterfxRippleTexture != NULL) {
        textureFree(gWaterfxRippleTexture);
        gWaterfxRippleTexture = NULL;
    }
    if (gWaterfxSplashTexture0 != NULL) {
        textureFree(gWaterfxSplashTexture0);
        gWaterfxSplashTexture0 = NULL;
    }
    if (gWaterfxSplashTexture1 != NULL) {
        textureFree(gWaterfxSplashTexture1);
        gWaterfxSplashTexture1 = NULL;
    }
    if (gWaterfxWakeTexture != NULL) {
        textureFree(gWaterfxWakeTexture);
        gWaterfxWakeTexture = NULL;
    }
    if (gWaterfxSplashDisplayList != NULL) {
        mm_free(gWaterfxSplashDisplayList);
        gWaterfxSplashDisplayList = NULL;
    }
    if (gWaterfxSplashPosArray != NULL) {
        mm_free(gWaterfxSplashPosArray);
        gWaterfxSplashPosArray = NULL;
    }
    if (gWaterfxSplashTexCoordArray != NULL) {
        mm_free(gWaterfxSplashTexCoordArray);
        gWaterfxSplashTexCoordArray = NULL;
    }
}

void waterfx_initialise(void) {
    u8* memory;

    memory = mmAlloc(sizeof(WaterfxStorage), 0x13, 0);
    if (memory == NULL) {
        debugPrintf(sWaterfxDllAllocFailed);
        return;
    }
    gWaterfxRippleTriangles = (LightmapTriangle*)memory;
    gWaterfxWakeTriangles = (LightmapTriangle*)(memory + sizeof(LightmapTriangle) * WATERFX_POOL_SIZE * 2);
    {
        u8* vertices = memory + offsetof(WaterfxStorage, rippleVertices);
        u8* particles;
        gWaterfxRippleVertices = (LightmapVertex*)vertices;
        gWaterfxWakeVertices = (LightmapVertex*)(vertices + sizeof(LightmapVertex) * WATERFX_POOL_SIZE * 4);
        particles = vertices + sizeof(LightmapVertex) * WATERFX_POOL_SIZE * 8;
        gWaterfxRipplePool = (WaterCircularRipple*)particles;
        gWaterfxSplashPool = (WaterSplashBurst*)(particles + sizeof(WaterCircularRipple) * WATERFX_POOL_SIZE);
        gWaterfxDropPool = (WaterSplashDrop*)(particles + sizeof(WaterCircularRipple) * WATERFX_POOL_SIZE +
                                              sizeof(WaterSplashBurst) * WATERFX_MAX_SPLASHES);
        gWaterfxWakePool = (WaterMovementRipple*)(particles + sizeof(WaterCircularRipple) * WATERFX_POOL_SIZE +
                                                  sizeof(WaterSplashBurst) * WATERFX_MAX_SPLASHES +
                                                  sizeof(WaterSplashDrop) * WATERFX_POOL_SIZE);
    }
    gWaterfxRippleCount = 0;
    gWaterfxSplashCount = 0;
    gWaterfxDropCount = 0;
    gWaterfxWakeCount = 0;
    gWaterfxRippleTexture = textureLoadAsset(WATERFX_TEXTURE_RIPPLE);
    gWaterfxSplashTexture0 = textureLoadAsset(WATERFX_TEXTURE_SPLASH0);
    gWaterfxSplashTexture1 = textureLoadAsset(WATERFX_TEXTURE_SPLASH1);
    gWaterfxWakeTexture = textureLoadAsset(WATERFX_TEXTURE_WAKE);
    waterfx_onMapSetup();
    waterfx_buildSplashDisplayList();
}

WaterfxDescriptor gWaterfxDescriptor = {
    {0, 0, 0},
    0x000A0000,
    waterfx_initialise,
    waterfx_release,
    {
        0,
        waterfx_run,
        waterfx_spawnImpactSurface,
        waterfx_render,
        waterfx_spawnSplashBurst,
        waterfx_spawnCircularRipple,
        waterfx_spawnMovementRipple,
        waterfx_onMapSetup,
        waterfx_setRippleScale,
    },
};

char sWaterfxDllAllocFailed[] = "Could not allocate memory for waterfx dll\n";
