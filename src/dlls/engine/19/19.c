#include "main/dll/waterfx.h"
#include "main/dll/curves_collision_state.h"
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
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
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

u8* gWaterfxRippleVtx;
u8* gWaterfxRippleVtxDesc;
u8* gWaterfxWakeVtx;
u8* gWaterfxWakeVtxDesc;
int gWaterfxRippleCount;
u8* gWaterfxRipplePool;
int gWaterfxSplashCount;
u8* gWaterfxSplashPool;
int gWaterfxWakeCount;
u8* gWaterfxWakePool;
int gWaterfxDropCount;
u8* gWaterfxDropPool;
Texture* gWaterfxRippleTexture;
Texture* gWaterfxSplashTexture0;
Texture* gWaterfxSplashTexture1;
Texture* gWaterfxWakeTexture;
f32 gWaterfxRippleScale;
void* gWaterfxSplashDisplayList;
u16 gWaterfxSplashDisplayListSize;
void* gWaterfxSplashPosArray;
void* gWaterfxSplashTexCoordArray;
u8 gWaterfxPendingImpactPositionValid;

f32 gWaterfxPendingImpactPosition[4];

volatile PPCWGPipe GXWGFifo : (0xCC008000);

#define WATERFX_POOL_SIZE    30
#define WATERFX_MAX_SPLASHES 10

#define WATERFX_TEXTURE_RIPPLE  0x56  /* gWaterfxRippleTexture */
#define WATERFX_TEXTURE_SPLASH0 0xc2a /* gWaterfxSplashTexture0 */
#define WATERFX_TEXTURE_SPLASH1 0xc2c /* gWaterfxSplashTexture1 */
#define WATERFX_TEXTURE_WAKE    0xc2d /* gWaterfxWakeTexture */


#define WATERFX_PHASE_START             0.100000024f
#define WATERFX_BAND_OFFSET_SCALE       0.9f
#define WATERFX_RIPPLE_FADE_RATE        0.5f
#define WATERFX_ONE                     1.0f
#define WATERFX_FADE_CURVE_SCALE        4.0f
#define WATERFX_BAND_LIMIT_BASE         0.05f
#define WATERFX_BAND_COUNT              7.0f
#define WATERFX_SPLASH_SIZE_SCALE       2.0f
#define WATERFX_ZERO                    0.0f
#define WATERFX_ALPHA_MAX               255.0f
#define WATERFX_PI                      3.142f
#define WATERFX_RING_SEGMENT_MAX        15.0f
#define WATERFX_DEFAULT_SCALE           0.01f
#define WATERFX_SPLASH_VELOCITY_SCALE   3.0f
#define WATERFX_SPLASH_LIFETIME_SCALE   16.0f
#define WATERFX_RIPPLE_GROW_SPEED       0.001f
#define WATERFX_WAKE_GROW_SPEED         0.004f
#define WATERFX_DROP_GRAVITY            -0.05f
#define WATERFX_DROP_DAMPING            0.97f
#define WATERFX_DROP_RIPPLE_SCALE       0.005f
#define WATERFX_SHALLOW_DEPTH           10.0f
#define WATERFX_SPLASH_SPEED_THRESHOLD  0.25f

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
 * and writes that band's per-vertex alpha into the color array (s->vtxColors).
 * The completed geometry is drawn twice (front then back cull) via the shared
 * display list.
 */
void waterfx_drawSplashBurst(WaterParticle* s)
{
    Mtx mtxD;
    Mtx scale;
    Mtx mtxB;
    Mtx mtxC;
    int mtxIdx;
    u8* colorOut;
    int i;

    PSMTXScale(scale, s->size, s->size, s->size);
    i = 0;
    mtxIdx = 0;
    colorOut = (u8*)s;
    for (; i < 8; i++)
    {
        f32 bandPhase;
        f32 ph;
        f32 life = s->life;
        f32 dd;
        f32 lim;
        f32 sc;
        f32 fade;
        f32 alpha;
        bandPhase = WATERFX_PHASE_START + WATERFX_BAND_OFFSET_SCALE * ((f32)i / WATERFX_BAND_COUNT);
        ph = bandPhase * life;
        dd = ph - 0.5f;
        fade = -(WATERFX_FADE_CURVE_SCALE * (dd * dd) - 1.0f);
        lim = WATERFX_BAND_LIMIT_BASE + WATERFX_BAND_OFFSET_SCALE * ((f32)i / WATERFX_BAND_COUNT);
        if (life < lim)
        {
            alpha = 1.0f;
        }
        else
        {
            alpha = (1.0f - life) / (1.0f - lim);
        }
        sc = 2.0f * ph + 1.0f;
        PSMTXScale(mtxB, sc, 1.0f, sc);
        PSMTXTrans(mtxC, 0.0f, 2.0f * fade, 0.0f);
        PSMTXConcat(mtxC, mtxB, mtxD);
        PSMTXConcat(scale, mtxD, mtxD);
        PSMTXTrans(mtxC, s->x - playerMapOffsetX, s->y, s->z - playerMapOffsetZ);
        PSMTXConcat(mtxC, mtxD, mtxD);
        PSMTXConcat((MtxPtr)Camera_GetViewMatrix(), mtxD, mtxD);
        GXLoadPosMtxImm(mtxD, mtxIdx);
        *(u32*)(colorOut + 0x18) = (u8)(int)(WATERFX_ALPHA_MAX * alpha);
        mtxIdx += 3;
        colorOut += 4;
    }
    DCStoreRange(s->vtxColors, 32);
    GXSetArray(GX_VA_CLR0, s->vtxColors, 4);
    GXSetCullMode(GX_CULL_FRONT);
    GXCallDisplayList(gWaterfxSplashDisplayList, gWaterfxSplashDisplayListSize);
    GXSetCullMode(GX_CULL_BACK);
    GXCallDisplayList(gWaterfxSplashDisplayList, gWaterfxSplashDisplayListSize);
}

static void waterfx_buildSplashDisplayList(void) {
    int m;
    f32* pos;
    int i;
    int j;
    int k;
    void* dl;
    u8 a[1];

    GXSetMisc(GX_MT_XF_FLUSH, 0);
    gWaterfxSplashPosArray = mmAlloc(192, 0, 0);
    gWaterfxSplashTexCoordArray = mmAlloc(1024, 0, 0);
    for (i = 0; i < 8; i++) {
        for (j = 0; j < 16; j++) {
            if (i == 0) {
                f32 ang;
                f32 sv;
                f32 cv;
                pos = (f32*)((u8*)gWaterfxSplashPosArray + j * 12);
                ang = WATERFX_PI * (f32)(j * 2) / WATERFX_RING_SEGMENT_MAX;
                sv = mathCosfPrecise(ang);
                cv = mathSinfPrecise(ang);
                pos[0] = sv;
                pos[1] = WATERFX_ZERO;
                pos[2] = cv;
            }
            {
                int idx = i * 16 + j;
                f32* tex = (f32*)((u8*)gWaterfxSplashTexCoordArray + idx * 8);
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
    a[0] = 0;
    for (k = 0; k < 15; k++) {
        GXBegin(GX_TRIANGLESTRIP, GX_VTXFMT2, 16);
        for (m = 7; m >= 0; m--) {
            a[0] = m * 3;
            GXWGFifo.u8 = a[0];
            GXWGFifo.u8 = a[0];
            GXWGFifo.u16 = k;
            GXWGFifo.u16 = m;
            GXWGFifo.u16 = m * 16 + k;
            GXWGFifo.u8 = a[0];
            GXWGFifo.u8 = a[0];
            GXWGFifo.u16 = (k + 1) % 16;
            GXWGFifo.u16 = m;
            GXWGFifo.u16 = m * 16 + (k + 1) % 16;
        }
    }
    gWaterfxSplashDisplayListSize = GXEndDisplayList();
    GXSetMisc(GX_MT_XF_FLUSH, 8);
}

int waterfx_consumePendingImpactNearPoint(f32* vec, f32 dist)
{
    if (gWaterfxPendingImpactPositionValid != 0 &&
        PSVECSquareDistance((Vec*)vec, (Vec*)gWaterfxPendingImpactPosition) < dist * dist)
    {
        gWaterfxPendingImpactPositionValid = 0;
        return 1;
    }
    gWaterfxPendingImpactPositionValid = 0;
    return 0;
}

void waterfx_spawnRipple(f32 x, f32 y, f32 z, s16 rotParam, f32 w, int intensity)
{
    int i = 0;
    WaterEntry7* p = (WaterEntry7*)gWaterfxRipplePool;
    WaterVtx* q;
    WaterEntry7* e;
    int j;
    while (i < WATERFX_POOL_SIZE && p->active != 0)
    {
        p++;
        i++;
    }
    if (i >= WATERFX_POOL_SIZE)
    {
        return;
    }
    j = i * 4;
    q = &((WaterVtx*)gWaterfxRippleVtx)[j];
    q->x = -300;
    q->y = 0;
    q->z = 300;
    q->a = 0xff;
    q->u = 0;
    q->v = 0;
    q = &((WaterVtx*)gWaterfxRippleVtx)[j + 1];
    q->x = -300;
    q->y = 0;
    q->z = -300;
    q->a = 0xff;
    q->u = 0;
    q->v = 0x7f;
    q = &((WaterVtx*)gWaterfxRippleVtx)[j + 2];
    q->x = 300;
    q->y = 0;
    q->z = -300;
    q->a = 0xff;
    q->u = 0x7f;
    q->v = 0x7f;
    q = &((WaterVtx*)gWaterfxRippleVtx)[j + 3];
    q->x = 300;
    q->y = 0;
    q->z = 300;
    q->a = 0xff;
    q->u = 0x7f;
    q->v = 0;
    e = (WaterEntry7*)gWaterfxRipplePool;
    e[i].w = w;
    e = (WaterEntry7*)gWaterfxRipplePool;
    e[i].active = 0xff;
    e = (WaterEntry7*)gWaterfxRipplePool;
    e[i].x = x;
    e = (WaterEntry7*)gWaterfxRipplePool;
    e[i].y = y;
    e = (WaterEntry7*)gWaterfxRipplePool;
    e[i].z = z;
    e = (WaterEntry7*)gWaterfxRipplePool;
    e[i].rot = rotParam;
    e = (WaterEntry7*)gWaterfxRipplePool;
    e[i].scale = gWaterfxRippleScale;
    e = (WaterEntry7*)gWaterfxRipplePool;
    e[i].fadeRate = WATERFX_RIPPLE_FADE_RATE * intensity;
    gWaterfxRippleCount++;
}

void waterfx_setRippleScale(int flag, f32 val)
{
    if (flag != 0)
    {
        val = WATERFX_DEFAULT_SCALE;
    }
    gWaterfxRippleScale = val;
}

void waterfx_spawnSimpleRipple(f32 x, f32 y, f32 z, s16 id, f32 w)
{
    int i = 0;
    WaterEntry* p = (WaterEntry*)gWaterfxWakePool;
    WaterVtx* q;
    WaterEntry* entry;
    int j;
    while (i < WATERFX_POOL_SIZE && p->active != 0)
    {
        p++;
        i++;
    }
    if (i >= WATERFX_POOL_SIZE)
    {
        return;
    }
    j = i * 4;
    q = &((WaterVtx*)gWaterfxWakeVtx)[j];
    q[0].x = -200;
    q[0].y = 0;
    q[0].z = 400;
    q[0].a = 0xff;
    q[0].u = 0;
    q[0].v = 0;
    q[1].x = -200;
    q[1].y = 0;
    q[1].z = -200;
    q[1].a = 0xff;
    q[1].u = 0;
    q[1].v = 0x80;
    q[2].x = 200;
    q[2].y = 0;
    q[2].z = -200;
    q[2].a = 0xff;
    q[2].u = 0x80;
    q[2].v = 0x80;
    q[3].x = 200;
    q[3].y = 0;
    q[3].z = 400;
    q[3].a = 0xff;
    q[3].u = 0x80;
    q[3].v = 0;
    entry = (WaterEntry*)gWaterfxWakePool + i;
    entry->x = x;
    entry->y = y;
    entry->z = z;
    entry->w = w;
    entry->scale = WATERFX_DEFAULT_SCALE;
    entry->active = 0xff;
    entry->rot = id;
    entry->f18 = 0;
    gWaterfxWakeCount++;
}


void waterfx_spawnSplashBurst(void* obj, f32 a, f32 b, f32 c, f32 d)
{
    WaterParticle* p;
    int i;
    WaterParticle* base;
    WaterParticle* slot;
    int rnd;
    if (WATERFX_ZERO == d)
    {
        d = WATERFX_SPLASH_VELOCITY_SCALE;
    }
    i = 0;
    base = (WaterParticle*)gWaterfxSplashPool;
    p = base;
    while (i < WATERFX_MAX_SPLASHES && (p->dropCount != 0 || p->life < 1.0f))
    {
        p++;
        i++;
    }
    if (i >= WATERFX_MAX_SPLASHES)
    {
        return;
    }
    slot = &base[i];
    slot->x = a;
    slot->y = b;
    slot->z = c;
    gWaterfxSplashCount++;
    slot->size = d;
    rnd = randomGetRange((int)slot->size, (int)(WATERFX_SPLASH_SIZE_SCALE * slot->size));
    slot->dropCount = waterfx_spawnSplashDrops(&((WaterParticle*)gWaterfxSplashPool)[i], i, rnd, slot->size);
    slot->life = WATERFX_ZERO;
    slot->lifeSpeed = 1.0f / (WATERFX_SPLASH_LIFETIME_SCALE * sqrtf(slot->size));
}

int waterfx_spawnSplashDrops(WaterParticle* src, int idx, int count, f32 v)
{
    int cur;
    f32 scale;
    WaterDrop* p;
    WaterDrop* base;
    WaterDrop* slot;
    int j;
    int i;
    cur = gWaterfxDropCount;
    if (count + cur > WATERFX_POOL_SIZE)
    {
        count = WATERFX_POOL_SIZE - cur;
    }
    if (count != 0)
    {
        i = 0;
        scale = WATERFX_RIPPLE_GROW_SPEED * v;
        for (; i < count; i++)
        {
            j = 0;
            base = (WaterDrop*)gWaterfxDropPool;
            p = base;
            while (j < WATERFX_POOL_SIZE && p->parentIdx != -1)
            {
                p++;
                j++;
            }
            if (j < WATERFX_POOL_SIZE)
            {
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

void waterfx_render(int obj, int renderParam)
{
    int poolOffset;
    int descriptorOffset;
    WaterEntry7* e;
    WaterParticle* s;
    WaterDrop* d;
    WaterEntry* g;
    int i;
    int vertexOffset;
    int j;
    f32 thr;
    MatrixTransform dp;
    if (gWaterfxRippleCount != 0 || gWaterfxWakeCount != 0 || gWaterfxSplashCount != 0 ||
        gWaterfxDropCount != 0)
    {
        GXSetCullMode(GX_CULL_NONE);
        if (gWaterfxRippleCount != 0)
        {
            setupReflectionBumpDistortTev(gWaterfxRippleTexture);
        }
        for (i = 0, poolOffset = 0; i < WATERFX_POOL_SIZE; poolOffset += 0x1c, i++)
        {
            e = (WaterEntry7*)(gWaterfxRipplePool + poolOffset);
            if (e->active != 0)
            {
                setTextColor((void*)obj, 0xff, 0xff, 0xff, (u8)e->active);
                dp.x = e->x;
                dp.y = e->y;
                dp.z = e->z;
                dp.scale = e->scale;
                dp.rotX = e->rot;
                dp.rotZ = 0;
                dp.rotY = 0;
                Camera_LoadModelViewMatrix(obj, renderParam, &dp, 1.0f, WATERFX_ZERO,
                                           NULL);
                loadReflectionTexMtxs();
                lightmapDrawTriangleList(gWaterfxRippleVtx + i * 0x40,
                                  gWaterfxRippleVtxDesc + i * 0x20, 2);
            }
        }
        j = 0;
        if (gWaterfxSplashCount != 0)
        {
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
        for (poolOffset = 0, thr = 1.0f; j < WATERFX_MAX_SPLASHES; poolOffset += 0x3c, j++)
        {
            s = (WaterParticle*)(gWaterfxSplashPool + poolOffset);
            if (s->life < thr)
            {
                waterfx_drawSplashBurst(s);
            }
        }
        if (gWaterfxDropCount != 0)
        {
            waterfx_setupSplashDropPointRender();
        }
        for (i = 0, poolOffset = 0; i < WATERFX_POOL_SIZE; poolOffset += 0x1c, i++)
        {
            d = (WaterDrop*)(gWaterfxDropPool + poolOffset);
            if (d->parentIdx != -1)
            {
                f32 vx, vy, vz;
                GXBegin(GX_POINTS, GX_VTXFMT2, 1);
                vz = d->z - playerMapOffsetZ;
                vy = d->y;
                vx = d->x - playerMapOffsetX;
                GXWGFifo.f32 = vx;
                GXWGFifo.f32 = vy;
                GXWGFifo.f32 = vz;
            }
        }
        if (gWaterfxWakeCount != 0)
        {
            setupReflectionDistortTev(gWaterfxWakeTexture);
        }
        for (poolOffset = 0, j = 0, descriptorOffset = 0, vertexOffset = 0;
             j < WATERFX_POOL_SIZE;
             j++, descriptorOffset += 0x20, poolOffset += 0x1c, vertexOffset += 0x40)
        {
            g = (WaterEntry*)(gWaterfxWakePool + poolOffset);
            if (g->active != 0 && g->f18 == 0)
            {
                setTextColor((void*)obj, 0xff, 0xff, 0xff, (u8)g->active);
                dp.x = g->x;
                dp.y = g->y;
                dp.z = g->z;
                dp.scale = g->scale;
                dp.rotX = g->rot;
                dp.rotZ = 0;
                dp.rotY = 0;
                Camera_LoadModelViewMatrix(obj, renderParam, &dp, 1.0f, WATERFX_ZERO,
                                           NULL);
                loadReflectionTexMtxs();
                lightmapDrawTriangleList(gWaterfxWakeVtx + vertexOffset,
                                  gWaterfxWakeVtxDesc + descriptorOffset, 2);
            }
        }
        Rcp_ResetRenderState();
    }
}

void waterfx_run(int frames)
{
    int i;
    for (i = 0; i < WATERFX_POOL_SIZE; i++)
    {
        WaterEntry7* e = &((WaterEntry7*)gWaterfxRipplePool)[i];
        if (e->active != 0)
        {
            e->scale += WATERFX_RIPPLE_GROW_SPEED * timeDelta;
            e->active = (s16)(e->active - framesThisStep * e->fadeRate);
            if (e->active < 0)
            {
                e->active = 0;
                gWaterfxRippleCount--;
            }
        }
    }
    for (i = 0; i < WATERFX_POOL_SIZE; i++)
    {
        WaterEntry* g = &((WaterEntry*)gWaterfxWakePool)[i];
        if (g->active != 0)
        {
            g->scale += WATERFX_WAKE_GROW_SPEED * timeDelta;
            g->active = (s16)(g->active - framesThisStep * 2);
            if (g->active < 0)
            {
                g->active = 0;
                gWaterfxWakeCount--;
            }
        }
    }
    {
        for (i = 0; i < WATERFX_MAX_SPLASHES; i++)
        {
            WaterParticle* s = &((WaterParticle*)gWaterfxSplashPool)[i];
            if (s->life < 1.0f)
            {
                s->life += s->lifeSpeed * timeDelta;
                if (s->life >= 1.0f)
                {
                    gWaterfxSplashCount--;
                }
            }
        }
    }
    for (i = 0; i < WATERFX_POOL_SIZE; i++)
    {
        WaterParticle* wp;
        WaterDrop* d = &((WaterDrop*)gWaterfxDropPool)[i];
        if (d->parentIdx != -1)
        {
            wp = &((WaterParticle*)gWaterfxSplashPool)[d->parentIdx];
            d->vy += WATERFX_DROP_GRAVITY * timeDelta;
            d->vx *= WATERFX_DROP_DAMPING;
            d->vy *= WATERFX_DROP_DAMPING;
            d->vz *= WATERFX_DROP_DAMPING;
            d->x += d->vx;
            d->y += d->vy;
            d->z += d->vz;
            if (d->y < wp->y)
            {
                wp->dropCount--;
                d->parentIdx = -1;
                gWaterfxDropCount--;
                gWaterfxRippleScale = WATERFX_DROP_RIPPLE_SCALE;
                waterfx_spawnRipple(d->x, wp->y, d->z, 0, WATERFX_ZERO, 8);
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
void waterfx_spawnImpactSurface(u8* objHeader, u16 limbMask, f32* impactPositions, CurvesCollisionState* collision,
                                f32 speed) {
    CurvesCollisionState* surf = collision;
    f32* pos = impactPositions;
    while (limbMask != 0) {
        if (limbMask & 1) {
            f32 px = pos[0];
            f32 pz = pos[2];
            if (surf->resultWaterDepth < WATERFX_SHALLOW_DEPTH) {
                if (speed > WATERFX_SPLASH_SPEED_THRESHOLD) {
                    waterfx_spawnSplashBurst(objHeader, px,
                                             ((GameObject*)objHeader)->anim.localPosY + surf->resultWaterDepth, pz,
                                             WATERFX_ZERO);
                }
            }
            gWaterfxRippleScale = WATERFX_DEFAULT_SCALE;
            waterfx_spawnRipple(px, ((GameObject*)objHeader)->anim.localPosY + surf->resultWaterDepth, pz,
                                ((GameObject*)objHeader)->anim.rotX, WATERFX_ZERO, 4);
            gWaterfxPendingImpactPosition[0] = px;
            gWaterfxPendingImpactPosition[1] = ((GameObject*)objHeader)->anim.localPosY + surf->resultWaterDepth;
            gWaterfxPendingImpactPosition[2] = pz;
            gWaterfxPendingImpactPositionValid = 1;
        }
        limbMask >>= 1;
        pos += 3;
    }
}

void waterfx_onMapSetup(void)
{
    int i;
    WaterVtxDesc* vd;
    {
        vd = (WaterVtxDesc*)gWaterfxRippleVtxDesc;
        for (i = 0; i < WATERFX_POOL_SIZE; i++)
        {
            WaterEntry7* e;
            vd[0].b1 = 3;
            vd[0].b2 = 1;
            vd[0].b3 = 0;
            vd[1].b1 = 3;
            vd[1].b2 = 2;
            vd[1].b3 = 1;
            vd += 2;
            e = &((WaterEntry7*)gWaterfxRipplePool)[i];
            e->x = 0.0f;
            e->y = 0.0f;
            e->z = 0.0f;
            e->w = 0.0f;
            e->scale = 0.01f;
            e->active = 0;
        }
    }
    {
        f32 initThreshold;
        f32 initPos;
        initPos = WATERFX_ZERO;
        initThreshold = 1.0f;
        for (i = 0; i < WATERFX_MAX_SPLASHES; i++)
        {
            WaterParticle* s = &((WaterParticle*)gWaterfxSplashPool)[i];
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
        vd = (WaterVtxDesc*)gWaterfxWakeVtxDesc;
        initPos = WATERFX_ZERO;
        initScale = WATERFX_DEFAULT_SCALE;
        for (i = 0; i < WATERFX_POOL_SIZE; i++)
        {
            WaterEntry* g;
            vd[0].b1 = 3;
            vd[0].b2 = 1;
            vd[0].b3 = 0;
            vd[1].b1 = 3;
            vd[1].b2 = 2;
            vd[1].b3 = 1;
            vd += 2;
            g = &((WaterEntry*)gWaterfxWakePool)[i];
            g->x = initPos;
            g->y = initPos;
            g->z = initPos;
            g->w = initPos;
            g->scale = initScale;
            g->active = 0;
            g->rot = 0;
        }
    }
    {
        f32 initPos = WATERFX_ZERO;
        for (i = 0; i < WATERFX_POOL_SIZE; i++)
        {
            WaterDrop* d = &((WaterDrop*)gWaterfxDropPool)[i];
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

void waterfx_release(void)
{
    if (gWaterfxRippleVtxDesc != NULL)
    {
        mm_free(gWaterfxRippleVtxDesc);
    }
    if (gWaterfxRippleTexture != NULL)
    {
        textureFree((Texture*)((u8*)gWaterfxRippleTexture));
        gWaterfxRippleTexture = NULL;
    }
    if (gWaterfxSplashTexture0 != NULL)
    {
        textureFree((Texture*)((u8*)gWaterfxSplashTexture0));
        gWaterfxSplashTexture0 = NULL;
    }
    if (gWaterfxSplashTexture1 != NULL)
    {
        textureFree((Texture*)((u8*)gWaterfxSplashTexture1));
        gWaterfxSplashTexture1 = NULL;
    }
    if (gWaterfxWakeTexture != NULL)
    {
        textureFree((Texture*)((u8*)gWaterfxWakeTexture));
        gWaterfxWakeTexture = NULL;
    }
    if (gWaterfxSplashDisplayList != NULL)
    {
        mm_free(gWaterfxSplashDisplayList);
        gWaterfxSplashDisplayList = NULL;
    }
    if (gWaterfxSplashPosArray != NULL)
    {
        mm_free(gWaterfxSplashPosArray);
        gWaterfxSplashPosArray = NULL;
    }
    if (gWaterfxSplashTexCoordArray != NULL)
    {
        mm_free(gWaterfxSplashTexCoordArray);
        gWaterfxSplashTexCoordArray = NULL;
    }
}

void waterfx_initialise(void)
{
    u8* buf;

    buf = mmAlloc(0x22b0, 0x13, 0);
    if (buf == NULL)
    {
        debugPrintf(sWaterfxDllAllocFailed);
        return;
    }
    gWaterfxRippleVtxDesc = buf;
    gWaterfxWakeVtxDesc = buf + 0x3c0;
    {
        u8* p2 = buf + 0x780;
        u8* p3;
        gWaterfxRippleVtx = p2;
        gWaterfxWakeVtx = p2 + 0x780;
        p3 = p2 + 0xf00;
        gWaterfxRipplePool = p3;
        gWaterfxSplashPool = p3 + 0x348;
        gWaterfxDropPool = p3 + 0x5a0;
        gWaterfxWakePool = p3 + 0x8e8;
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

ResourceDescriptorCallbacks11 waterfx_funcs = {
    {0x00000000, 0x00000000, 0x00000000, 0x000a0000},
    {(ResourceDescriptorCallback)waterfx_initialise,
     (ResourceDescriptorCallback)waterfx_release,
     0x00000000,
     (ResourceDescriptorCallback)waterfx_run,
     (ResourceDescriptorCallback)waterfx_spawnImpactSurface,
     (ResourceDescriptorCallback)waterfx_render,
     (ResourceDescriptorCallback)waterfx_spawnSplashBurst,
     (ResourceDescriptorCallback)waterfx_spawnRipple,
     (ResourceDescriptorCallback)waterfx_spawnSimpleRipple,
     (ResourceDescriptorCallback)waterfx_onMapSetup,
     (ResourceDescriptorCallback)waterfx_setRippleScale}};

char sWaterfxDllAllocFailed[] = "Could not allocate memory for waterfx dll\n";
