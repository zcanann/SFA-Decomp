/*
 * waterfx (DLL 0x13) - water surface impact effects.
 *
 * Maintains four particle pools allocated as one block in
 * waterfx_initialise: ripple quads (WaterEntry7, gWaterfxRipplePool, up to 30),
 * a second ripple/wake pool (WaterEntry, gWaterfxWakePool, up to 30), splash
 * bursts (WaterParticle, gWaterfxSplashPool, up to 10) and the individual splash
 * drops thrown by each burst (WaterDrop, gWaterfxDropPool, up to 30). Counts of
 * live entries are tracked in the lbl_803DD2xx pointer-sized counters.
 *
 * waterfx_func04 is the per-frame entry from a water surface: for each set
 * bit in the limb mask it spawns a ripple (and, when the surface is shallow
 * and the speed is high enough, a splash burst) and records a pending impact
 * position that waterfx_consumePendingImpactNearPoint can query. waterfx_run
 * advances all pools each tick; waterfx_func05 renders them. Drops that fall
 * below their parent particle's surface spawn a fresh ripple.
 *
 * Tunables live in the lbl_803DF2xx/lbl_803DF3xx config block; the splash
 * point-sprite render state is built in waterfx_setupSplashDropPointRender.
 */
#include "main/dll/fx_800944A0_shared.h"
#include "dolphin/os/OSCache.h"

volatile PPCWGPipe GXWGFifo : (0xCC008000);

#define WATERFX_POOL_SIZE 30
#define WATERFX_MAX_SPLASHES 10

extern void PSMTXScale(f32* m, f32 x, f32 y, f32 z);
extern void PSMTXTrans(f32* m, f32 x, f32 y, f32 z);
extern void PSMTXConcat(void* a, void* b, void* ab);
extern void GXCallDisplayList(void* list, u32 nbytes);
extern void GXSetMisc(int token, int val);
extern void GXBeginDisplayList(void* list, u32 size);
extern int GXEndDisplayList(void);
extern void GXResetWriteGatherPipe(void);
extern u16 gWaterfxSplashDisplayListSize;
extern const f32 lbl_803DF2E0;
extern f32 lbl_803DF2E4;
extern f32 lbl_803DF2F0;
extern f32 lbl_803DF2F4;
extern const f32 lbl_803DF2F8;
extern const f32 lbl_803DF304;
extern f32 gWaterfxPi;
extern const f32 lbl_803DF314;
extern f32 fn_802942EC(f32);
extern f32 fn_80293F7C(f32);

void waterfx_setupSplashDropPointRender(void)
{
    u8 col[4];
    u8 kcol[4];
    u8 ignoredLightColor;
    GXSetPointSize(0x12, 5);
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXLoadPosMtxImm(Camera_GetViewMatrix(), 0);
    GXSetCurrentMtx(0);
    GXSetTevKColorSel(0, 0xc);
    GXSetTevKAlphaSel(0, 0x1c);
    GXSetNumIndStages(0);
    GXSetNumTexGens(0);
    GXSetNumTevStages(1);
    GXSetNumChans(1);
    GXSetTevDirect(0);
    GXSetTevOrder(0, 0xff, 0xff, 4);
    GXSetTevColorIn(0, 0xf, 0xf, 0xf, 0xe);
    GXSetTevAlphaIn(0, 7, 7, 7, 6);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetBlendMode(1, 4, 5, 5);
    gxSetZMode_(1, 3, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetCullMode(0);
    (*gSkyInterface)->getCurrentAmbientAndLightColors(
        &col[0], &col[1], &col[2], &ignoredLightColor, &ignoredLightColor, &ignoredLightColor);
    col[0] = (col[0] >> 2) + 0x80;
    col[1] = (col[1] >> 2) + 0x80;
    col[2] = (col[2] >> 2) + 0x80;
    col[3] = 0x80;
    *(int*)kcol = *(int*)col;
    GXSetTevKColor(0, kcol);
}

int waterfx_consumePendingImpactNearPoint(f32* vec, f32 dist)
{
    if (gWaterfxPendingImpactPositionValid != 0 &&
        PSVECSquareDistance(vec, gWaterfxPendingImpactPosition) < dist * dist)
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
    WaterEntry7* p = gWaterfxRipplePool;
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
    e = (WaterEntry7*)gWaterfxRipplePool + i;
    e->w = w;
    e = (WaterEntry7*)gWaterfxRipplePool + i;
    e->active = 0xff;
    e = (WaterEntry7*)gWaterfxRipplePool + i;
    e->x = x;
    e = (WaterEntry7*)gWaterfxRipplePool + i;
    e->y = y;
    e = (WaterEntry7*)gWaterfxRipplePool + i;
    e->z = z;
    e = (WaterEntry7*)gWaterfxRipplePool + i;
    e->f14 = rotParam;
    e = (WaterEntry7*)gWaterfxRipplePool + i;
    e->f10 = gWaterfxRippleScale;
    e = (WaterEntry7*)gWaterfxRipplePool + i;
    e->f18 = lbl_803DF2E8 * intensity;
    gWaterfxRippleCount = (void*)((int)gWaterfxRippleCount + 1);
}

void waterfx_setRippleScale(int flag, f32 val)
{
    if (flag != 0)
    {
        val = lbl_803DF318;
    }
    gWaterfxRippleScale = val;
}

void waterfx_func08(s16 p1, f32 a, f32 b, f32 c, f32 d)
{
    int i = 0;
    WaterEntry* p = gWaterfxWakePool;
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
    entry->x = a;
    entry->y = b;
    entry->z = c;
    entry->w = d;
    entry->f10 = lbl_803DF318;
    entry->active = 0xff;
    entry->f16 = p1;
    entry->f18 = 0;
    gWaterfxWakeCount = (void*)((int)gWaterfxWakeCount + 1);
}

#pragma dont_inline on
void waterfx_spawnSplashBurst(void* obj, f32 a, f32 b, f32 c, f32 d)
{
    WaterParticle* p;
    int i;
    WaterParticle* base;
    WaterParticle* slot;
    int rnd;
    if (lbl_803DF300 == d)
    {
        d = lbl_803DF31C;
    }
    i = 0;
    base = gWaterfxSplashPool;
    p = base;
    while (i < WATERFX_MAX_SPLASHES && (p->active != 0 || p->f10 < *(f32 *)&lbl_803DF2EC))
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
    gWaterfxSplashCount = (void*)((int)gWaterfxSplashCount + 1);
    slot->f0c = d;
    rnd = randomGetRange((int)slot->f0c, (int)(lbl_803DF2FC * slot->f0c));
    slot->active = waterfx_spawnSplashDrops(&((WaterParticle*)gWaterfxSplashPool)[i], i, rnd, slot->f0c);
    slot->f10 = lbl_803DF300;
    slot->f14 = lbl_803DF2EC / (lbl_803DF320 * sqrtf(slot->f0c));
}
#pragma dont_inline reset

int waterfx_spawnSplashDrops(WaterParticle* src, int idx, int count, f32 v)
{
    int cur;
    f32 scale;
    WaterDrop* p;
    WaterDrop* base;
    WaterDrop* slot;
    int j;
    int i;
    cur = (int)gWaterfxDropCount;
    if (count + cur > WATERFX_POOL_SIZE)
    {
        count = WATERFX_POOL_SIZE - cur;
    }
    if (count != 0)
    {
        i = 0;
        scale = gWaterfxRippleGrowSpeed * v;
        for (; i < count; i++)
        {
            j = 0;
            base = (WaterDrop*)gWaterfxDropPool;
            p = base;
            while (j < WATERFX_POOL_SIZE && p->idx != -1)
            {
                p++;
                j++;
            }
            if (j < WATERFX_POOL_SIZE)
            {
                slot = &base[j];
                slot->f0c = randomGetRange(-250, 250);
                slot->f0c = slot->f0c * scale;
                slot->f14 = randomGetRange(-250, 250);
                slot->f14 = slot->f14 * scale;
                slot->f10 = randomGetRange(200, 300);
                slot->f10 = slot->f10 * scale;
                slot->idx = idx;
                slot->x = src->x;
                slot->y = src->y;
                slot->z = src->z;
                gWaterfxDropCount = (void*)((int)gWaterfxDropCount + 1);
            }
        }
    }
    return count;
}

void waterfx_func05(int obj, int renderParam)
{
    int i;
    f32 thr;
    WaterDrawObj dp;
    if ((int)gWaterfxRippleCount != 0 || (int)gWaterfxWakeCount != 0 || (int)gWaterfxSplashCount != 0 ||
        (int)gWaterfxDropCount != 0)
    {
        GXSetCullMode(0);
        if ((int)gWaterfxRippleCount != 0)
        {
            fn_8007CAF4((int)gWaterfxRippleTexture);
        }
        {
        int oPool, o32, o64;
        for (i = 0, oPool = 0, o32 = 0, o64 = oPool; i < WATERFX_POOL_SIZE; oPool += 0x1c, o32 += 0x20, o64 += 0x40, i++)
        {
            WaterEntry7* e = (WaterEntry7*)((char*)gWaterfxRipplePool + oPool);
            if (e->active != 0)
            {
                setTextColor(obj, 0xff, 0xff, 0xff, (u8)e->active);
                dp.x = e->x;
                dp.y = e->y;
                dp.z = e->z;
                dp.f10 = e->f10;
                dp.f8 = e->f14;
                dp.fc = 0;
                dp.fa = 0;
                Camera_LoadModelViewMatrix(obj, renderParam, &dp, lbl_803DF2EC, lbl_803DF300, 0);
                fn_8007D670();
                drawFn_8005cf8c((char*)gWaterfxRippleVtx + o64, (char*)gWaterfxRippleVtxDesc + o32, 2);
            }
        }
        }
        if ((int)gWaterfxSplashCount != 0)
        {
            fn_8007BD8C((int)gWaterfxSplashTexture0, (int)gWaterfxSplashTexture1);
            GXSetArray(9, gWaterfxSplashPosArray, 0xc);
            GXSetArray(0xd, gWaterfxSplashTexCoordArray, 8);
            GXClearVtxDesc();
            GXSetVtxDesc(0, 1);
            GXSetVtxDesc(1, 1);
            GXSetVtxDesc(9, 3);
            GXSetVtxDesc(0xb, 3);
            GXSetVtxDesc(0xd, 3);
        }
        thr = lbl_803DF2EC;
        for (i = 0; i < WATERFX_MAX_SPLASHES; i++)
        {
            WaterParticle* s = &((WaterParticle*)gWaterfxSplashPool)[i];
            if (s->f10 < thr)
            {
                fn_80095164(s);
            }
        }
        if ((int)gWaterfxDropCount != 0)
        {
            waterfx_setupSplashDropPointRender();
        }
        for (i = 0; i < WATERFX_POOL_SIZE; i++)
        {
            WaterDrop* d = &((WaterDrop*)gWaterfxDropPool)[i];
            if (d->idx != -1)
            {
                f32 vx, vy, vz;
                GXBegin(0xb8, 2, 1);
                vz = d->z - playerMapOffsetZ;
                vy = d->y;
                vx = d->x - playerMapOffsetX;
                GXWGFifo.f32 = vx;
                GXWGFifo.f32 = vy;
                GXWGFifo.f32 = vz;
            }
        }
        if ((int)gWaterfxWakeCount != 0)
        {
            fn_8007C664((int)gWaterfxWakeTexture);
        }
        for (i = 0; i < WATERFX_POOL_SIZE; i++)
        {
            WaterEntry* g = &((WaterEntry*)gWaterfxWakePool)[i];
            int o32 = i * 0x20;
            int o64 = i * 0x40;
            if (g->active != 0 && g->f18 == 0)
            {
                setTextColor(obj, 0xff, 0xff, 0xff, (u8)g->active);
                dp.x = g->x;
                dp.y = g->y;
                dp.z = g->z;
                dp.f10 = g->f10;
                dp.f8 = g->f16;
                dp.fc = 0;
                dp.fa = 0;
                Camera_LoadModelViewMatrix(obj, renderParam, &dp, lbl_803DF2EC, lbl_803DF300, 0);
                fn_8007D670();
                drawFn_8005cf8c((char*)gWaterfxWakeVtx + o64, (char*)gWaterfxWakeVtxDesc + o32, 2);
            }
        }
        fn_800542F4();
    }
}

void waterfx_run(void)
{
    int i;
    for (i = 0; i < WATERFX_POOL_SIZE; i++)
    {
        WaterEntry7* e = &((WaterEntry7*)gWaterfxRipplePool)[i];
        if (e->active != 0)
        {
            e->f10 += gWaterfxRippleGrowSpeed * timeDelta;
            e->active = (s16)(e->active - framesThisStep * e->f18);
            if (e->active < 0)
            {
                e->active = 0;
                gWaterfxRippleCount = (void*)((int)gWaterfxRippleCount - 1);
            }
        }
    }
    for (i = 0; i < WATERFX_POOL_SIZE; i++)
    {
        WaterEntry* g = &((WaterEntry*)gWaterfxWakePool)[i];
        if (g->active != 0)
        {
            g->f10 += gWaterfxWakeGrowSpeed * timeDelta;
            g->active = (s16)(g->active - framesThisStep * 2);
            if (g->active < 0)
            {
                g->active = 0;
                gWaterfxWakeCount = (void*)((int)gWaterfxWakeCount - 1);
            }
        }
    }
    {
        for (i = 0; i < WATERFX_MAX_SPLASHES; i++)
        {
            WaterParticle* s = &((WaterParticle*)gWaterfxSplashPool)[i];
            if (s->f10 < 1.0f)
            {
                s->f10 += s->f14 * timeDelta;
                if (s->f10 >= 1.0f)
                {
                    gWaterfxSplashCount = (void*)((int)gWaterfxSplashCount - 1);
                }
            }
        }
    }
    for (i = 0; i < WATERFX_POOL_SIZE; i++)
    {
        WaterDrop* d = &((WaterDrop*)gWaterfxDropPool)[i];
        if (d->idx != -1)
        {
            WaterParticle* wp = &((WaterParticle*)gWaterfxSplashPool)[d->idx];
            d->f10 += gWaterfxDropGravity * timeDelta;
            d->f0c *= gWaterfxDropDamping;
            d->f10 *= gWaterfxDropDamping;
            d->f14 *= gWaterfxDropDamping;
            d->x += d->f0c;
            d->y += d->f10;
            d->z += d->f14;
            if (wp->y > d->y)
            {
                wp->active--;
                d->idx = -1;
                gWaterfxDropCount = (void*)((int)gWaterfxDropCount - 1);
                gWaterfxRippleScale = lbl_803DF334;
                waterfx_spawnRipple(d->x, wp->y, d->z, 0, lbl_803DF300, 8);
            }
        }
    }
}

void waterfx_func04(u8* p3, u16 mask, f32* vecs, u8* p6, f32 fval)
{
    u8* q = p6;
    f32* v = vecs;
    while (mask != 0)
    {
        if (mask & 1)
        {
            f32 vx = v[0];
            f32 vz = v[2];
            if (*(f32*)(q + 0x1b4) < lbl_803DF338)
            {
                if (fval > lbl_803DF33C)
                {
                    waterfx_spawnSplashBurst(p3, vx, *(f32*)(p3 + 0x10) + *(f32*)(q + 0x1b4), vz, lbl_803DF300);
                }
            }
            gWaterfxRippleScale = lbl_803DF318;
            waterfx_spawnRipple(vx, *(f32*)(p3 + 0x10) + *(f32*)(q + 0x1b4), vz, *(s16*)p3, lbl_803DF300, 4);
            gWaterfxPendingImpactPosition[0] = vx;
            gWaterfxPendingImpactPosition[1] = *(f32*)(p3 + 0x10) + *(f32*)(q + 0x1b4);
            gWaterfxPendingImpactPosition[2] = vz;
            gWaterfxPendingImpactPositionValid = 1;
        }
        mask >>= 1;
        v += 3;
    }
}

void waterfx_onMapSetup(void)
{
    int i;
    VtxDesc* vd;
    {
        vd = (VtxDesc*)gWaterfxRippleVtxDesc;
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
            e->f10 = 0.01f;
            e->active = 0;
        }
    }
    {
        f32 initThreshold;
        f32 initPos;
        initPos = lbl_803DF300;
        initThreshold = lbl_803DF2EC;
        for (i = 0; i < WATERFX_MAX_SPLASHES; i++)
        {
            WaterParticle* s = &((WaterParticle*)gWaterfxSplashPool)[i];
            s->x = initPos;
            s->y = initPos;
            s->z = initPos;
            s->f10 = initThreshold;
            s->active = 0;
        }
    }
    {
        f32 initScale;
        f32 initPos;
        vd = (VtxDesc*)gWaterfxWakeVtxDesc;
        initPos = lbl_803DF300;
        initScale = lbl_803DF318;
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
            g->f10 = initScale;
            g->active = 0;
            g->f16 = 0;
        }
    }
    {
        f32 initPos = lbl_803DF300;
        for (i = 0; i < WATERFX_POOL_SIZE; i++)
        {
            WaterDrop* d = &((WaterDrop*)gWaterfxDropPool)[i];
            d->idx = -1;
            d->f0c = initPos;
            d->f10 = initPos;
            d->f14 = initPos;
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
        textureFree((int)gWaterfxRippleTexture);
        gWaterfxRippleTexture = NULL;
    }
    if (gWaterfxSplashTexture0 != NULL)
    {
        textureFree((int)gWaterfxSplashTexture0);
        gWaterfxSplashTexture0 = NULL;
    }
    if (gWaterfxSplashTexture1 != NULL)
    {
        textureFree((int)gWaterfxSplashTexture1);
        gWaterfxSplashTexture1 = NULL;
    }
    if (gWaterfxWakeTexture != NULL)
    {
        textureFree((int)gWaterfxWakeTexture);
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
    char* buf;

    buf = mmAlloc(0x22b0, 0x13, 0);
    if (buf == NULL)
    {
        debugPrintf(sWaterfxDllAllocFailed);
        return;
    }
    gWaterfxRippleVtxDesc = buf;
    gWaterfxWakeVtxDesc = buf + 0x3c0;
    {
        char* p2 = buf + 0x780;
        char* p3;
        gWaterfxRippleVtx = p2;
        gWaterfxWakeVtx = p2 + 0x780;
        p3 = p2 + 0xf00;
        gWaterfxRipplePool = p3;
        gWaterfxSplashPool = p3 + 0x348;
        gWaterfxDropPool = p3 + 0x5a0;
        gWaterfxWakePool = p3 + 0x8e8;
    }
    gWaterfxRippleCount = NULL;
    gWaterfxSplashCount = NULL;
    gWaterfxDropCount = NULL;
    gWaterfxWakeCount = NULL;
    gWaterfxRippleTexture = (void*)textureLoadAsset(0x56);
    gWaterfxSplashTexture0 = (void*)textureLoadAsset(0xc2a);
    gWaterfxSplashTexture1 = (void*)textureLoadAsset(0xc2c);
    gWaterfxWakeTexture = (void*)textureLoadAsset(0xc2d);
    waterfx_onMapSetup();
    waterfx_drawFn_800953fc();
}

void fn_80095164(WaterParticle* s)
{
    f32 mtxD[12];
    f32 scale[12];
    f32 mtxB[12];
    f32 mtxC[12];
    int mtxIdx;
    u8* p;
    int i;

    PSMTXScale(scale, s->f0c, s->f0c, s->f0c);
    i = 0;
    mtxIdx = 0;
    p = (u8*)s;
    for (; i < 8; i++)
    {
        f32 h = s->f10;
        f32 ph = lbl_803DF2E0;
        f32 a = 0.9f * ((f32)i / 7.0f);
        f32 dd;
        f32 lim;
        f32 sc;
        f32 fade;
        f32 t;
        ph = (ph + a) * h;
        dd = ph - 0.5f;
        fade = -(4.0f * (dd * dd) - 1.0f);
        lim = 0.05f + a;
        if (h < lim)
        {
            t = 1.0f;
        }
        else
        {
            t = (1.0f - h) / (1.0f - lim);
        }
        sc = 2.0f * ph + 1.0f;
        PSMTXScale(mtxB, sc, 1.0f, sc);
        PSMTXTrans(mtxC, lbl_803DF300, 2.0f * fade, lbl_803DF300);
        PSMTXConcat(mtxC, mtxB, mtxD);
        PSMTXConcat(scale, mtxD, mtxD);
        PSMTXTrans(mtxC, s->x - playerMapOffsetX, s->y, s->z - playerMapOffsetZ);
        PSMTXConcat(mtxC, mtxD, mtxD);
        PSMTXConcat(Camera_GetViewMatrix(), mtxD, mtxD);
        GXLoadPosMtxImm(mtxD, mtxIdx);
        *(u32*)(p + 0x18) = (u8)(int)(lbl_803DF304 * t);
        mtxIdx += 3;
        p += 4;
    }
    DCStoreRange(s->pad18, 32);
    GXSetArray(11, s->pad18, 4);
    GXSetCullMode(1);
    GXCallDisplayList(gWaterfxSplashDisplayList, gWaterfxSplashDisplayListSize);
    GXSetCullMode(2);
    GXCallDisplayList(gWaterfxSplashDisplayList, gWaterfxSplashDisplayListSize);
}

void waterfx_drawFn_800953fc(void)
{
    int k;
    int j;
    int i;
    int m;
    void* dl;

    GXSetMisc(1, 0);
    gWaterfxSplashPosArray = mmAlloc(192, 0, 0);
    gWaterfxSplashTexCoordArray = mmAlloc(1024, 0, 0);
    for (i = 0; i < 8; i++)
    {
        for (j = 0; j < 16; j++)
        {
            if (i == 0)
            {
                f32* pos = (f32*)((u8*)gWaterfxSplashPosArray + j * 12);
                f32 ang = gWaterfxPi * (f32)(j * 2) / lbl_803DF314;
                f32 sv = fn_802942EC(ang);
                f32 cv = fn_80293F7C(ang);
                pos[0] = sv;
                pos[1] = lbl_803DF300;
                pos[2] = cv;
            }
            {
                int idx = i * 16 + j;
                f32* tex = (f32*)((u8*)gWaterfxSplashTexCoordArray + idx * 8);
                tex[0] = j / lbl_803DF314;
                tex[1] = i / lbl_803DF2F8;
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
    for (k = 0; k < 15; k++)
    {
        GXBegin(152, 2, 16);
        for (m = 7; m >= 0; m--)
        {
            u8 a = m * 3;
            GXWGFifo.u8 = a;
            GXWGFifo.u8 = a;
            GXWGFifo.u16 = k;
            GXWGFifo.u16 = m;
            GXWGFifo.u16 = m * 16 + k;
            GXWGFifo.u8 = a;
            GXWGFifo.u8 = a;
            GXWGFifo.u16 = (k + 1) % 16;
            GXWGFifo.u16 = m;
            GXWGFifo.u16 = m * 16 + (k + 1) % 16;
        }
    }
    gWaterfxSplashDisplayListSize = GXEndDisplayList();
    GXSetMisc(1, 8);
}
