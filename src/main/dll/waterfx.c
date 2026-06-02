#include "ghidra_import.h"
#include "main/dll/fx_800944A0_shared.h"

volatile PPCWGPipe GXWGFifo : (0xCC008000);

#pragma scheduling off
#pragma peephole off
void fn_80094F7C(void) {
    u8 col[4];
    u8 kcol[4];
    f32 dummy;
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
    (*(void (*)(void *, void *, void *, f32 *, f32 *, f32 *))(*(int *)(*gSHthorntailAnimationInterface + 0x40)))(
        &col[0], &col[1], &col[2], &dummy, &dummy, &dummy);
    col[0] = (col[0] >> 2) + 0x80;
    col[1] = (col[1] >> 2) + 0x80;
    col[2] = (col[2] >> 2) + 0x80;
    col[3] = 0x80;
    *(int *)kcol = *(int *)col;
    GXSetTevKColor(0, kcol);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_800956F4(int vec, f32 dist) {
    if (lbl_803DD1F8 != 0 && PSVECSquareDistance((f32 *)vec, lbl_8039AB48) < dist * dist) {
        lbl_803DD1F8 = 0;
        return 1;
    }
    lbl_803DD1F8 = 0;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void waterfx_spawnRipple(s16 p1, int p2, f32 a, f32 b, f32 c, f32 d) {
    int i = 0;
    WaterEntry7 *p = lbl_803DD238;
    WaterVtx *q;
    WaterEntry7 *e;
    int j;
    while (i < 0x1e && p->active != 0) {
        p++;
        i++;
    }
    if (i >= 0x1e) {
        return;
    }
    j = i * 4;
    q = &((WaterVtx *)lbl_803DD24C)[j];
    q->x = -300;
    q->y = 0;
    q->z = 300;
    q->a = 0xff;
    q->u = 0;
    q->v = 0;
    q = &((WaterVtx *)lbl_803DD24C)[j + 1];
    q->x = -300;
    q->y = 0;
    q->z = -300;
    q->a = 0xff;
    q->u = 0;
    q->v = 0x7f;
    q = &((WaterVtx *)lbl_803DD24C)[j + 2];
    q->x = 300;
    q->y = 0;
    q->z = -300;
    q->a = 0xff;
    q->u = 0x7f;
    q->v = 0x7f;
    q = &((WaterVtx *)lbl_803DD24C)[j + 3];
    q->x = 300;
    q->y = 0;
    q->z = 300;
    q->a = 0xff;
    q->u = 0x7f;
    q->v = 0;
    e = (WaterEntry7 *)lbl_803DD238 + i;
    e->w = d;
    e = (WaterEntry7 *)lbl_803DD238 + i;
    e->active = 0xff;
    e = (WaterEntry7 *)lbl_803DD238 + i;
    e->x = a;
    e = (WaterEntry7 *)lbl_803DD238 + i;
    e->y = b;
    e = (WaterEntry7 *)lbl_803DD238 + i;
    e->z = c;
    e = (WaterEntry7 *)lbl_803DD238 + i;
    e->f14 = p1;
    e = (WaterEntry7 *)lbl_803DD238 + i;
    e->f10 = lbl_803DD20C;
    e = (WaterEntry7 *)lbl_803DD238 + i;
    e->f18 = lbl_803DF2E8 * (f32)p2;
    lbl_803DD23C = (void *)((int)lbl_803DD23C + 1);
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void waterfx_setRippleScale(int flag, f32 val) {
    if (flag != 0) {
        val = lbl_803DF318;
    }
    lbl_803DD20C = val;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void waterfx_func08(s16 p1, f32 a, f32 b, f32 c, f32 d) {
    int i = 0;
    WaterEntry *p = lbl_803DD228;
    WaterVtx *q;
    WaterEntry *entry;
    int j;
    while (i < 0x1e && p->active != 0) {
        p++;
        i++;
    }
    if (i >= 0x1e) {
        return;
    }
    j = i * 4;
    q = &((WaterVtx *)lbl_803DD244)[j];
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
    entry = (WaterEntry *)lbl_803DD228 + i;
    entry->x = a;
    entry->y = b;
    entry->z = c;
    entry->w = d;
    entry->f10 = lbl_803DF318;
    entry->active = 0xff;
    entry->f16 = p1;
    entry->f18 = 0;
    lbl_803DD22C = (void *)((int)lbl_803DD22C + 1);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void waterfx_spawnSplashBurst(void *obj, f32 a, f32 b, f32 c, f32 d) {
    WaterParticle *p;
    int i;
    WaterParticle *base;
    WaterParticle *slot;
    int rnd;
    if (lbl_803DF300 == d) {
        d = lbl_803DF31C;
    }
    i = 0;
    base = lbl_803DD230;
    p = base;
    while (i < 0xa && (p->active != 0 || p->f10 < lbl_803DF2EC)) {
        p++;
        i++;
    }
    if (i >= 0xa) {
        return;
    }
    slot = &base[i];
    slot->x = a;
    slot->y = b;
    slot->z = c;
    lbl_803DD234 = (void *)((int)lbl_803DD234 + 1);
    slot->f0c = d;
    rnd = randomGetRange((int)slot->f0c, (int)(lbl_803DF2FC * slot->f0c));
    slot->active = (u8)waterfx_spawnSplashDrops(&((WaterParticle *)lbl_803DD230)[i], i, rnd, slot->f0c);
    slot->f10 = lbl_803DF300;
    slot->f14 = lbl_803DF2EC / (lbl_803DF320 * sqrtf(slot->f0c));
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int waterfx_spawnSplashDrops(WaterParticle *src, int idx, int count, f32 v) {
    int cur;
    f32 scale;
    ExpParticle *p;
    ExpParticle *base;
    ExpParticle *slot;
    int j;
    int i;
    cur = (int)lbl_803DD224;
    if (count + cur > 30) {
        count = 30 - cur;
    }
    if (count != 0) {
        i = 0;
        scale = lbl_803DF324 * v;
        for (; i < count; i++) {
            base = (ExpParticle *)lbl_803DD220;
            p = base;
            j = 0;
            while (j < 30 && p->active != -1) {
                p++;
                j++;
            }
            if (j < 30) {
                slot = &base[j];
                slot->f0c = (f32)randomGetRange(-250, 250);
                slot->f0c = slot->f0c * scale;
                slot->f14 = (f32)randomGetRange(-250, 250);
                slot->f14 = slot->f14 * scale;
                slot->f10 = (f32)randomGetRange(200, 300);
                slot->f10 = slot->f10 * scale;
                slot->active = (s8)idx;
                slot->x = src->x;
                slot->y = src->y;
                slot->z = src->z;
                lbl_803DD224 = (void *)((int)lbl_803DD224 + 1);
            }
        }
    }
    return count;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void waterfx_func05(int p1, int p2) {
    int i;
    f32 thr;
    WaterDrawObj dp;
    if ((int)lbl_803DD23C != 0 || (int)lbl_803DD22C != 0 || (int)lbl_803DD234 != 0 ||
        (int)lbl_803DD224 != 0) {
        GXSetCullMode(0);
        if ((int)lbl_803DD23C != 0) {
            fn_8007CAF4((int)lbl_803DD21C);
        }
        for (i = 0; i < 30; i++) {
            WaterEntry7 *e = &((WaterEntry7 *)lbl_803DD238)[i];
            if (e->active != 0) {
                setTextColor(p1, 0xff, 0xff, 0xff, (u8)e->active);
                dp.x = e->x;
                dp.y = e->y;
                dp.z = e->z;
                dp.f10 = e->f10;
                dp.f8 = e->f14;
                dp.fc = 0;
                dp.fa = 0;
                Camera_LoadModelViewMatrix(p1, p2, &dp, lbl_803DF2EC, lbl_803DF300, 0);
                fn_8007D670();
                drawFn_8005cf8c((char *)lbl_803DD24C + i * 0x40, (char *)lbl_803DD248 + i * 0x20, 2);
            }
        }
        if ((int)lbl_803DD234 != 0) {
            fn_8007BD8C((int)lbl_803DD218, (int)lbl_803DD214);
            GXSetArray(9, lbl_803DD200, 0xc);
            GXSetArray(0xd, lbl_803DD1FC, 8);
            GXClearVtxDesc();
            GXSetVtxDesc(0, 1);
            GXSetVtxDesc(1, 1);
            GXSetVtxDesc(9, 3);
            GXSetVtxDesc(0xb, 3);
            GXSetVtxDesc(0xd, 3);
        }
        thr = lbl_803DF2EC;
        for (i = 0; i < 10; i++) {
            WaterParticle *s = &((WaterParticle *)lbl_803DD230)[i];
            if (s->f10 < thr) {
                fn_80095164(s);
            }
        }
        if ((int)lbl_803DD224 != 0) {
            fn_80094F7C();
        }
        for (i = 0; i < 30; i++) {
            WaterDrop *d = &((WaterDrop *)lbl_803DD220)[i];
            if (d->idx != -1) {
                GXBegin(0xb8, 2, 1);
                GXWGFifo.f32 = d->x - playerMapOffsetX;
                GXWGFifo.f32 = d->y;
                GXWGFifo.f32 = d->z - playerMapOffsetZ;
            }
        }
        if ((int)lbl_803DD22C != 0) {
            fn_8007C664((int)lbl_803DD210);
        }
        for (i = 0; i < 30; i++) {
            WaterEntry *g = &((WaterEntry *)lbl_803DD228)[i];
            if (g->active != 0 && g->f18 == 0) {
                setTextColor(p1, 0xff, 0xff, 0xff, (u8)g->active);
                dp.x = g->x;
                dp.y = g->y;
                dp.z = g->z;
                dp.f10 = g->f10;
                dp.f8 = g->f16;
                dp.fc = 0;
                dp.fa = 0;
                Camera_LoadModelViewMatrix(p1, p2, &dp, lbl_803DF2EC, lbl_803DF300, 0);
                fn_8007D670();
                drawFn_8005cf8c((char *)lbl_803DD244 + i * 0x40, (char *)lbl_803DD240 + i * 0x20, 2);
            }
        }
        fn_800542F4();
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void waterfx_run(void) {
    int i;
    for (i = 0; i < 30; i++) {
        WaterEntry7 *e = &((WaterEntry7 *)lbl_803DD238)[i];
        if (e->active != 0) {
            e->f10 += lbl_803DF324 * timeDelta;
            e->active = (s16)(e->active - framesThisStep * e->f18);
            if (e->active < 0) {
                e->active = 0;
                lbl_803DD23C = (void *)((int)lbl_803DD23C - 1);
            }
        }
    }
    for (i = 0; i < 30; i++) {
        WaterEntry *g = &((WaterEntry *)lbl_803DD228)[i];
        if (g->active != 0) {
            g->f10 += lbl_803DF328 * timeDelta;
            g->active = (s16)(g->active - framesThisStep * 2);
            if (g->active < 0) {
                g->active = 0;
                lbl_803DD22C = (void *)((int)lbl_803DD22C - 1);
            }
        }
    }
    for (i = 0; i < 10; i++) {
        WaterParticle *s = &((WaterParticle *)lbl_803DD230)[i];
        if (s->f10 < lbl_803DF2EC) {
            s->f10 += s->f14 * timeDelta;
            if (s->f10 >= lbl_803DF2EC) {
                lbl_803DD234 = (void *)((int)lbl_803DD234 - 1);
            }
        }
    }
    for (i = 0; i < 30; i++) {
        WaterDrop *d = &((WaterDrop *)lbl_803DD220)[i];
        if (d->idx != -1) {
            WaterParticle *wp = &((WaterParticle *)lbl_803DD230)[d->idx];
            d->f10 += lbl_803DF32C * timeDelta;
            d->f0c *= lbl_803DF330;
            d->f10 *= lbl_803DF330;
            d->f14 *= lbl_803DF330;
            d->x += d->f0c;
            d->y += d->f10;
            d->z += d->f14;
            if (d->y < wp->y) {
                wp->active--;
                d->idx = -1;
                lbl_803DD224 = (void *)((int)lbl_803DD224 - 1);
                lbl_803DD20C = lbl_803DF334;
                waterfx_spawnRipple(0, 8, d->x, wp->y, d->z, lbl_803DF300);
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void waterfx_func04(u8 *p3, u16 mask, f32 *vecs, u8 *p6, f32 fval) {
    u8 *q = p6;
    f32 *v = vecs;
    while (mask != 0) {
        if (mask & 1) {
            f32 vx = v[0];
            f32 vz = v[2];
            if (*(f32 *)(q + 0x1b4) < lbl_803DF338) {
                if (fval > lbl_803DF33C) {
                    waterfx_spawnSplashBurst(p3, vx, *(f32 *)(p3 + 0x10) + *(f32 *)(q + 0x1b4), vz, lbl_803DF300);
                }
            }
            lbl_803DD20C = lbl_803DF318;
            waterfx_spawnRipple(*(s16 *)p3, 4, vx, *(f32 *)(p3 + 0x10) + *(f32 *)(q + 0x1b4), vz, lbl_803DF300);
            lbl_8039AB48[0] = vx;
            lbl_8039AB48[1] = *(f32 *)(p3 + 0x10) + *(f32 *)(q + 0x1b4);
            lbl_8039AB48[2] = vz;
            lbl_803DD1F8 = 1;
        }
        mask >>= 1;
        v += 3;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void waterfx_onMapSetup(void) {
    int i;
    VtxDesc *vd;
    {
        f32 cf10;
        f32 cxyz;
        vd = (VtxDesc *)lbl_803DD248;
        cxyz = lbl_803DF300;
        cf10 = lbl_803DF318;
        for (i = 0; i < 30; i++) {
            WaterEntry7 *e;
            vd[0].b1 = 3;
            vd[0].b2 = 1;
            vd[0].b3 = 0;
            vd[1].b1 = 3;
            vd[1].b2 = 2;
            vd[1].b3 = 1;
            e = &((WaterEntry7 *)lbl_803DD238)[i];
            e->x = cxyz;
            e->y = cxyz;
            e->z = cxyz;
            e->w = cxyz;
            e->f10 = cf10;
            e->active = 0;
            vd += 2;
        }
    }
    {
        f32 cf10;
        f32 cxyz;
        cxyz = lbl_803DF300;
        cf10 = lbl_803DF2EC;
        for (i = 0; i < 10; i++) {
            WaterParticle *s = &((WaterParticle *)lbl_803DD230)[i];
            s->x = cxyz;
            s->y = cxyz;
            s->z = cxyz;
            s->f10 = cf10;
            s->active = 0;
        }
    }
    {
        f32 cf10;
        f32 cxyz;
        vd = (VtxDesc *)lbl_803DD240;
        cxyz = lbl_803DF300;
        cf10 = lbl_803DF318;
        for (i = 0; i < 30; i++) {
            WaterEntry *g;
            vd[0].b1 = 3;
            vd[0].b2 = 1;
            vd[0].b3 = 0;
            vd[1].b1 = 3;
            vd[1].b2 = 2;
            vd[1].b3 = 1;
            g = &((WaterEntry *)lbl_803DD228)[i];
            g->x = cxyz;
            g->y = cxyz;
            g->z = cxyz;
            g->w = cxyz;
            g->f10 = cf10;
            g->active = 0;
            g->f16 = 0;
            vd += 2;
        }
    }
    {
        f32 cf10 = lbl_803DF300;
        for (i = 0; i < 30; i++) {
            WaterDrop *d = &((WaterDrop *)lbl_803DD220)[i];
            d->idx = -1;
            d->f0c = cf10;
            d->f10 = cf10;
            d->f14 = cf10;
            d->x = cf10;
            d->y = cf10;
            d->z = cf10;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void waterfx_release(void) {
    if (lbl_803DD248 != NULL) {
        mm_free(lbl_803DD248);
    }
    if (lbl_803DD21C != NULL) {
        textureFree((int)lbl_803DD21C);
        lbl_803DD21C = NULL;
    }
    if (lbl_803DD218 != NULL) {
        textureFree((int)lbl_803DD218);
        lbl_803DD218 = NULL;
    }
    if (lbl_803DD214 != NULL) {
        textureFree((int)lbl_803DD214);
        lbl_803DD214 = NULL;
    }
    if (lbl_803DD210 != NULL) {
        textureFree((int)lbl_803DD210);
        lbl_803DD210 = NULL;
    }
    if (lbl_803DD208 != NULL) {
        mm_free(lbl_803DD208);
        lbl_803DD208 = NULL;
    }
    if (lbl_803DD200 != NULL) {
        mm_free(lbl_803DD200);
        lbl_803DD200 = NULL;
    }
    if (lbl_803DD1FC != NULL) {
        mm_free(lbl_803DD1FC);
        lbl_803DD1FC = NULL;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void waterfx_initialise(void) {
    char *buf;

    buf = mmAlloc(0x22b0, 0x13, 0);
    if (buf == NULL) {
        debugPrintf(sWaterfxDllAllocFailed);
        return;
    }
    lbl_803DD248 = buf;
    lbl_803DD240 = buf + 0x3c0;
    buf += 0x780;
    lbl_803DD24C = buf;
    lbl_803DD244 = buf + 0x780;
    buf += 0xf00;
    lbl_803DD238 = buf;
    lbl_803DD230 = buf + 0x348;
    lbl_803DD220 = buf + 0x5a0;
    lbl_803DD228 = buf + 0x8e8;
    lbl_803DD23C = NULL;
    lbl_803DD234 = NULL;
    lbl_803DD224 = NULL;
    lbl_803DD22C = NULL;
    lbl_803DD21C = (void *)textureLoadAsset(0x56);
    lbl_803DD218 = (void *)textureLoadAsset(0xc2a);
    lbl_803DD214 = (void *)textureLoadAsset(0xc2c);
    lbl_803DD210 = (void *)textureLoadAsset(0xc2d);
    waterfx_onMapSetup();
    waterfx_drawFn_800953fc();
}
#pragma peephole reset
#pragma scheduling reset

