#include "ghidra_import.h"

extern f32 lbl_803DF318;
extern f32 lbl_803DF348;
extern f32 lbl_803DF34C;
extern f32 lbl_803DB790;
extern f32 lbl_803DD20C;
extern int lbl_803DB618[2];
extern int lbl_803DD1F0;
extern u8 lbl_803DD1F8;
extern u8 lbl_8039AB28[];
extern f32 lbl_8039AB48[];
extern int objFindTexture(int name, int a, int b);
extern f32 PSVECSquareDistance(f32 *a, f32 *b);
extern void *memset(void *dst, int c, int n);
extern void Obj_FreeObject(int obj);
extern void textureFree(int tex);
extern int textureLoadAsset(int id);
extern void mm_free(void *p);
extern void *mmAlloc(int size, int kind, int flags);
extern void debugPrintf(char *fmt, ...);
extern char sWaterfxDllAllocFailed[];
extern int gExpgfxRuntimeData[];
extern int gExpgfxTextureFreeInProgress;
extern u8 framesThisStep;
extern void waterfx_onMapSetup(void);
extern void waterfx_drawFn_800953fc(void);
extern void *lbl_803DD1FC;
extern void *lbl_803DD200;
extern void *lbl_803DD208;
extern void *lbl_803DD210;
extern void *lbl_803DD214;
extern void *lbl_803DD218;
extern void *lbl_803DD21C;
extern void *lbl_803DD220;
extern void *lbl_803DD224;
extern void *lbl_803DD228;
extern void *lbl_803DD22C;
extern void *lbl_803DD230;
extern void *lbl_803DD234;
extern void *lbl_803DD238;
extern void *lbl_803DD23C;
extern void *lbl_803DD240;
extern void *lbl_803DD244;
extern void *lbl_803DD248;
extern void *lbl_803DD24C;

void cloudaction_func08_nop(void) {}
void cloudaction_func09_nop(void) {}
void cloudaction_release(void) {}

#pragma scheduling off
#pragma peephole off
void viewFinderSetZoomTo50(void) {
    lbl_803DB790 = lbl_803DF34C;
}

void viewFinderSetZoom(f32 zoom) {
    lbl_803DB790 = lbl_803DF348 / zoom;
}

void waterfx_func0A(int flag, f32 val) {
    if (flag != 0) {
        val = lbl_803DF318;
    }
    lbl_803DD20C = val;
}

void cloudaction_initialise(void) {
    lbl_803DB618[0] = -1;
    lbl_803DB618[1] = -1;
    lbl_803DD1F0 = 0;
}

void cloudaction_onMapSetup(void) {
    memset(lbl_8039AB28, 0, 0x1c);
}

extern void GXSetPointSize(int size, int fmt);
extern void GXClearVtxDesc(void);
extern void GXSetVtxDesc(int attr, int type);
extern void *Camera_GetViewMatrix(void);
extern void GXLoadPosMtxImm(void *mtx, int id);
extern void GXSetCurrentMtx(int id);
extern void GXSetTevKColorSel(int stage, int sel);
extern void GXSetTevKAlphaSel(int stage, int sel);
extern void GXSetNumIndStages(int n);
extern void GXSetNumTexGens(int n);
extern void GXSetNumTevStages(int n);
extern void GXSetNumChans(int n);
extern void GXSetTevDirect(int stage);
extern void GXSetTevOrder(int stage, int coord, int map, int color);
extern void GXSetTevColorIn(int stage, int a, int b, int c, int d);
extern void GXSetTevAlphaIn(int stage, int a, int b, int c, int d);
extern void GXSetTevSwapMode(int stage, int ras, int tex);
extern void GXSetTevColorOp(int stage, int op, int bias, int scale, int clamp, int reg);
extern void GXSetTevAlphaOp(int stage, int op, int bias, int scale, int clamp, int reg);
extern void GXSetBlendMode(int type, int src, int dst, int op);
extern void gxSetZMode_(int compEnable, int func, int updateEnable);
extern void gxSetPeControl_ZCompLoc_(int zcomploc);
extern void GXSetAlphaCompare(int comp0, int ref0, int op, int comp1, int ref1);
extern void GXSetCullMode(int mode);
extern void GXSetTevKColor(int id, void *color);
extern int *gSHthorntailAnimationInterface;

void fn_80094F7C(void) {
    f32 dummy;
    u8 kcol[4];
    u8 col[4];
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

void cloudaction_func05(void) {
    int tex;
    if (*(void **)lbl_8039AB28 != NULL) {
        tex = objFindTexture(*(int *)lbl_8039AB28, 0, 0);
        if (tex != 0) {
            *(s16 *)(tex + 8) = *(s16 *)(tex + 8) - lbl_8039AB28[0x18];
            if (*(s16 *)(tex + 8) < -0x2710) {
                *(s16 *)(tex + 8) = *(s16 *)(tex + 8) + 0x2710;
            }
        }
    }
}

int fn_800956F4(int vec, f32 dist) {
    if (lbl_803DD1F8 != 0 && PSVECSquareDistance((f32 *)vec, lbl_8039AB48) < dist * dist) {
        lbl_803DD1F8 = 0;
        return 1;
    }
    lbl_803DD1F8 = 0;
    return 0;
}

void cloudaction_free(void) {
    if (*(void **)lbl_8039AB28 != NULL) {
        Obj_FreeObject(*(int *)lbl_8039AB28);
        *(int *)lbl_8039AB28 = 0;
    }
    *(int *)(lbl_8039AB28 + 0xc) = 0;
    if (*(void **)(lbl_8039AB28 + 4) != NULL) {
        Obj_FreeObject(*(int *)(lbl_8039AB28 + 4));
        *(int *)(lbl_8039AB28 + 4) = 0;
    }
    *(int *)(lbl_8039AB28 + 0x10) = 0;
    if (*(void **)(lbl_8039AB28 + 8) != NULL) {
        Obj_FreeObject(*(int *)(lbl_8039AB28 + 8));
        *(int *)(lbl_8039AB28 + 8) = 0;
    }
    *(int *)(lbl_8039AB28 + 0x14) = 0;
}

void fn_8009AD44(void) {
    int *e;
    int i;

    i = 0;
    e = gExpgfxRuntimeData;
    for (; i < 0x20; i++) {
        if (e[2] != 0) {
            e[1] = e[1] - framesThisStep;
            if (e[1] <= 0) {
                e[2] = 0;
                e[1] = 0;
                e[3] = 0;
                gExpgfxTextureFreeInProgress = 1;
                textureFree(e[0]);
                gExpgfxTextureFreeInProgress = 0;
                e[0] = 0;
            }
        }
        e += 4;
    }
}

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

extern u8 *Obj_GetPlayerObject(void);
extern f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z);
extern void CameraShake_Start(f32 a, f32 b, f32 c);
extern void doRumble(f32 v);
extern f32 lbl_803DF354;
extern f32 lbl_803DF384;
extern f32 lbl_803DF3A0;
extern f32 lbl_803DF3A4;
extern f32 lbl_803DF3A8;

void fn_8009A8C8(u8 *obj, f32 thresh) {
    u8 *player = Obj_GetPlayerObject();
    if (player == NULL) {
        return;
    }
    if (*(u16 *)(player + 0xb0) & 0x1000) {
        return;
    }
    {
        f32 d = Camera_DistanceToCurrentViewPosition(*(f32 *)(obj + 0x18), *(f32 *)(obj + 0x1c), *(f32 *)(obj + 0x20));
        if (d <= thresh) {
            f32 t = lbl_803DF354 - d / thresh;
            CameraShake_Start(lbl_803DF3A0 * t, lbl_803DF384 * t, lbl_803DF3A4);
            doRumble(lbl_803DF3A8 * t);
        }
    }
}

typedef struct {
    u16 h18;
    u16 h1a;
    u16 h1c;
    u16 pad;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} ParticleEmit;

extern int *Resource_Acquire(int id, int kind);

void fn_80096F9C(f32 *pos, u8 a, u8 b, u8 c, u8 d) {
    int args[4];
    ParticleEmit s1;
    int *res;
    s1.scale = lbl_803DF354;
    s1.h1c = 0;
    s1.h1a = 0;
    s1.h18 = 0;
    s1.x = pos[0];
    s1.y = pos[1];
    s1.z = pos[2];
    res = Resource_Acquire(0x5a, 1);
    args[0] = a;
    args[1] = b;
    args[2] = c;
    args[3] = d;
    (*(void (*)(int, int, void *, int, int, void *))(*(int *)(*(int *)res + 4)))(0, 1, &s1, 0x401, -1, args);
}

typedef struct {
    s16 x;
    s16 y;
    s16 z;
    s16 pad6;
    s16 u;
    s16 v;
    u8 padc[3];
    u8 a;
} WaterVtx;

typedef struct {
    f32 x;
    f32 y;
    f32 z;
    f32 w;
    f32 f10;
    s16 active;
    s16 f16;
    u8 f18;
    u8 pad19[3];
} WaterEntry;

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

typedef struct {
    f32 x;
    f32 y;
    f32 z;
    f32 f0c;
    f32 f10;
    f32 f14;
    u8 pad18[0x20];
    u8 active;
    u8 pad39[3];
} WaterParticle;

extern f32 lbl_803DF300;
extern f32 lbl_803DF31C;
extern f32 lbl_803DF2EC;
extern f32 lbl_803DF2FC;
extern f32 lbl_803DF320;
extern int randomGetRange(int lo, int hi);
extern f32 sqrtf(f32 x);
extern int fn_80095B18(WaterParticle *slot, int idx, int rand, f32 v);

#pragma dont_inline on
void waterfx_func06(void *obj, f32 a, f32 b, f32 c, f32 d) {
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
    slot->active = (u8)fn_80095B18(&((WaterParticle *)lbl_803DD230)[i], i, rnd, slot->f0c);
    slot->f10 = lbl_803DF300;
    slot->f14 = lbl_803DF2EC / (lbl_803DF320 * sqrtf(slot->f0c));
}

typedef struct {
    f32 x;
    f32 y;
    f32 z;
    f32 w;
    f32 f10;
    s16 f14;
    s16 active;
    s16 f18;
    u8 pad1a[2];
} WaterEntry7;

extern f32 lbl_803DF2E8;

void waterfx_func07(s16 p1, int p2, f32 a, f32 b, f32 c, f32 d) {
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

extern f32 lbl_803DF338;
extern f32 lbl_803DF33C;

void waterfx_func04(u8 *p3, u16 mask, f32 *vecs, u8 *p6, f32 fval) {
    u8 *q = p6;
    f32 *v = vecs;
    while (mask != 0) {
        if (mask & 1) {
            f32 vx = v[0];
            f32 vz = v[2];
            if (*(f32 *)(q + 0x1b4) < lbl_803DF338) {
                if (fval > lbl_803DF33C) {
                    waterfx_func06(p3, vx, *(f32 *)(p3 + 0x10) + *(f32 *)(q + 0x1b4), vz, lbl_803DF300);
                }
            }
            lbl_803DD20C = lbl_803DF318;
            waterfx_func07(*(s16 *)p3, 4, vx, *(f32 *)(p3 + 0x10) + *(f32 *)(q + 0x1b4), vz, lbl_803DF300);
            lbl_8039AB48[0] = vx;
            lbl_8039AB48[1] = *(f32 *)(p3 + 0x10) + *(f32 *)(q + 0x1b4);
            lbl_8039AB48[2] = vz;
            lbl_803DD1F8 = 1;
        }
        mask >>= 1;
        v += 3;
    }
}

typedef struct {
    int v[5];
} Tbl5;

extern int lbl_802C1FF8[];
extern int lbl_802C200C[];
extern f32 lbl_803DF35C;
extern f32 gExpgfxFrameTimerB;
extern void fn_80098B18(void *obj, int a, int b, int c, f32 *vec);

void fn_80098270(void *obj, u8 a, u8 b, f32 c, f32 d) {
    Tbl5 t1 = *(Tbl5 *)lbl_802C1FF8;
    Tbl5 t2 = *(Tbl5 *)lbl_802C200C;
    f32 vec[3];
    int frame;
    if (a == 0) {
        return;
    }
    if (b == 0) {
        return;
    }
    if (b >= 5) {
        return;
    }
    if (gExpgfxFrameTimerB != lbl_803DF35C) {
        frame = 0;
    } else {
        frame = (u8)t2.v[b];
    }
    vec[0] = lbl_803DF35C;
    vec[1] = d;
    vec[2] = lbl_803DF35C;
    if (a == 1) {
        fn_80098B18(obj, (u8)t1.v[b], frame, 0, vec);
    }
}

typedef struct {
    u16 v[11];
} Tbl11;

typedef struct {
    s16 pad[3];
    s16 f6;
    f32 f8;
    f32 vec[3];
} PartfxParams;

extern int lbl_802C2114[];
extern int lbl_803DF340;
extern u16 lbl_803DF344;
extern int *gPartfxInterface;

void hitDetectFn_80097070(void *obj, u8 a, u8 b, u8 count, void *p7, f32 fval) {
    PartfxParams params;
    Tbl11 table = *(Tbl11 *)lbl_802C2114;
    u16 ps[3];
    int i;
    *(int *)ps = lbl_803DF340;
    ps[2] = lbl_803DF344;
    if (a == 0) {
        return;
    }
    if (b == 0) {
        return;
    }
    params.f8 = fval;
    params.f6 = (s16)table.v[b];
    if (p7 != NULL) {
        params.vec[0] = *(f32 *)((char *)p7 + 0xc);
        params.vec[1] = *(f32 *)((char *)p7 + 0x10);
        params.vec[2] = *(f32 *)((char *)p7 + 0x14);
    } else {
        params.vec[0] = lbl_803DF35C;
        params.vec[1] = lbl_803DF35C;
        params.vec[2] = lbl_803DF35C;
    }
    for (i = 0; i < count; i++) {
        (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
            obj, ps[a], &params, 2, -1, 0);
    }
}

typedef struct {
    u16 v[7];
} Tbl7;

extern int lbl_802C20EC[];
extern int lbl_802C2104[];
extern f32 gExpgfxFrameTimerA;

void fn_800971A0(void *obj, u8 a, u8 b, u8 mask, void *p7, f32 fval) {
    PartfxParams params;
    Tbl11 table1 = *(Tbl11 *)lbl_802C20EC;
    Tbl7 table2 = *(Tbl7 *)lbl_802C2104;
    if (a == 0) {
        return;
    }
    if (b == 0) {
        return;
    }
    if ((mask & (u16)(int)gExpgfxFrameTimerA) == 0) {
        return;
    }
    params.f8 = fval;
    params.f6 = (s16)table1.v[b];
    if (p7 != NULL) {
        params.vec[0] = *(f32 *)((char *)p7 + 0xc);
        params.vec[1] = *(f32 *)((char *)p7 + 0x10);
        params.vec[2] = *(f32 *)((char *)p7 + 0x14);
    } else {
        params.vec[0] = lbl_803DF35C;
        params.vec[1] = lbl_803DF35C;
        params.vec[2] = lbl_803DF35C;
    }
    (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
        obj, table2.v[a], &params, 2, -1, 0);
}

typedef struct {
    f32 x;
    f32 y;
    f32 z;
    f32 f0c;
    f32 f10;
    f32 f14;
    s8 active;
    u8 pad[3];
} ExpParticle;

extern f32 lbl_803DF324;

int fn_80095B18(WaterParticle *src, int idx, int count, f32 v) {
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

extern u8 Obj_IsLoadingLocked(void);
extern u8 *Obj_AllocObjectSetup(int size, int id);
extern void Obj_SetupObject(void *obj, int a, int b, int c, int d);
extern f32 lbl_803DF3AC;
extern f32 lbl_803DF3B0;

void spawnExplosion(u8 *src, f32 fval, u8 a, u8 flag4, u8 flag8, u8 flag10, u8 doShake,
                    u8 flag20, u8 f1cinit) {
    u8 *obj;
    if (Obj_IsLoadingLocked() != 0) {
        obj = Obj_AllocObjectSetup(0x24, 0x253);
        *(u8 *)(obj + 4) = 2;
        *(u8 *)(obj + 5) = 1;
        *(f32 *)(obj + 8) = *(f32 *)(src + 0x18);
        *(f32 *)(obj + 0xc) = *(f32 *)(src + 0x1c);
        *(f32 *)(obj + 0x10) = *(f32 *)(src + 0x20);
        *(s8 *)(obj + 0x19) = (s8)a;
        *(s16 *)(obj + 0x1a) = (s16)(lbl_803DF3AC * fval);
        *(s16 *)(obj + 0x1c) = (u8)f1cinit;
        if (flag4 != 0) {
            *(s16 *)(obj + 0x1c) |= 4;
        }
        if (flag8 != 0) {
            *(s16 *)(obj + 0x1c) |= 8;
        }
        if (flag10 != 0) {
            *(s16 *)(obj + 0x1c) |= 0x10;
        }
        if (flag20 != 0) {
            *(s16 *)(obj + 0x1c) |= 0x20;
        }
        if (doShake != 0) {
            u8 *player = Obj_GetPlayerObject();
            if (player != NULL && (*(u16 *)(player + 0xb0) & 0x1000) == 0) {
                f32 d = Camera_DistanceToCurrentViewPosition(*(f32 *)(src + 0x18),
                                                             *(f32 *)(src + 0x1c),
                                                             *(f32 *)(src + 0x20));
                if (d <= lbl_803DF3B0) {
                    f32 t = lbl_803DF354 - d / lbl_803DF3B0;
                    CameraShake_Start(lbl_803DF3A0 * t, lbl_803DF384 * t, lbl_803DF3A4);
                    doRumble(lbl_803DF3A8 * t);
                }
            }
        }
        Obj_SetupObject(obj, 5, *(s8 *)(src + 0xac), -1, 0);
    }
}

void DIMexplosionFn_8009a96c(u8 *src, f32 vx, f32 vy, f32 vz, f32 fval, u8 a, u8 flag4,
                             u8 flag8, u8 flag10, u8 doShake, u8 flag20, u8 f1cinit) {
    u8 *obj;
    if (Obj_IsLoadingLocked() != 0) {
        obj = Obj_AllocObjectSetup(0x24, 0x253);
        *(u8 *)(obj + 4) = 2;
        *(u8 *)(obj + 5) = 1;
        *(f32 *)(obj + 8) = vx;
        *(f32 *)(obj + 0xc) = vy;
        *(f32 *)(obj + 0x10) = vz;
        *(s8 *)(obj + 0x19) = (s8)a;
        *(s16 *)(obj + 0x1a) = (s16)(lbl_803DF3AC * fval);
        *(s16 *)(obj + 0x1c) = (u8)f1cinit;
        if (flag4 != 0) {
            *(s16 *)(obj + 0x1c) |= 4;
        }
        if (flag8 != 0) {
            *(s16 *)(obj + 0x1c) |= 8;
        }
        if (flag10 != 0) {
            *(s16 *)(obj + 0x1c) |= 0x10;
        }
        if (flag20 != 0) {
            *(s16 *)(obj + 0x1c) |= 0x20;
        }
        if (doShake != 0) {
            u8 *player = Obj_GetPlayerObject();
            if (player != NULL && (*(u16 *)(player + 0xb0) & 0x1000) == 0) {
                f32 d = Camera_DistanceToCurrentViewPosition(*(f32 *)(src + 0x18),
                                                             *(f32 *)(src + 0x1c),
                                                             *(f32 *)(src + 0x20));
                if (d <= lbl_803DF3B0) {
                    f32 t = lbl_803DF354 - d / lbl_803DF3B0;
                    CameraShake_Start(lbl_803DF3A0 * t, lbl_803DF384 * t, lbl_803DF3A4);
                    doRumble(lbl_803DF3A8 * t);
                }
            }
        }
        Obj_SetupObject(obj, 5, *(s8 *)(src + 0xac), -1, 0);
    }
}

int expgfx_acquireResourceEntry(int arg) {
    int minVal;
    int minIdx;
    int i;
    int *p;
    int *base;
    void *tex;

    i = 0;
    base = gExpgfxRuntimeData;
    p = base;
    for (; i < 0x20; i++) {
        if (*(void **)p != NULL && arg == p[2]) {
            tex = *(void **)&gExpgfxRuntimeData[i * 4];
            if (tex != NULL && *(u16 *)((char *)tex + 0xe) >= 0x4000) {
                return -1;
            }
            gExpgfxRuntimeData[i * 4 + 1] = 1000;
            return (s16)i;
        }
        p += 4;
    }
    p = base;
    for (i = 0; i < 0x20; i++) {
        if (*(void **)p == NULL) {
            gExpgfxRuntimeData[i * 4] = textureLoadAsset(arg);
            tex = *(void **)&gExpgfxRuntimeData[i * 4];
            if (tex != NULL && *(u16 *)((char *)tex + 0xe) >= 0x4000) {
                gExpgfxTextureFreeInProgress = 1;
                if (tex != NULL) {
                    textureFree((int)tex);
                }
                gExpgfxTextureFreeInProgress = 0;
                gExpgfxRuntimeData[i * 4] = 0;
                return -1;
            }
            if (tex != NULL) {
                gExpgfxRuntimeData[i * 4 + 1] = 1000;
                gExpgfxRuntimeData[i * 4 + 2] = arg;
                return (s16)i;
            }
            return -2;
        }
        p += 4;
    }
    if (Obj_IsLoadingLocked() == 0) {
        return -4;
    }
    minVal = 0xfa00;
    minIdx = 0;
    p = base;
    for (i = 0; i < 0x20; i++) {
        if (p[1] < minVal) {
            minVal = p[1];
            minIdx = i;
        }
        p += 4;
    }
    gExpgfxTextureFreeInProgress = 1;
    tex = *(void **)&gExpgfxRuntimeData[minIdx * 4];
    if (tex != NULL) {
        textureFree((int)tex);
    }
    gExpgfxTextureFreeInProgress = 0;
    gExpgfxRuntimeData[minIdx * 4] = 0;
    gExpgfxRuntimeData[minIdx * 4] = textureLoadAsset(arg);
    if (*(void **)&gExpgfxRuntimeData[minIdx * 4] != NULL) {
        gExpgfxRuntimeData[minIdx * 4 + 1] = 1000;
        gExpgfxRuntimeData[minIdx * 4 + 2] = arg;
        return (s16)minIdx;
    }
    return -3;
}

typedef struct {
    s16 a;
    s16 b;
    s16 f4;
    s16 f6;
    f32 f8;
} PartfxFlags;

void fn_80098928(void *obj, u8 mode, int p5, int p6, int p7, f32 fval) {
    PartfxFlags params;
    int i;
    u8 count;

    if (framesThisStep > 3) {
        count = 3;
    } else {
        count = framesThisStep;
    }
    params.f6 = (s16)p5;
    params.f4 = (s16)p6;
    params.f8 = fval;
    switch (mode) {
    case 1:
        params.a = 0;
        params.b = 0;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b7, &params, 1, -1, p7);
        }
        break;
    case 2:
        params.a = 1;
        params.b = 0;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b7, &params, 1, -1, p7);
        }
        break;
    case 3:
        params.a = 0;
        params.b = 1;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b7, &params, 1, -1, p7);
        }
        break;
    case 4:
        params.a = 1;
        params.b = 1;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b7, &params, 1, -1, p7);
        }
        break;
    }
}

typedef struct {
    s16 pad[3];
    s16 h6;
    f32 f8;
} PFX3;

extern f32 lbl_803DF358;
extern f32 lbl_803DF390;

void projectileParticleFxFn_80099660(void *obj, int mode) {
    PartfxParams ps;
    f32 tailScale;
    f32 scale;
    int i;

    switch (mode) {
    case 0:
        scale = lbl_803DF358;
        for (i = 10; i < 20; i += 2) {
            ps.f6 = (s16)i;
            ps.f8 = scale;
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7a0, &ps, 1, -1, 0);
        }
        tailScale = lbl_803DF390;
        break;
    case 1:
        scale = lbl_803DF354;
        for (i = 10; i < 20; i += 2) {
            ps.f6 = (s16)i;
            ps.f8 = scale;
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7a0, &ps, 1, -1, 0);
        }
        for (i = 0; i < 20; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7a0, 0, 1, -1, 0);
        }
        tailScale = lbl_803DF354;
        break;
    case 2:
        scale = lbl_803DF354;
        for (i = 10; i < 20; i += 2) {
            ps.f6 = (s16)i;
            ps.f8 = scale;
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7a1, &ps, 1, -1, 0);
        }
        for (i = 0; i < 20; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7a1, 0, 1, -1, 0);
        }
        tailScale = lbl_803DF354;
        break;
    case 3:
        scale = lbl_803DF358;
        for (i = 10; i < 20; i += 2) {
            ps.f6 = (s16)i;
            ps.f8 = scale;
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7a6, &ps, 1, -1, 0);
        }
        tailScale = lbl_803DF390;
        break;
    case 4:
        scale = lbl_803DF354;
        for (i = 10; i < 20; i += 2) {
            ps.f6 = (s16)i;
            ps.f8 = scale;
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7a6, &ps, 1, -1, 0);
        }
        for (i = 0; i < 20; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7a6, 0, 1, -1, 0);
        }
        tailScale = lbl_803DF354;
        break;
    case 6:
        scale = lbl_803DF358;
        for (i = 10; i < 20; i += 2) {
            ps.f6 = (s16)i;
            ps.f8 = scale;
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7a1, &ps, 1, -1, 0);
        }
        tailScale = lbl_803DF390;
        break;
    default:
        return;
    }
    (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
        obj, 0x79f, 0, 1, -1, &tailScale);
}

void itemPickupDoParticleFx(void *obj, int mode, u8 count, f32 fval) {
    PartfxParams params;
    int i;

    params.f8 = fval;
    if (mode == 0) {
        return;
    }
    switch (mode) {
    case 1:
        params.f6 = 0x79;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b1, &params, 1, -1, 0);
        }
        break;
    case 2:
        params.f6 = 0xc13;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b1, &params, 1, -1, 0);
        }
        break;
    case 3:
        params.f6 = 0x71;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b1, &params, 1, -1, 0);
        }
        break;
    case 4:
        params.f6 = 0xdb;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b1, &params, 1, -1, 0);
        }
        break;
    case 5:
        params.f6 = 0x77;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b1, &params, 1, -1, 0);
        }
        break;
    case 6:
        params.f6 = 0x7b;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b1, &params, 1, -1, 0);
        }
        break;
    case 7:
        params.f6 = 0xda;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b1, &params, 1, -1, 0);
        }
        break;
    case 8:
        params.f6 = 0xdd;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7cc, &params, 1, -1, 0);
        }
        break;
    case 10:
        params.f6 = 0xde;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7cc, &params, 1, -1, 0);
        }
        break;
    case 9:
        params.f6 = 0xdf;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7cc, &params, 1, -1, 0);
        }
        break;
    default:
        params.f6 = 0x5c;
        for (i = 0; i < count; i++) {
            (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
                obj, 0x7b1, &params, 1, -1, 0);
        }
        break;
    }
}

typedef struct {
    u16 v[9];
} ParticleTblA;

typedef struct {
    u16 v[8];
} ParticleTbl8;

extern int lbl_802C1FD8[];
extern f32 lbl_803DF350;
extern f32 lbl_803DF358;
extern f32 lbl_803DF368;
extern f32 lbl_803DF36C;
extern f32 lbl_803DF370;
extern f32 sin(f32 x);
extern f32 fn_80293E80(f32 x);
extern void mathFn_80021ac8(void *in, f32 *out);

void objParticleFn_80097734(void *obj, u8 idx, u8 kind, u8 mode, u8 chance,
                            void *origin, int flags, f32 f8val, f32 angBase,
                            f32 lo, f32 hi) {
    PartfxParams params;
    ParticleTblA tA = *(ParticleTblA *)((char *)lbl_802C1FD8 + 0x8c);
    ParticleTbl8 tB = *(ParticleTbl8 *)((char *)lbl_802C1FD8 + 0xa0);
    ParticleTbl8 tC = *(ParticleTbl8 *)((char *)lbl_802C1FD8 + 0xb0);
    ParticleTbl8 tD = *(ParticleTbl8 *)((char *)lbl_802C1FD8 + 0xc0);
    u16 rvec[3];
    int i;
    f32 fdelta;
    f32 f30;
    f32 f29;

    params.f8 = f8val;
    params.f6 = (s16)tA.v[kind];
    params.pad[1] = 0x3c;
    fdelta = angBase - lo;
    for (i = 0; i < 4; i++) {
        u16 val;
        f32 a;
        if (randomGetRange(0, 0x63) >= chance) {
            continue;
        }
        rvec[0] = (u16)randomGetRange(0, 0xffff);
        rvec[1] = 0;
        rvec[2] = 0;
        f30 = (f32)randomGetRange(1, 1000) / lbl_803DF368;
        f29 = (f32)randomGetRange(0, 1000) / lbl_803DF368;
        params.vec[1] = lbl_803DF35C;
        params.vec[2] = lbl_803DF35C;
        switch (mode) {
        case 1:
            params.vec[0] = lbl_803DF354 - f30 * f30;
            break;
        case 2:
            f29 = f29 * (f29 * f29);
            params.vec[0] = lbl_803DF354 - f30 * f30;
            break;
        case 3:
            f29 = lbl_803DF354 - f29 * (f29 * f29);
            params.vec[0] = lbl_803DF354 - f30 * f30;
            break;
        case 4:
            val = (u16)(int)(lbl_803DF350 * f29);
            a = lbl_803DF36C * (f32)(u32)val / lbl_803DF370;
            f29 = lbl_803DF358 * (lbl_803DF354 + (f32)sin(a));
            params.vec[0] = lbl_803DF354 - f30 * f30;
            break;
        case 5:
            val = (u16)(int)(lbl_803DF350 * f29);
            a = lbl_803DF36C * (f32)(u32)val / lbl_803DF370;
            f29 = lbl_803DF358 * (lbl_803DF354 + fn_80293E80(a));
            params.vec[0] = lbl_803DF354 - f30 * f30;
            break;
        case 6:
            params.vec[0] = f30 * f30;
            break;
        case 7:
            params.vec[0] = lbl_803DF354 - f30 * (f30 * (f30 * (f30 * f30)));
            break;
        }
        params.vec[0] = params.vec[0] * (f29 * fdelta + lo);
        mathFn_80021ac8(rvec, params.vec);
        params.vec[1] = (f29 - lbl_803DF358) * hi;
        if (origin != NULL) {
            params.vec[0] += *(f32 *)((char *)origin + 0xc);
            params.vec[1] += *(f32 *)((char *)origin + 0x10);
            params.vec[2] += *(f32 *)((char *)origin + 0x14);
        }
        params.pad[2] = (s16)tC.v[idx];
        params.pad[0] = (s16)tD.v[idx];
        (*(void (*)(void *, int, void *, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
            obj, tB.v[idx], &params, flags | 2, -1, 0);
    }
}

typedef struct {
    u16 v[15];
} ColorTbl;

extern int *lbl_803DCAB4;
extern f32 lbl_803DF394;
extern f32 lbl_803DF398;
extern void modelLightStruct_setField50(void *light, int v);
extern void lightVecFn_8001dd88(void *light, f32 x, f32 y, f32 z);
extern void modelLightStruct_setColorsA8AC(void *light, int r, int g, int b, int a);
extern void modelLightStruct_setColors100104(void *light, int r, int g, int b, int a);
extern void lightDistAttenFn_8001dc38(void *light, f32 a, f32 b);
extern void lightSetField4D(void *light, int v);
extern void lightFn_8001db6c(void *light, f32 a, int b);
extern void lightFn_8001d620(void *light, int a, int b);
extern void lightSetField2FB(void *light, int v);

void objParticleFn_80099d84(void *obj, u8 type, void *light, f32 scale, f32 fextra) {
    f32 p8 = fextra;
    PartfxParams params;
    ColorTbl colors = *(ColorTbl *)lbl_802C1FD8;
    f32 zoff = lbl_803DF394;
    u8 *cbuf;

    params.f8 = scale;
    params.pad[0] = 0;
    params.pad[2] = 0;
    params.pad[1] = 0;
    params.f6 = 0xc0a;
    switch (type) {
    case 1:
        params.vec[0] = scale * (f32)randomGetRange(-10, 10);
        params.vec[1] = scale * (f32)randomGetRange(-10, 10);
        params.vec[2] = scale * (f32)randomGetRange(-10, 10);
        (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
            obj, 0x32f, &params, 2, -1, &p8);
        break;
    case 2:
        params.vec[0] = scale * (f32)randomGetRange(-10, 10);
        params.vec[1] = scale * (f32)randomGetRange(-10, 10);
        params.vec[2] = scale * (f32)randomGetRange(-10, 10);
        (*(void (*)(void *, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 8)))(
            obj, 0x330, &params, 2, -1, &p8);
        break;
    case 3:
        (*(void (*)(void *, int, void *, int, int))(*(int *)(*lbl_803DCAB4 + 0xc)))(
            obj, 0x32f, &p8, 0x19, 0);
        break;
    case 4:
        (*(void (*)(void *, int, void *, int, int))(*(int *)(*lbl_803DCAB4 + 0xc)))(
            obj, 0x330, &p8, 0x19, 0);
        break;
    case 5:
        params.f6 = 0xc0a;
        (*(void (*)(void *, int, void *, int, void *))(*(int *)(*lbl_803DCAB4 + 0xc)))(
            obj, 0x7cd, &p8, 0x32, &params);
        break;
    case 6:
        params.f6 = 0xc0d;
        (*(void (*)(void *, int, void *, int, void *))(*(int *)(*lbl_803DCAB4 + 0xc)))(
            obj, 0x7ce, &p8, 0x50, &params);
        break;
    case 7:
        params.f6 = 0x605;
        params.pad[2] = 1;
        (*(void (*)(void *, int, void *, int, void *))(*(int *)(*lbl_803DCAB4 + 0xc)))(
            obj, 0x7cf, &p8, 0x19, &params);
        zoff = lbl_803DF35C;
        break;
    case 8:
        params.f6 = 0x605;
        params.pad[2] = 0;
        (*(void (*)(void *, int, void *, int, void *))(*(int *)(*lbl_803DCAB4 + 0xc)))(
            obj, 0x7cf, &p8, 0x19, &params);
        zoff = lbl_803DF35C;
        break;
    }

    if (light != NULL) {
        modelLightStruct_setField50(light, 2);
        lightVecFn_8001dd88(light, *(f32 *)((char *)obj + 0x18),
                            *(f32 *)((char *)obj + 0x1c) + zoff,
                            *(f32 *)((char *)obj + 0x20));
        cbuf = (u8 *)&colors;
        modelLightStruct_setColorsA8AC(light, cbuf[type * 3], cbuf[type * 3 + 1],
                                       cbuf[type * 3 + 2], 0xff);
        modelLightStruct_setColors100104(light, cbuf[type * 3], cbuf[type * 3 + 1],
                                         cbuf[type * 3 + 2], 0xff);
        lightDistAttenFn_8001dc38(light, lbl_803DF34C, lbl_803DF398);
        lightSetField4D(light, 0);
        lightFn_8001db6c(light, lbl_803DF35C, 1);
        lightFn_8001db6c(light, lbl_803DF354, 0);
        lightFn_8001d620(light, 0, 0);
        lightSetField2FB(light, 1);
    }
}
#pragma peephole reset
#pragma scheduling reset
