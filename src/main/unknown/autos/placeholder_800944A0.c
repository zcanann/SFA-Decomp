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
    int i;
    char *e;

    e = (char *)gExpgfxRuntimeData;
    for (i = 0; i < 0x20; i++) {
        if (*(int *)(e + 8) != 0) {
            *(int *)(e + 4) = *(int *)(e + 4) - framesThisStep;
            if (*(int *)(e + 4) <= 0) {
                *(int *)(e + 8) = 0;
                *(int *)(e + 4) = 0;
                *(int *)(e + 0xc) = 0;
                gExpgfxTextureFreeInProgress = 1;
                textureFree(*(int *)e);
                gExpgfxTextureFreeInProgress = 0;
                *(int *)e = 0;
            }
        }
        e += 0x10;
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
#pragma peephole reset
#pragma scheduling reset
