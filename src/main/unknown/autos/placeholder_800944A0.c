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


#pragma scheduling off
#pragma peephole off





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



extern u8 *Obj_GetPlayerObject(void);
extern f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z);
extern void CameraShake_Start(f32 a, f32 b, f32 c);
extern void doRumble(f32 v);
extern f32 lbl_803DF354;
extern f32 lbl_803DF384;
extern f32 lbl_803DF3A0;
extern f32 lbl_803DF3A4;
extern f32 lbl_803DF3A8;


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

#pragma dont_inline reset

extern f32 lbl_803DF338;
extern f32 lbl_803DF33C;


extern f32 timeDelta;
extern f32 lbl_803DF324;
extern f32 lbl_803DF328;
extern f32 lbl_803DF32C;
extern f32 lbl_803DF330;
extern f32 lbl_803DF334;

typedef struct {
    f32 x;
    f32 y;
    f32 z;
    f32 f0c;
    f32 f10;
    f32 f14;
    s8 idx;
    u8 pad19[3];
} WaterDrop;


typedef union {
    u8 u8;
    u16 u16;
    u32 u32;
    s16 s16;
    s32 s32;
    f32 f32;
} PPCWGPipe;
volatile PPCWGPipe GXWGFifo : (0xCC008000);

extern void GXSetArray(int attr, void *base, int stride);
extern void GXBegin(int type, int fmt, int count);
extern void setTextColor(int unused, int a, int b, int c, int d);
extern void Camera_LoadModelViewMatrix(int p1, int p2, void *obj, f32 scale, f32 unused, int p6);
extern void drawFn_8005cf8c(void *matrix, void *displayList, int count);
extern void fn_8007D670(void);
extern void fn_8007CAF4(int a);
extern void fn_8007BD8C(int a, int b);
extern void fn_8007C664(int a);
extern void fn_800542F4(void);
extern void fn_80095164(WaterParticle *s);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

typedef struct {
    s16 f8;
    s16 fa;
    s16 fc;
    u8 pade[2];
    f32 f10;
    f32 x;
    f32 y;
    f32 z;
} WaterDrawObj;


typedef struct {
    u8 pad0;
    u8 b1;
    u8 b2;
    u8 b3;
    u8 pad4[12];
} VtxDesc;


typedef struct {
    int v[5];
} Tbl5;

extern int lbl_802C1FF8[];
extern int lbl_802C200C[];
extern f32 lbl_803DF35C;
extern f32 gExpgfxFrameTimerB;
extern void fn_80098B18(void *obj, int a, int b, int c, f32 *vec);


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

extern f32 lbl_803DF380;
extern void mathFn_80021ac8(void *obj, f32 *vec);
extern void Camera_ProjectWorldPointWithOffset(f32 *ox, f32 *oy, f32 *oz, f32 x, f32 y, f32 z, f32 w);
extern void Camera_NdcToScreen(int *sx, int *sy, int *sz, f32 x, f32 y, f32 z);
extern int maybeReadDepthBuffer(int x, int y, void *obj);



typedef struct {
    u16 v[7];
} Tbl7;

extern int lbl_802C20EC[];
extern int lbl_802C2104[];
extern f32 gExpgfxFrameTimerA;


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


extern u8 Obj_IsLoadingLocked(void);
extern u8 *Obj_AllocObjectSetup(int size, int id);
extern void *Obj_SetupObject(void *obj, int a, int b, int c, int d);
extern f32 lbl_803DF3AC;
extern f32 lbl_803DF3B0;



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


typedef struct {
    s16 pad[3];
    s16 h6;
    f32 f8;
} PFX3;

extern f32 lbl_803DF358;
extern f32 lbl_803DF390;



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

typedef struct {
    int a[5];
    int b[4];
    int c[5];
} CloudEnvTbl;

extern int lbl_8030F7B0[];
extern f32 lbl_803DF2DC;
extern int saveGameGetEnvState(void);


typedef struct {
    u16 a;
    u16 b;
} ParticlePair;

typedef struct {
    ParticlePair e[13];
} ParticlePairTbl;

extern int lbl_802C212C[];






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

#pragma peephole reset
#pragma scheduling reset
