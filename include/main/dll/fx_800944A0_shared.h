#ifndef SFA_DLL_FX_800944A0_SHARED_H
#define SFA_DLL_FX_800944A0_SHARED_H

#include "ghidra_import.h"
#include "main/cloud_action_runtime.h"
#include "main/cloud_layer_state.h"
#include "main/effect_interfaces.h"
#include "main/objtexture.h"
#include "main/resource.h"
#include "main/sky_interface.h"

/* typedefs (verbatim from placeholder_800944A0) */
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
typedef struct {
    u16 v[11];
} Tbl11;
typedef struct {
    s16 pad[3];
    s16 f6;
    f32 f8;
    f32 vec[3];
} PartfxParams;
typedef struct {
    u16 v[7];
} Tbl7;
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
typedef struct {
    u16 v[9];
} ParticleTblA;
typedef struct {
    u16 v[8];
} ParticleTbl8;
typedef struct {
    int a[5];
    int b[4];
    int c[5];
} CloudEnvTbl;
typedef struct {
    u16 a;
    u16 b;
} ParticlePair;
typedef struct {
    ParticlePair e[13];
} ParticlePairTbl;
typedef struct {
    u16 v[15];
} ColorTbl;

/* external symbol declarations */
extern f32 lbl_803DF318;
extern f32 lbl_803DF348;
extern f32 lbl_803DF34C;
extern f32 lbl_803DB790;
extern f32 gWaterfxRippleScale;
extern int lbl_803DB618[2];
extern u8 gWaterfxPendingImpactPositionValid;
extern f32 gWaterfxPendingImpactPosition[];
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
extern void waterfx_drawFn_800953fc(void);
extern void *gWaterfxSplashTexCoordArray;
extern void *gWaterfxSplashPosArray;
extern void *gWaterfxSplashDisplayList;
extern void *gWaterfxWakeTexture;
extern void *gWaterfxSplashTexture1;
extern void *gWaterfxSplashTexture0;
extern void *gWaterfxRippleTexture;
extern void *gWaterfxDropPool;
extern void *gWaterfxDropCount;
extern void *gWaterfxWakePool;
extern void *gWaterfxWakeCount;
extern void *gWaterfxSplashPool;
extern void *gWaterfxSplashCount;
extern void *gWaterfxRipplePool;
extern void *gWaterfxRippleCount;
extern void *gWaterfxWakeVtxDesc;
extern void *gWaterfxWakeVtx;
extern void *gWaterfxRippleVtxDesc;
extern void *gWaterfxRippleVtx;
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
extern u8 *Obj_GetPlayerObject(void);
extern f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z);
extern void CameraShake_Start(f32 a, f32 b, f32 c);
extern void doRumble(f32 v);
extern const f32 lbl_803DF354;
extern f32 lbl_803DF384;
extern f32 lbl_803DF3A0;
extern f32 lbl_803DF3A4;
extern f32 lbl_803DF3A8;
extern f32 lbl_803DF300;
extern f32 lbl_803DF31C;
extern f32 lbl_803DF2EC;
extern f32 lbl_803DF2FC;
extern f32 lbl_803DF320;
extern int randomGetRange(int lo, int hi);
extern f32 sqrtf(f32 x);
extern f32 lbl_803DF2E8;
extern f32 lbl_803DF338;
extern f32 lbl_803DF33C;
extern f32 timeDelta;
extern f32 gWaterfxRippleGrowSpeed;
extern f32 gWaterfxWakeGrowSpeed;
extern f32 gWaterfxDropGravity;
extern const f32 gWaterfxDropDamping;
extern f32 lbl_803DF334;
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
extern int lbl_802C1FF8[];
extern int lbl_802C200C[];
extern const f32 lbl_803DF35C;
extern f32 gExpgfxFrameTimerB;
extern void fn_80098B18(void *obj, f32 scale, int type, int count, int mode, f32 *vec);
extern int lbl_802C2114[];
extern int lbl_803DF340;
extern u16 lbl_803DF344;
extern f32 lbl_803DF380;
extern void vecRotateZXY(void *obj, f32 *vec);
extern void Camera_ProjectWorldPointWithOffset(f32 *ox, f32 *oy, f32 *oz, f32 x, f32 y, f32 z, f32 w);
extern void Camera_NdcToScreen(int *sx, int *sy, int *sz, f32 x, f32 y, f32 z);
extern int depthReadRequestPoll(int x, int y, void *obj);
extern int lbl_802C20EC[];
extern int lbl_802C2104[];
extern f32 gExpgfxFrameTimerA;
extern f32 gWaterfxRippleGrowSpeed;
extern u8 Obj_IsLoadingLocked(void);
extern u8 *Obj_AllocObjectSetup(int size, int id);
extern void *Obj_SetupObject(void *obj, int a, int b, int c, int d);
extern f32 lbl_803DF3AC;
extern f32 lbl_803DF3B0;
extern const f32 lbl_803DF358;
extern f32 lbl_803DF390;
extern int gObjFxCrystalSparkleTbl[];
extern const f32 lbl_803DF350;
extern const f32 lbl_803DF358;
extern f32 lbl_803DF368;
extern f32 gObjFxPi;
extern f32 lbl_803DF370;
extern f32 mathCosf(f32 x);
extern f32 mathSinf(f32 x);
extern void vecRotateZXY(void *in, f32 *out);
extern int gCloudActionEnvTbl[];
extern f32 lbl_803DF2DC;
extern int saveGameGetEnvState(void);
extern int gObjFxRandomBurstTbl[];
extern f32 lbl_803DF394;
extern f32 lbl_803DF398;
extern void modelLightStruct_setLightKind(void *light, int v);
extern void modelLightStruct_setPosition(void *light, f32 x, f32 y, f32 z);
extern void modelLightStruct_setDiffuseColor(void *light, int r, int g, int b, int a);
extern void modelLightStruct_setSpecularColor(void *light, int r, int g, int b, int a);
extern void modelLightStruct_setDistanceAttenuation(void *light, f32 a, f32 b);
extern void lightSetField4D(void *light, int v);
extern void modelLightStruct_setEnabled(void *light, int b, f32 a);
extern void modelLightStruct_startColorFade(void *light, int a, int b);
extern void modelLightStruct_setAffectsAabbLightSelection(void *light, int v);

/* forward declarations for graduated FX functions */
void cloudaction_func08_nop(void);
void cloudaction_func09_nop(void);
void cloudaction_free(void);
void cloudaction_func05(void);
void cloudaction_onMapSetup(void);
void cloudaction_update(int p1, int p2, u8 *state, int p4, int val);
void cloudaction_release(void);
void cloudaction_initialise(void);
void waterfx_setupSplashDropPointRender(void);
int waterfx_consumePendingImpactNearPoint(f32 *vec, f32 dist);
void waterfx_spawnRipple(f32 a, f32 b, f32 c, s16 p1, f32 d, int p2);
void waterfx_setRippleScale(int flag, f32 val);
void waterfx_func08(s16 p1, f32 a, f32 b, f32 c, f32 d);
void waterfx_spawnSplashBurst(void *obj, f32 a, f32 b, f32 c, f32 d);
int waterfx_spawnSplashDrops(WaterParticle *src, int idx, int count, f32 v);
void waterfx_func05(int p1, int p2);
void waterfx_run(void);
void waterfx_func04(u8 *p3, u16 mask, f32 *vecs, u8 *p6, f32 fval);
void waterfx_onMapSetup(void);
void waterfx_release(void);
void waterfx_initialise(void);
void viewFinderSetZoom(f32 zoom);
void viewFinderSetZoomTo50(void);
void objfx_spawnRandomBurst(void *obj, u8 type, u8 count, void *origin, u8 flagByte, f32 mult);
void objfx_spawnHitEmitterAtPos(f32 *pos, u8 a, u8 b, u8 c, u8 d);
void hitDetectFn_80097070(void *obj, u8 a, u8 b, u8 count, void *p7, f32 fval);
void objfx_spawnMaskedHitEffect(void *obj, u8 a, u8 b, u8 mask, void *p7, f32 fval);
void objfx_spawnDirectionalBurst(void *obj, u8 idx, f32 f8val, u8 kind, u8 mode, u8 chance,
                    f32 mult, void *origin, int flags);
void objfx_spawnArcedBurst(void *obj, u8 idx, f32 f8val, u8 kind, u8 mode, u8 chance,
                            f32 angBase, f32 lo, f32 hi, void *origin, int flags);
void objfx_spawnBoxBurst(void *obj, u8 idx, f32 f8val, u8 kind, u8 mode, u8 chance,
                         f32 mulX, f32 mulY, f32 mulZ, void *origin, int flags);
void objShowButtonGlow(void *obj, u8 mode, f32 intensity);
void objfx_spawnFrameTimedHitPulse(void *obj, u8 a, u8 b, f32 c, f32 d);
void objfx_spawnLightPulse(void *obj, u8 type, int a3, u8 mode, void *light, f32 fa, f32 fb);
void objfx_spawnFlaggedTrailBurst(void *obj, u8 mode, int p5, int p6, int p7, f32 fval);
void projectileParticleFxFn_80099660(void *obj, int mode);
void itemPickupDoParticleFx(void *obj, int mode, u8 count, f32 fval);
void objParticleFn_80099d84(void *obj, f32 scale, int type, f32 fextra, void *light);
void fn_8009A8C8(u8 *obj, f32 thresh);
void DIMexplosionFn_8009a96c(u8 *src, f32 vx, f32 vy, f32 vz, f32 fval, u8 a, u8 flag4,
                             u8 flag8, u8 flag10, u8 doShake, u8 flag20, u8 f1cinit);
void spawnExplosion(u8 *src, f32 fval, u8 a, u8 flag4, u8 flag8, u8 flag10, u8 doShake,
                    u8 flag20, u8 f1cinit);
void expgfx_updateResourceEntries(int unused);
int expgfx_acquireResourceEntry(int resourceId);

#endif
