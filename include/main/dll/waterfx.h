#ifndef MAIN_DLL_WATERFX_H_
#define MAIN_DLL_WATERFX_H_

#include "global.h"
#include "main/dll/waterfx_interface.h"
#include "main/texture.h"

typedef struct WaterVtx
{
    s16 x;
    s16 y;
    s16 z;
    s16 pad6;
    s16 u;
    s16 v;
    u8 padc[3];
    u8 a;
} WaterVtx;

typedef struct WaterEntry
{
    f32 x;
    f32 y;
    f32 z;
    f32 w;
    f32 scale;
    s16 active;
    s16 rot;
    u8 f18;
    u8 pad19[3];
} WaterEntry;

typedef struct WaterParticle
{
    f32 x;
    f32 y;
    f32 z;
    f32 size;
    f32 life;
    f32 lifeSpeed;
    u8 vtxColors[0x20];
    u8 dropCount;
    u8 pad39[3];
} WaterParticle;

typedef struct WaterEntry7
{
    f32 x;
    f32 y;
    f32 z;
    f32 w;
    f32 scale;
    s16 rot;
    s16 active;
    s16 fadeRate;
    u8 pad1a[2];
} WaterEntry7;

typedef struct WaterDrop
{
    f32 x;
    f32 y;
    f32 z;
    f32 vx;
    f32 vy;
    f32 vz;
    s8 parentIdx;
    u8 pad19[3];
} WaterDrop;

typedef struct WaterVtxDesc
{
    u8 pad0;
    u8 b1;
    u8 b2;
    u8 b3;
    u8 pad4[12];
} WaterVtxDesc;

extern f32 gWaterfxRippleScale;
extern f32 lbl_803DF318;
extern f32 lbl_803DF300;
extern f32 lbl_803DF31C;
extern f32 lbl_803DF2EC;
extern f32 lbl_803DF2FC;
extern f32 lbl_803DF320;
extern f32 lbl_803DF2E8;
extern f32 lbl_803DF338;
extern f32 lbl_803DF33C;
extern f32 lbl_803DF334;
extern u8 gWaterfxPendingImpactPositionValid;
extern f32 gWaterfxPendingImpactPosition[];
extern char sWaterfxDllAllocFailed[];
extern void* gWaterfxSplashTexCoordArray;
extern void* gWaterfxSplashPosArray;
extern void* gWaterfxSplashDisplayList;
extern Texture* gWaterfxWakeTexture;
extern Texture* gWaterfxSplashTexture1;
extern Texture* gWaterfxSplashTexture0;
extern Texture* gWaterfxRippleTexture;
extern void* gWaterfxDropPool;
extern int gWaterfxDropCount;
extern void* gWaterfxWakePool;
extern int gWaterfxWakeCount;
extern void* gWaterfxSplashPool;
extern int gWaterfxSplashCount;
extern void* gWaterfxRipplePool;
extern int gWaterfxRippleCount;
extern u8* gWaterfxWakeVtxDesc;
extern u8* gWaterfxWakeVtx;
extern u8* gWaterfxRippleVtxDesc;
extern u8* gWaterfxRippleVtx;
extern f32 gWaterfxWakeGrowSpeed;
extern f32 gWaterfxDropGravity;
extern const f32 gWaterfxDropDamping;
extern f32 gWaterfxRippleGrowSpeed;

void waterfx_setupSplashDropPointRender(void);
void waterfx_buildSplashDisplayList(void);
int waterfx_consumePendingImpactNearPoint(f32* vec, f32 dist);
void waterfx_spawnRipple(f32 a, f32 b, f32 c, s16 p1, f32 d, int p2);
void waterfx_setRippleScale(int flag, f32 val);
void waterfx_spawnSimpleRipple(f32 a, f32 b, f32 c, s16 p1, f32 d);
void waterfx_spawnSplashBurst(void* obj, f32 a, f32 b, f32 c, f32 d);
int waterfx_spawnSplashDrops(WaterParticle* src, int idx, int count, f32 v);
void waterfx_render(int p1, int p2);
void waterfx_run(int frames);
void waterfx_spawnImpactSurface(u8* p3, u16 mask, f32* vecs, u8* p6, f32 fval);
void waterfx_onMapSetup(void);
void waterfx_release(void);
void waterfx_initialise(void);
void waterfx_drawSplashBurst(WaterParticle* particle);

#endif /* MAIN_DLL_WATERFX_H_ */
