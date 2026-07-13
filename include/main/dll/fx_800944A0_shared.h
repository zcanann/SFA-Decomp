#ifndef SFA_DLL_FX_800944A0_SHARED_H
#define SFA_DLL_FX_800944A0_SHARED_H

#include "ghidra_import.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/debug.h"
#include "main/shader_api.h"
#include "main/vecmath.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/object.h"
#include "main/dll/objfx_api.h"
#include "main/mm.h"
#include "main/cloud_action_runtime.h"
#include "main/cloud_layer_state.h"
#include "main/camera.h"
#include "main/effect_interfaces.h"
#include "main/objtexture.h"
#include "main/texture.h"
#include "main/resource.h"
#include "main/sky_interface.h"
#include "main/frame_timing.h"
#include "main/lightmap_api.h"
#include "main/objfx_hit_emitter_api.h"
#include "main/dll/expgfx_resource_api.h"
#include "main/pad_api.h"
#include "main/dll/waterfx.h"
#include "main/dll/cloudaction.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "dolphin/gx/GXLegacyDecls.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "track/intersect_api.h"

/* typedefs (verbatim from placeholder_800944A0) */
typedef struct
{
    u16 h18;
    u16 h1a;
    u16 h1c;
    u16 pad;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} ParticleEmit;
typedef struct
{
    int v[5];
} Tbl5;
typedef struct
{
    u16 v[11];
} Tbl11;
typedef struct
{
    s16 pad[3];
    s16 f6;
    f32 f8;
    f32 vec[3];
} PartfxParams;
typedef struct
{
    u16 v[7];
} Tbl7;
typedef struct
{
    f32 x;
    f32 y;
    f32 z;
    f32 f0c;
    f32 f10;
    f32 f14;
    s8 active;
    u8 pad[3];
} ExpParticle;
typedef struct
{
    s16 a;
    s16 b;
    s16 f4;
    s16 f6;
    f32 f8;
} PartfxFlags;
typedef struct
{
    s16 pad[3];
    s16 h6;
    f32 f8;
} PFX3;
typedef struct
{
    u16 v[9];
} ParticleTblA;
typedef struct
{
    u16 v[8];
} ParticleTbl8;
typedef struct
{
    u16 a;
    u16 b;
} ParticlePair;
typedef struct
{
    ParticlePair e[13];
} ParticlePairTbl;
typedef struct
{
    u16 v[15];
} ColorTbl;

/* external symbol declarations */
extern f32 lbl_803DF348;
extern f32 lbl_803DF34C;
extern f32 lbl_803DB790;
extern void* memset(void* dst, int c, int n);
extern const f32 lbl_803DF354;
extern f32 lbl_803DF384;
extern f32 lbl_803DF3A0;
extern f32 lbl_803DF3A4;
extern f32 lbl_803DF3A8;
extern void fn_800542F4(void);
extern int lbl_802C1FF8[];
extern int lbl_802C200C[];
extern const f32 lbl_803DF35C;
extern f32 gExpgfxFrameTimerB;
extern int lbl_802C2114[];
extern int lbl_803DF340;
extern u16 lbl_803DF344;
extern f32 lbl_803DF380;
extern int depthReadRequestPoll(int x, int y, void* obj);
extern int lbl_802C20EC[];
extern int lbl_802C2104[];
extern f32 gExpgfxFrameTimerA;
extern f32 lbl_803DF3AC;
extern f32 lbl_803DF3B0;
extern f32 lbl_803DF390;
extern int gObjFxCrystalSparkleTbl[];
extern const f32 lbl_803DF350;
extern const f32 lbl_803DF358;
extern f32 lbl_803DF368;
extern f32 gObjFxPi;
extern f32 lbl_803DF370;
extern int gObjFxRandomBurstTbl[];
extern f32 lbl_803DF394;
extern f32 lbl_803DF398;
extern void modelLightStruct_setLightKind(void* light, int v);
extern void modelLightStruct_setPosition(void* light, f32 x, f32 y, f32 z);
extern void modelLightStruct_setDiffuseColor(void* light, int r, int g, int b, int a);
extern void modelLightStruct_setSpecularColor(void* light, int r, int g, int b, int a);
extern void modelLightStruct_setDistanceAttenuation(void* light, f32 a, f32 b);
extern void modelLightStruct_setEnabled(void* light, int b, f32 a);
extern void modelLightStruct_startColorFade(void* light, int a, int b);

/* forward declarations for graduated FX functions */
void objShowButtonGlow(void* obj, u8 mode, f32 intensity);
void objfx_spawnFlaggedTrailBurst(void* obj, u8 mode, int p5, int p6, int p7, f32 fval);

#endif
