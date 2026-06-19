#ifndef MAIN_DLL_MODGFX_H_
#define MAIN_DLL_MODGFX_H_

#include "ghidra_import.h"
#include "main/expgfx_internal.h"
#include "main/object_descriptor.h"
#include "main/rcp_dolphin.h"

extern ObjectDescriptor11 projgfx_funcs;
extern char sProjgfxReleaseDoNoLongerSupported[];
extern char sProjgfxRayhitDoNoLongerSupported[];
extern char sProjgfxSetzscaleDoNoLongerSupported[];

#define PROJGFX_SPAWN_FLAG_USE_ATTACHED_SOURCE 0x200000

extern u32 FUN_800033a8();
extern u32 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern u32 FUN_80017814();
extern u32 FUN_80017830();
extern u32 FUN_80017ac8();
extern u32 FUN_802420e0();
extern u64 FUN_80286840();
extern u32 FUN_8028688c();

void modgfx_releaseExpgfxPools(void);
void modgfx_allocExpgfxPools(void);
void modgfx_scrollVertexTexcoords(int param_1,int param_2);
void modgfx_resetBaseVertexState(int param_1);
void modgfx_updateVertexRgb(int param_1,int param_2,int param_3);
void modgfx_updateEffectPosition(int state,int command,int mode);
void modgfx_updateEffectRotation(int state,int command,int mode);
void modgfx_updateVertexAlpha(int param_1,int param_2,int param_3,u32 param_4);
void modgfx_updateVertexScale(int param_1,int param_2,int param_3,u32 param_4);
void modgfx_restoreActiveVertexState(int param_1);
void modgfx_releaseActiveEffectsByType(u64 param_1,u64 param_2,u64 param_3,
                                       u64 param_4,u64 param_5,u64 param_6,
                                       u64 param_7,u64 param_8,short param_9,
                                       int param_10);
void FUN_800a1338(void);
void FUN_800a133c(double param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void modgfx_releaseActiveEffectsByOwner(u64 param_1,u64 param_2,u64 param_3,
                                        u64 param_4,u64 param_5,u64 param_6,
                                        u64 param_7,u64 param_8,int param_9);
void modgfx_releaseAllActiveEffects(u64 param_1,u64 param_2,u64 param_3,
                                    u64 param_4,u64 param_5,u64 param_6,
                                    u64 param_7,u64 param_8);
void FUN_800a15d0(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_800a15d4(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,int param_11,u16 *param_12,
                 int param_13,u16 *param_14,u32 param_15,int param_16);
void modgfx_resetActiveEffectRegistry(u64 param_1,u64 param_2,u64 param_3,
                                      u64 param_4,u64 param_5,u64 param_6,
                                      u64 param_7,u64 param_8);
void FUN_800a1804(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
u32 FUN_800a1954(void);
u32 FUN_800a1978(void);
void FUN_800a199c(void);
void FUN_800a19bc(u64 param_1,double param_2,u32 param_3,u32 param_4,
                 int param_5);
void FUN_800a1de4(int param_1);
void FUN_800a1f80(u32 param_1,u32 param_2,u32 param_3);
void FUN_800a2620(u32 param_1,u32 param_2,u32 param_3,u32 param_4,
                 u16 *param_5);
void FUN_800a2730(void);
void FUN_800a2734(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_800a2994(u32 param_1,u32 param_2,short *param_3,u32 param_4,
                 u32 param_5,float *param_6);
void FUN_800a2998(void);
void FUN_800a299c(void);
void FUN_800a29a0(u32 param_1,u32 param_2,ExpgfxAttachedSourceState *param_3,
                 u32 param_4,u8 param_5);
void FUN_800a29a4(void);
u32
FUN_800a2a98(int param_1,int param_2,ExpgfxAttachedSourceState *param_3,u32 param_4,
             u8 param_5);
void FUN_800a2aa0(void);
void FUN_800a2b94(u32 param_1,u32 param_2,ExpgfxAttachedSourceState *param_3,
                 u32 param_4,u8 param_5,float *param_6);
void FUN_800a2b98(u32 param_1,u32 param_2,ExpgfxAttachedSourceState *param_3,
                 u32 param_4,u8 param_5);
void FUN_800a2b9c(void);
void FUN_800a2c90(u32 param_1,u32 param_2,ExpgfxAttachedSourceState *param_3,
                 u32 param_4,u8 param_5);
void FUN_800a3238(void);
u32
projgfx_spawnPresetEffect(int param_1,u32 param_2,ExpgfxAttachedSourceState *param_3,
                          u32 param_4,u8 param_5,u16 *param_6);
void FUN_800a363c(void);
void FUN_800a3730(u32 param_1,u32 param_2,ExpgfxAttachedSourceState *param_3,
                 u32 param_4,u8 param_5,int param_6);
void FUN_800a3734(void);
u32
FUN_800a3828(int param_1,u32 param_2,ExpgfxAttachedSourceState *param_3,u32 param_4,
             u8 param_5);
void FUN_800a3830(void);
u32
FUN_800a3924(int param_1,u32 param_2,ExpgfxAttachedSourceState *param_3,u32 param_4,
             u8 param_5);
void FUN_800a392c(void);
void projgfx_release_doUnsupported(void);
int projgfx_rayhit_doUnsupported(void);
int projgfx_setzscale_doUnsupported(void);
int projgfx_func04_ret_m1(void);
void projgfx_func05_nop(void);
void projgfx_func06_nop(void);
void projgfx_func07_nop(void);
int projgfx_getObjectTypeId(void);
void projgfx_onMapSetup(void);
void projgfx_initialise(void);

#endif /* MAIN_DLL_MODGFX_H_ */
