#ifndef MAIN_DLL_MODGFX_H_
#define MAIN_DLL_MODGFX_H_

#include "ghidra_import.h"
#include "main/dll/projgfx_interface.h"
#include "main/vecmath.h"
#include "main/expgfx_internal.h"
#include "main/object_descriptor.h"
#include "main/rcp_dolphin.h"

extern ObjectDescriptor11 projgfx_funcs;
extern char sProjgfxReleaseDoNoLongerSupported[];
extern char sProjgfxRayhitDoNoLongerSupported[];
extern char sProjgfxSetzscaleDoNoLongerSupported[];

#define PROJGFX_SPAWN_FLAG_USE_ATTACHED_SOURCE 0x200000

extern u32 FUN_80017814();
extern u32 FUN_802420e0();

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
void modgfx_releaseActiveEffectsByOwner(u64 param_1,u64 param_2,u64 param_3,
                                        u64 param_4,u64 param_5,u64 param_6,
                                        u64 param_7,u64 param_8,int param_9);
void modgfx_releaseAllActiveEffects(u64 param_1,u64 param_2,u64 param_3,
                                    u64 param_4,u64 param_5,u64 param_6,
                                    u64 param_7,u64 param_8);
void modgfx_resetActiveEffectRegistry(u64 param_1,u64 param_2,u64 param_3,
                                      u64 param_4,u64 param_5,u64 param_6,
                                      u64 param_7,u64 param_8);
u32
projgfx_spawnPresetEffect(int param_1,u32 param_2,ExpgfxAttachedSourceState *param_3,
                          u32 param_4,u8 param_5,u16 *param_6);
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
