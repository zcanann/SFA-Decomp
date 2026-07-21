#ifndef MAIN_RCP_DOLPHIN_H_
#define MAIN_RCP_DOLPHIN_H_

#include "ghidra_import.h"
#include "main/rcp_dolphin_api.h"

/* TEX0.tab/TEX1.tab/TEXPRE.tab entry (bankWord): high bits select source map, */
/* bits 29..24 are the mipmap/animation-frame count. */
#define TEX_TAB_MAP_A           0x80000000u
#define TEX_TAB_MAP_B           0x40000000u
#define TEX_TAB_MIP_COUNT_SHIFT 24
#define TEX_TAB_MIP_COUNT_MASK  0x3f

void FUN_80051fc4(u32 param_1,u32 param_2,int param_3,char *param_4,u32 param_5,
                 u32 param_6);
void FUN_80053074(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_8005360c(u32 param_1,u32 *param_2,u32 *param_3,u32 param_4,
                 int param_5);
void FUN_80053758(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
u32
FUN_8005398c(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,u32 param_9,
            u32 param_10,u32 param_11,u32 param_12,u32 param_13,
            u32 param_14,u32 param_15,u32 param_16);
void FUN_80053aa0(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_80053c34(u32 param_1,u32 param_2,int param_3,int param_4,int param_5,
                 int param_6);
void FUN_80053c94(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_80053c98(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,char param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_80053c9c(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,int param_11,u32 *param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);


/* extern-cleanup: defining-file public prototypes */
void loadTextureFiles(void);
void Rcp_InitDistortionEffects(void);
void* getLoadedTexture(int key);
u8 Rcp_GetViewFinderHudEnabled(void);
void Rcp_SetViewFinderHudEnabled(u8 x);
void ShaderDef_free(int* def);
void gxTextureFn_80052efc(void);
void loadNextMap(void);

#endif /* MAIN_RCP_DOLPHIN_H_ */
