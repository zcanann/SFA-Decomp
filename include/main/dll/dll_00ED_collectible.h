#ifndef MAIN_DLL_GFXEMIT_H_
#define MAIN_DLL_GFXEMIT_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

void FUN_801723dc(int param_1);
void FUN_801726ac(short *param_1);
void FUN_80172974(u32 param_1,u32 param_2,ObjAnimUpdateState *animUpdate);
void FUN_80172b40(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void collectible_free(int obj);
void FUN_8017308c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
int collectible_getExtraSize(void);
int collectible_getObjectTypeId(void);
void collectible_hitDetect(void);
int collectible_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);


/* extern-cleanup: defining-file public prototypes */
void collectible_updateIdleMotion(int obj);

#endif /* MAIN_DLL_GFXEMIT_H_ */
