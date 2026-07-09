#ifndef MAIN_DLL_DF_DFLANTERN_H_
#define MAIN_DLL_DF_DFLANTERN_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

void DFSH_Door2Speci_free(void);
void DFSH_Door2Speci_render(int p1,int p2,int p3,int p4,int p5,s8 visible);
void DFSH_Door2Speci_hitDetect(void);
void DFSH_Door2Speci_update(void);
void DFSH_Door2Speci_init(struct GameObject *obj,int def);
void DFSH_Door2Speci_release(void);
void DFSH_Door2Speci_initialise(void);
void fn_801C2914(int obj);
int DFSH_Shrine_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
int DFSH_Shrine_getExtraSize(void);
int DFSH_Shrine_getObjectTypeId(void);
void DFSH_Shrine_free(struct GameObject *obj);

#endif /* MAIN_DLL_DF_DFLANTERN_H_ */
