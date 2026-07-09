#ifndef MAIN_DLL_DR_DLL_024F_KTREXLEVEL_H_
#define MAIN_DLL_DR_DLL_024F_KTREXLEVEL_H_

#include "global.h"
#include "ghidra_import.h"

int KT_RexLevel_getExtraSize(void);
int KT_RexLevel_getObjectTypeId(void);
void KT_RexLevel_free(void);
void KT_RexLevel_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible);
void KT_RexLevel_hitDetect(void);
void ktrexlevel_clearPathGameBits(void);
void ktrexlevel_updatePathGameBits(void);
void KT_RexLevel_update(int obj);
void KT_RexLevel_init(struct GameObject *obj);
void KT_RexLevel_release(void);
void KT_RexLevel_initialise(void);

#endif /* MAIN_DLL_DR_DLL_024F_KTREXLEVEL_H_ */
