#ifndef MAIN_DLL_SP_DLL_0289_SPITEMBEAM_H_
#define MAIN_DLL_SP_DLL_0289_SPITEMBEAM_H_

#include "ghidra_import.h"
#include "global.h"

typedef struct SpitembeamPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 itemIndex; /* 0x1A: shop item slot this beam marks */
    u8 pad1C[0x20 - 0x1C];
} SpitembeamPlacement;

STATIC_ASSERT(sizeof(SpitembeamPlacement) == 0x20);

int spitembeam_getExtraSize(void);
int spitembeam_getObjectTypeId(void);
void spitembeam_free(void);
void spitembeam_render(void);
void spitembeam_hitDetect(void);
void spitembeam_update(int* obj);
void spitembeam_init(struct GameObject* obj);
void spitembeam_release(void);
void spitembeam_initialise(void);

#endif /* MAIN_DLL_SP_DLL_0289_SPITEMBEAM_H_ */
