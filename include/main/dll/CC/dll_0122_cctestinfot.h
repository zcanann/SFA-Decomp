#ifndef MAIN_DLL_CC_DLL_0122_CCTESTINFOT_H_
#define MAIN_DLL_CC_DLL_0122_CCTESTINFOT_H_

#include "global.h"

typedef struct CctestinfotState
{
    f32 holdTimer; /* 0x00: counts down while help text is shown */
    u8 disguised;  /* 0x04: cached playerIsDisguised() result, hint-text index */
    u8 pad05[3];
} CctestinfotState;

STATIC_ASSERT(offsetof(CctestinfotState, disguised) == 0x4);
STATIC_ASSERT(sizeof(CctestinfotState) == 0x8);

int CCTestInfot_getExtraSize(void);
void CCTestInfot_update(int* obj);
void CCTestInfot_init(int obj, s8* def);

#endif /* MAIN_DLL_CC_DLL_0122_CCTESTINFOT_H_ */
