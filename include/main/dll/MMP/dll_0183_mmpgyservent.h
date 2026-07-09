#ifndef MAIN_DLL_MMP_DLL_0183_MMPGYSERVENT_H_
#define MAIN_DLL_MMP_DLL_0183_MMPGYSERVENT_H_

#include "types.h"

typedef struct MmpGyserventPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 disableBit; /* 0x1E: gamebit that switches the vent off */
    u8 unk20;       /* 0x20 */
    u8 pad21[0x28 - 0x21];
} MmpGyserventPlacement;

int mmp_gyservent_getExtraSize(void);
int mmp_gyservent_getObjectTypeId(void);
void mmp_gyservent_free(void);
void mmp_gyservent_render(void);
void mmp_gyservent_hitDetect(void);
void mmp_gyservent_update(int obj);
void mmp_gyservent_init(struct GameObject *obj);
void mmp_gyservent_release(void);
void mmp_gyservent_initialise(void);

#endif /* MAIN_DLL_MMP_DLL_0183_MMPGYSERVENT_H_ */
