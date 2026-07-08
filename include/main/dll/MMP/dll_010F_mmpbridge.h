#ifndef MAIN_DLL_MMP_DLL_010F_MMPBRIDGE_H_
#define MAIN_DLL_MMP_DLL_010F_MMPBRIDGE_H_

#include "global.h"

typedef struct MmpBridgePlacement
{
    u8 pad0[0x18];
    s8 rotXByte; /* 0x18: rotX in 1/256 turns */
    u8 pad19[0x1E - 0x19];
    s16 enableBit; /* 0x1E: gamebit that deploys the bridge */
} MmpBridgePlacement;

int mmp_bridge_getExtraSize(void);
int mmp_bridge_getObjectTypeId(void);
void mmp_bridge_free(void);
void mmp_bridge_render(void);
void mmp_bridge_hitDetect(void);
void mmp_bridge_update(int* obj);
void mmp_bridge_init(int* obj);
void mmp_bridge_release(void);
void mmp_bridge_initialise(void);

#endif /* MAIN_DLL_MMP_DLL_010F_MMPBRIDGE_H_ */
