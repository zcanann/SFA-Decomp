#ifndef MAIN_DLL_SH_DLL_01B0_SHSWAPSTON_H_
#define MAIN_DLL_SH_DLL_01B0_SHSWAPSTON_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"

int warpstone_testEvent(u32 obj, u32 unused, int option);
void warpstone_loadBaseUi(void);
int warpstone_SeqFn(GameObject* obj, u32 unused, int animObj);
int warpstone_getExtraSize(void);
int warpstone_getObjectTypeId(void);
void warpstone_free(GameObject* obj, int mode);
void warpstone_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void warpstone_hitDetect(GameObject* obj);
void warpstone_update(int obj);
void warpstone_init(GameObject* obj, u8* setup);
void warpstone_release(void);
void warpstone_initialise(void);

extern ObjectDescriptor gWarpStoneObjDescriptor;

STATIC_ASSERT(sizeof(ObjectDescriptor) == 0x38);

#endif /* MAIN_DLL_SH_DLL_01B0_SHSWAPSTON_H_ */
