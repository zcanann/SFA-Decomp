#ifndef MAIN_DLL_MMP_DLL_0181_MMPTRENCHFX_H_
#define MAIN_DLL_MMP_DLL_0181_MMPTRENCHFX_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/dll/mmptrenchfxstate_struct.h"
#include "types.h"

int mmp_trenchfx_getExtraSize(void);
int mmp_trenchfx_getObjectTypeId(void);
void mmp_trenchfx_free(GameObject* obj);
void mmp_trenchfx_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void mmp_trenchfx_hitDetect(void);
void mmp_trenchfx_update(GameObject* obj);
void mmp_trenchfx_init(GameObject* obj, MmpTrenchFxPlacement* placement);
void mmp_trenchfx_release(void);
void mmp_trenchfx_initialise(void);

extern ObjectDescriptor gMMP_trenchFXObjDescriptor;

#endif /* MAIN_DLL_MMP_DLL_0181_MMPTRENCHFX_H_ */
