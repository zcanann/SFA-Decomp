#ifndef MAIN_DLL_DLL_0044_CAMERAMODEVIEWFINDER_H_
#define MAIN_DLL_DLL_0044_CAMERAMODEVIEWFINDER_H_

#include "types.h"

void firstPersonDoControls(s16* obj);
int firstPersonEnter(u8* cam, s16* p2);
void CameraModeViewfinder_copyToCurrent(s16* camObj);
void CameraModeViewfinder_free(int camObj);
void CameraModeViewfinder_update(s16* obj);
void CameraModeViewfinder_init(s16* obj, int mode, int* args);
void CameraModeViewfinder_release(void);
void CameraModeViewfinder_initialise(void);

#endif /* MAIN_DLL_DLL_0044_CAMERAMODEVIEWFINDER_H_ */
