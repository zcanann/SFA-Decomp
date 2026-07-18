#ifndef MAIN_DLL_PLAYER_EXT_H_
#define MAIN_DLL_PLAYER_EXT_H_

#include "dolphin/types.h"

void fn_802B4DE0(u8* obj, int flag);
void fn_802960E4(int obj, f32 xVelocity, f32 zVelocity);
void objLoadPlayerFromSave(int obj);
void playerUpdateWhileTimeStopped(int obj);
#endif /* MAIN_DLL_PLAYER_EXT_H_ */
