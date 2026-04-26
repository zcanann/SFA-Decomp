#ifndef MAIN_DLL_SFXPLAYER_H_
#define MAIN_DLL_SFXPLAYER_H_

#include "ghidra_import.h"

extern int gSfxplayerEffectHandles[8];

void sfxplayer_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                      undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void sfxplayer_init(int obj,int config);
void sfxplayer_release(void);
void sfxplayer_initialise(void);

#endif /* MAIN_DLL_SFXPLAYER_H_ */
