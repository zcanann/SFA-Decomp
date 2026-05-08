#ifndef MAIN_DLL_SFXPLAYER_H_
#define MAIN_DLL_SFXPLAYER_H_

#include "ghidra_import.h"

extern int gSfxplayerEffectHandles[8];

void sfxplayer_update(int obj);
void sfxplayer_init(int obj,int config);
void sfxplayer_release(void);
void sfxplayer_initialise(void);

#endif /* MAIN_DLL_SFXPLAYER_H_ */
