#ifndef MAIN_DLL_FRONT_N_RAREWARE_H_
#define MAIN_DLL_FRONT_N_RAREWARE_H_

#include "ghidra_import.h"

void runLoadingScreens(void);
void initLoadingScreenTextures(void);
void TitleScreenInit_render(void);
void TitleScreenInit_frameEnd(void);
int TitleScreenInit_frameStart(void);
void TitleScreenInit_release(void);
void TitleScreenInit_initialise(void);
void n_rareware_render(void);
void n_rareware_frameEnd(void);

#endif /* MAIN_DLL_FRONT_N_RAREWARE_H_ */
