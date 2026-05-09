#ifndef MAIN_DLL_FRONT_DLL_3B_H_
#define MAIN_DLL_FRONT_DLL_3B_H_

#include "ghidra_import.h"

void TitleMenu_initialise(void);
void *fn_8011730C(int flags);
void fn_80117350(void *message);
void thpAudioFn_80117380(void *cursor);
void *threadMainAlt_80117460(void *param);
void *thpAudioThreadMain(void *param);
void AXInit(void);
void AXQuit(void);

#endif /* MAIN_DLL_FRONT_DLL_3B_H_ */
