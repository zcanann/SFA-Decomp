#ifndef MAIN_DLL_DLL_02C0_FRONT_H_
#define MAIN_DLL_DLL_02C0_FRONT_H_

#include "main/dll/dll_02C0_front_api.h"
#include "main/texture.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "main/camera_interface.h"
#include "main/dll/tricky_state.h"
#include "main/game_object.h"
#include "main/dll/FRONT/dll_39.h"
#include "main/objseq.h"
#include "main/dll/FRONT/dll_0034_n_filemenu.h"

int TitleScreen_getObjectTypeId(u8* obj);
int TitleScreen_getExtraSize(void);
void TitleScreen_hitDetect(void);

void titleScreenTextDrawFunc(void);
void creditsStart(void);

#endif
