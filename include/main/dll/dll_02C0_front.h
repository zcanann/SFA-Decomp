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
void TitleScreen_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void TitleScreen_release(void);
void TitleScreen_initialise(void);
void TitleScreen_free(u8* obj);
void TitleScreen_update(u8* obj);
void TitleScreen_init(u8* obj, u8* def);

void creditsStart(void);

#endif
