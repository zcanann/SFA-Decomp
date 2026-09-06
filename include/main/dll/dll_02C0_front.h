#ifndef MAIN_DLL_DLL_02C0_FRONT_H_
#define MAIN_DLL_DLL_02C0_FRONT_H_

#include "main/dll/dll_02C0_front_api.h"
#include "main/texture.h"
#include "main/camera_interface.h"
#include "dlls/objects/196_Tricky.h"
#include "game/objects/object.h"
#include "main/dll/FRONT/dll_39.h"
#include "main/objseq.h"
#include "main/dll/FRONT/dll_0034_n_attractmode.h"

int TitleScreen_getObjectTypeId(GameObject* obj);
int TitleScreen_getExtraSize(void);
void TitleScreen_hitDetect(void);
void TitleScreen_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void TitleScreen_release(void);
void TitleScreen_initialise(void);
void TitleScreen_free(GameObject* obj);
void TitleScreen_update(GameObject* obj);
void TitleScreen_init(GameObject* obj, u8* def);

void creditsStart(void);
void titleScreenSetMenuSelection(s8 selection);

#endif
