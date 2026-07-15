#ifndef MAIN_DLL_DLL_0106_SCARAB_H_
#define MAIN_DLL_DLL_0106_SCARAB_H_

#include "main/dll/CF/CFguardian.h"
#include "main/dll/windlift107state_struct.h"
#include "main/dll/portalspelldoorstate_struct.h"
#include "main/dll/scarabstate_struct.h"
#include "main/obj_placement.h"
#include "main/frustum.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/objhits.h"

int scarab_sweptCollide(GameObject* obj);
int Scarab_getExtraSize(void);
void Scarab_free(void);
void Scarab_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void Scarab_update(GameObject* obj);
void Scarab_init(int* obj, u8* def);

#endif
