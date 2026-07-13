#ifndef MAIN_DLL_CF_DLL_0148_CFGUARDIAN_H_
#define MAIN_DLL_CF_DLL_0148_CFGUARDIAN_H_

#include "main/game_object.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/dll_0015_curves.h"
#include "main/obj_placement.h"
#include "main/dll/cfguardian_state.h"
#include "main/camera_interface.h"
#include "main/game_ui_interface.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/dll/player_status.h"
#include "main/objseq.h"
#include "main/dll/dll_002E_moveLib.h"

int* findRomCurvePointNearObject(int* obj, int p2, int* outVec, int p4);
int cfguardianSteerToward(int* obj, int* target, f32 speed, int p4);
int cfguardian_setScale(int* obj);
int cfguardian_getExtraSize(void);
int cfguardian_getObjectTypeId(void);
void cfguardian_free(int* obj, int keep);
void cfguardian_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
void cfguardian_hitDetect(int* obj);
void cfguardian_update(GameObject* obj);
void cfguardian_init(int* obj, u8* params);
void cfguardian_release(void);
void cfguardian_initialise(void);

#endif /* MAIN_DLL_CF_DLL_0148_CFGUARDIAN_H_ */
