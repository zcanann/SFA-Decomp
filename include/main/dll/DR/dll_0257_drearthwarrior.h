#ifndef MAIN_DLL_DR_DLL_0257_DREARTHWARRIOR_H_
#define MAIN_DLL_DR_DLL_0257_DREARTHWARRIOR_H_

#include "main/game_object.h"

extern void* gEarthWarriorResource;
extern void* gDREarthWarriorStateHandlers[];
extern void* gDREarthWarriorDefaultStateHandler;
extern f32 gEarthWarriorMatrix[16];

extern f32 lbl_803E82E8;
extern f32 lbl_803E82EC;
extern f32 GXInit_ClearColor;
extern f32 GXInit_BlackColor;
extern f32 GXInit_WhiteColor;
extern f32 lbl_803E82FC;
extern f32 lbl_803E8300;
extern f32 lbl_803E8304;
extern f32 lbl_803E8308;
extern f32 lbl_803E830C;
extern f32 GX_F32_256;
extern const f32 lbl_803E8338;
extern f32 lbl_803E8354;
extern int lbl_8033527C[];
extern f32 lbl_803DC76C;

int DR_EarthWarrior_stateHandler00(GameObject* obj);
int DR_EarthWarrior_stateHandler01(GameObject* obj, int state);
int DR_EarthWarrior_stateHandler02(GameObject* obj, int state);
int DR_EarthWarrior_stateHandler03(GameObject* obj, int state);

#endif /* MAIN_DLL_DR_DLL_0257_DREARTHWARRIOR_H_ */
