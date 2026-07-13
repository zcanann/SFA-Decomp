#ifndef MAIN_DLL_DR_DLL_0257_DREARTHWARRIOR_H_
#define MAIN_DLL_DR_DLL_0257_DREARTHWARRIOR_H_

#include "main/game_object.h"

extern void* gEarthWarriorResource;
extern void* gDREarthWarriorStateHandlers[];
extern void* gDREarthWarriorDefaultStateHandler;
extern f32 gEarthWarriorMatrix[16];

int DR_EarthWarrior_stateHandler00(GameObject* obj);
int DR_EarthWarrior_stateHandler01(GameObject* obj, int state);
int DR_EarthWarrior_stateHandler02(GameObject* obj, int state);
int DR_EarthWarrior_stateHandler03(GameObject* obj, int state);

#endif /* MAIN_DLL_DR_DLL_0257_DREARTHWARRIOR_H_ */
