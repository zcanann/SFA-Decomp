#ifndef MAIN_DLL_DLL_016C_DLL16C_H_
#define MAIN_DLL_DLL_016C_DLL16C_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

int dll_16C_getExtraSize(void);
int dll_16C_getObjectTypeId(void);
void dll_16C_free(int* obj);
void dll_16C_render(int* obj, int p1, int p2, int p3, int p4, s8 visible);
void dll_16C_hitDetect(GameObject* obj);
void dll_16C_update(int* obj);
void dll_16C_init(GameObject* obj, void* arg2);
int dll_16C_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate);
void dll_16C_release(void);
void dll_16C_initialise(void);
void dll_16C_syncSubObjectTransform(void* dst, void* src, int p1, int p2, int p3, int p4, int visible, int opacity,
                                    int copyTransform);

#endif /* MAIN_DLL_DLL_016C_DLL16C_H_ */
