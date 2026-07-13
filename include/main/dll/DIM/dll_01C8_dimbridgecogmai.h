#ifndef MAIN_DLL_DIM_DLL_01C8_DIMBRIDGECOGMAI_H_
#define MAIN_DLL_DIM_DLL_01C8_DIMBRIDGECOGMAI_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

extern ObjectDescriptor gDIMBridgeCogMaiObjDescriptor;

int dimbridgecogmai_getExtraSize(void);
int dimbridgecogmai_getObjectTypeId(void);
void dimbridgecogmai_free(int obj);
void dimbridgecogmai_render(GameObject* p1, int p2, int p3, int p4, int p5, s8 visible);
void dimbridgecogmai_hitDetect(void);
void dimbridgecogmai_update(int* obj);
void dimbridgecogmai_init(int* obj, int* def);
int dimbridgecogmai_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void dimbridgecogmai_initialise(void);

#endif /* MAIN_DLL_DIM_DLL_01C8_DIMBRIDGECOGMAI_H_ */
