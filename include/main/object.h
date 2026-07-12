#ifndef MAIN_OBJECT_H_
#define MAIN_OBJECT_H_

#include "main/game_object.h"

void* getTablesBinEntry(int i);
u8* loadObjectFile(int id);
int objGetTotalDataSize(void* tmpl, u8* def, s16* data, int flags);
void Obj_UpdateModelBlendStates(void);
void Obj_FreeObject(GameObject* obj);

int objGetFlagsE5_2(u8* obj);

#endif
