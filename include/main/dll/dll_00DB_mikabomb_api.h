#ifndef MAIN_DLL_DLL_00DB_MIKABOMB_API_H_
#define MAIN_DLL_DLL_00DB_MIKABOMB_API_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gMikaBombObjDescriptor;

void MikaBomb_free(GameObject* obj, int mode);
int MikaBomb_getExtraSize(void);
int MikaBomb_getObjectTypeId(void);
void MikaBomb_hitDetect(void);
void MikaBomb_init(int* obj);
void MikaBomb_initialise(void);
void MikaBomb_release(void);
void MikaBomb_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void MikaBomb_update(int* obj);

#endif /* MAIN_DLL_DLL_00DB_MIKABOMB_API_H_ */
