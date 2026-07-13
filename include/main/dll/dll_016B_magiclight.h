#ifndef MAIN_DLL_DLL_016B_MAGICLIGHT_H_
#define MAIN_DLL_DLL_016B_MAGICLIGHT_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

extern ObjectDescriptor gMagicLightObjDescriptor;

int MagicLight_getExtraSize(int* obj);
int MagicLight_getObjectTypeId(void);
void MagicLight_free(GameObject* obj);
void MagicLight_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible);
void MagicLight_hitDetect(void);
void MagicLight_update(GameObject* obj);
void MagicLight_init(int* obj, u8* params);
int MagicLight_SeqFn(int* obj);
void MagicLight_release(void);
void MagicLight_initialise(void);

#endif /* MAIN_DLL_DLL_016B_MAGICLIGHT_H_ */
