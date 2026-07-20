#ifndef MAIN_DLL_DLL_00C8_DEPTHOFFIELDPOINT_API_H_
#define MAIN_DLL_DLL_00C8_DEPTHOFFIELDPOINT_API_H_

#include "main/objanim_update.h"
#include "main/object_descriptor.h"
#include "main/game_object.h"

extern ObjectDescriptor gDepthOfFieldPointObjDescriptor;
extern u16 lbl_803208A0[];
extern u32 lbl_803208E8[];

int depthoffieldpoint_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int depthoffieldpoint_getExtraSize(void);
void depthoffieldpoint_init(GameObject* obj);
void depthoffieldpoint_update(GameObject* obj);

#endif /* MAIN_DLL_DLL_00C8_DEPTHOFFIELDPOINT_API_H_ */
