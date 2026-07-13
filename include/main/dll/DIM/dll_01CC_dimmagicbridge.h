#ifndef MAIN_DLL_DIM_DLL_01CC_DIMMAGICBRIDGE_H_
#define MAIN_DLL_DIM_DLL_01CC_DIMMAGICBRIDGE_H_

#include "main/dll/dimmagicbridge_state.h"
#include "main/dll/fbwgpipe_struct.h"
#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"
#include "main/objtexture.h"
#include "main/gamebits.h"

extern ObjectDescriptor gDIMMagicBridgeObjDescriptor;

void dimmagicbridge_updateVertexWave(GameObject* obj, u8* sub);
void dimmagicbridge_scrollTextureChannels(int obj, u8* extra);
int dimmagicbridge_getExtraSize(void);
int dimmagicbridge_getObjectTypeId(void);
void dimmagicbridge_free(void);
void dimmagicbridge_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dimmagicbridge_hitDetect(void);
void dimmagicbridge_update(GameObject* obj);
void dimmagicbridge_init(u8* obj, u8* params);
int dimmagicbridge_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void dimmagicbridge_release(void);
void dimmagicbridge_initialise(void);

#endif /* MAIN_DLL_DIM_DLL_01CC_DIMMAGICBRIDGE_H_ */
