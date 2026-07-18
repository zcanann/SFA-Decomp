#ifndef MAIN_DLL_DIM_DLL_01CC_DIMMAGICBRIDGE_H_
#define MAIN_DLL_DIM_DLL_01CC_DIMMAGICBRIDGE_H_

#include "main/dll/dimmagicbridge_state.h"
#include "main/dll/dimmagicbridge_api.h"
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
int dimmagicbridge_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);

#endif /* MAIN_DLL_DIM_DLL_01CC_DIMMAGICBRIDGE_H_ */
