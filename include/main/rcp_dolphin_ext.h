#ifndef MAIN_RCP_DOLPHIN_EXT_H_
#define MAIN_RCP_DOLPHIN_EXT_H_

#include "dolphin/types.h"
#include "main/map_romlist_page.h"

typedef struct GameObject GameObject;

void textureFn_800541ac(void* ctx, void* tex, int a, int b, int c, int d, int e);
void fn_80054F74(GameObject* object, f32* position);
void mapInstantiateObjects(MapRomListPage* page, int mapId, int groupIndex, GameObject* parent);
#endif /* MAIN_RCP_DOLPHIN_EXT_H_ */
