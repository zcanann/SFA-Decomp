#ifndef MAIN_DLL_WC_DLL_0291_WCTILE_H_
#define MAIN_DLL_WC_DLL_0291_WCTILE_H_

#include "global.h"
#include "main/game_object.h"

typedef struct WCTileSetup WCTileSetup;

int wctile_getExtraSize(void);
int wctile_getObjectTypeId(GameObject* obj);
void wctile_free(void);
void wctile_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void wctile_hitDetect(void);
void wctile_init(GameObject* obj, WCTileSetup* setup);
void wctile_release(void);
void wctile_initialise(void);
void wctile_update(GameObject* obj);

#endif /* MAIN_DLL_WC_DLL_0291_WCTILE_H_ */
