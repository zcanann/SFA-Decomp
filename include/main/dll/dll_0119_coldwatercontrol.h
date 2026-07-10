#ifndef MAIN_DLL_DLL_0119_COLDWATERCONTROL_H_
#define MAIN_DLL_DLL_0119_COLDWATERCONTROL_H_

#include "main/game_object.h"
#include "global.h"

typedef struct ColdwaterControlState
{
    f32 timer;       /* 0x00 immersion timer */
    void* playerObj; /* 0x04 cached player object */
} ColdwaterControlState;

STATIC_ASSERT(sizeof(ColdwaterControlState) == 0x8);
STATIC_ASSERT(offsetof(ColdwaterControlState, playerObj) == 0x4);

int ColdWaterControl_getExtraSize(void);
void ColdWaterControl_update(GameObject* obj);
void ColdWaterControl_init(GameObject* obj);

#endif /* MAIN_DLL_DLL_0119_COLDWATERCONTROL_H_ */
