#ifndef MAIN_DLL_DLL_0150_GCROBOTLIGHTBEA_H_
#define MAIN_DLL_DLL_0150_GCROBOTLIGHTBEA_H_

#include "types.h"
#include "main/game_object.h"
#include "main/modellight_api.h"

typedef struct GcRobotLightBeaState
{
    ModelLightStruct* light;
    int unk4;
    u8 hitFlags; /* 0x80 = player caught in the beam */
    u8 pad9[3];
} GcRobotLightBeaState;

u32 fn_801A0174(int* obj);
int gcrobotlightbea_getExtraSize(void);
int gcrobotlightbea_getObjectTypeId(void);
void gcrobotlightbea_free(int* obj);
void gcrobotlightbea_render(void);
void gcrobotlightbea_hitDetect(GameObject* obj);
void gcrobotlightbea_update(int* obj);
void gcrobotlightbea_init(int* obj);
void gcrobotlightbea_release(void);
void gcrobotlightbea_initialise(void);

#endif /* MAIN_DLL_DLL_0150_GCROBOTLIGHTBEA_H_ */
