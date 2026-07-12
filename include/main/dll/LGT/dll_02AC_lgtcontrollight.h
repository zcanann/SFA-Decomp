#ifndef MAIN_DLL_LGT_DLL_02AC_LGTCONTROLLIGHT_H_
#define MAIN_DLL_LGT_DLL_02AC_LGTCONTROLLIGHT_H_

#include "main/game_object.h"
#include "main/dll/dll_80220608_shared.h"
#include "main/dll/LGT/lgt_types.h"

typedef struct ControlLightSetup
{
    ObjPlacement base;
    u8 pad18;
    s8 invertMode;
    s16 radius;
    u8 pad1C[0x1E - 0x1C];
    s16 gameBit;
} ControlLightSetup;

typedef struct ControlLightState
{
    s16 gameBit;
    u8 pad02[2];
    f32 radius;
    u8 invertMode;
    u8 lastBit;
    u8 pad0A[2];
} ControlLightState;

STATIC_ASSERT(sizeof(ControlLightState) == 0x0C);
STATIC_ASSERT(offsetof(ControlLightState, gameBit) == 0x00);
STATIC_ASSERT(offsetof(ControlLightState, radius) == 0x04);
STATIC_ASSERT(offsetof(ControlLightState, invertMode) == 0x08);
STATIC_ASSERT(offsetof(ControlLightState, lastBit) == 0x09);
STATIC_ASSERT(offsetof(ControlLightSetup, invertMode) == 0x19);
STATIC_ASSERT(offsetof(ControlLightSetup, radius) == 0x1A);
STATIC_ASSERT(offsetof(ControlLightSetup, gameBit) == 0x1E);
STATIC_ASSERT(sizeof(ControlLightSetup) == 0x20);

int ControlLight_getExtraSize(void);
int ControlLight_getObjectTypeId(void);
void ControlLight_free(void);
void ControlLight_hitDetect(void);
void ControlLight_render(void);
void ControlLight_init(GameObject* obj, int setup);
void ControlLight_update(GameObject* obj);
void ControlLight_release(void);
void ControlLight_initialise(void);

#endif /* MAIN_DLL_LGT_DLL_02AC_LGTCONTROLLIGHT_H_ */
