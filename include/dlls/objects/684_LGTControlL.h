#ifndef DLLS_OBJECTS_684_LGTCONTROLL_H_
#define DLLS_OBJECTS_684_LGTCONTROLL_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

typedef struct ControlLightSetup {
    ObjPlacement base;
    u8 reserved18;
    s8 invertMode;
    s16 radius;
    u8 reserved1C[2];
    s16 gameBit;
} ControlLightSetup;

typedef struct ControlLightState {
    s16 gameBit;
    u8 reserved02[2];
    f32 radius;
    u8 invertMode;
    u8 lastBit;
    u8 reserved0A[2];
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
void ControlLight_init(GameObject* obj, ControlLightSetup* setup);
void ControlLight_update(GameObject* obj);
void ControlLight_release(void);
void ControlLight_initialise(void);

extern ObjectDescriptor gControlLightObjDescriptor;

#endif /* DLLS_OBJECTS_684_LGTCONTROLL_H_ */
