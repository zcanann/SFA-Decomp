#ifndef DLLS_OBJECTS_320_FOGCONTROL_H_
#define DLLS_OBJECTS_320_FOGCONTROL_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

typedef enum FogControlPlacementFlag {
    FOG_CONTROL_PLACEMENT_MODE = 0x01,
    FOG_CONTROL_PLACEMENT_SLOW_FADE_IN = 0x02,
    FOG_CONTROL_PLACEMENT_SLOW_FADE_OUT = 0x04,
    FOG_CONTROL_PLACEMENT_ENABLED = 0x08,
} FogControlPlacementFlag;

/*
 * The setup fields through depthScale are evidenced by this TU. The complete
 * record extent after 0x25 is not yet proven.
 */
typedef struct FogControlPlacement {
    ObjPlacement base; /* 0x00 */
    s16 enableGameBit; /* 0x18: -1 enables unconditionally */
    u8 flags;          /* 0x1A: FogControlPlacementFlag */
    u8 pad1B;          /* 0x1B */
    s16 fogTop;        /* 0x1C */
    s16 fogBottom;     /* 0x1E */
    s16 fogBase;       /* 0x20 */
    s16 depthOffset;   /* 0x22: normalized by 65535.0f */
    s16 depthScale;    /* 0x24 */
} FogControlPlacement;

/* FogControl_getExtraSize proves the complete 0x08-byte allocation. */
typedef struct FogControlState {
    f32 blend; /* 0x00 */
    u8 enabled : 1;
    u8 fullyBlended : 1;
    u8 unused : 6;
    u8 pad05[3]; /* 0x05 */
} FogControlState;

STATIC_ASSERT(offsetof(FogControlPlacement, base) == 0x00);
STATIC_ASSERT(offsetof(FogControlPlacement, enableGameBit) == 0x18);
STATIC_ASSERT(offsetof(FogControlPlacement, flags) == 0x1A);
STATIC_ASSERT(offsetof(FogControlPlacement, pad1B) == 0x1B);
STATIC_ASSERT(offsetof(FogControlPlacement, fogTop) == 0x1C);
STATIC_ASSERT(offsetof(FogControlPlacement, fogBottom) == 0x1E);
STATIC_ASSERT(offsetof(FogControlPlacement, fogBase) == 0x20);
STATIC_ASSERT(offsetof(FogControlPlacement, depthOffset) == 0x22);
STATIC_ASSERT(offsetof(FogControlPlacement, depthScale) == 0x24);

STATIC_ASSERT(offsetof(FogControlState, blend) == 0x00);
STATIC_ASSERT(offsetof(FogControlState, pad05) == 0x05);
STATIC_ASSERT(sizeof(FogControlState) == 0x08);

int FogControl_getExtraSize(void);
int FogControl_getObjectTypeId(void);
void FogControl_free(GameObject* obj);
void FogControl_hitDetect(void);
void FogControl_update(GameObject* obj);
void FogControl_init(GameObject* obj, FogControlPlacement* placement);

extern ObjectDescriptor gFogControlObjDescriptor;

#endif /* DLLS_OBJECTS_320_FOGCONTROL_H_ */
