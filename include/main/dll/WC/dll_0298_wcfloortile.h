#ifndef MAIN_DLL_WC_DLL_0298_WCFLOORTILE_H
#define MAIN_DLL_WC_DLL_0298_WCFLOORTILE_H

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef enum WcFloorTilePhase
{
    WCFLOORTILE_PHASE_IDLE = 0,
    WCFLOORTILE_PHASE_FALLING = 1,
    WCFLOORTILE_PHASE_FALLEN = 2,
    WCFLOORTILE_PHASE_RESTORE = 3
} WcFloorTilePhase;

typedef struct WcFloorTileState
{
    f32 shakeTime;
    s16 shakeMag;
    u8 phase;
    u8 flags;
} WcFloorTileState;

typedef struct WcFloorTileSetup
{
    ObjPlacement base;
    u8 pad18[2];
    s16 eventId;
    u8 pad1C[8];
} WcFloorTileSetup;

STATIC_ASSERT(sizeof(WcFloorTileState) == 8);
STATIC_ASSERT(offsetof(WcFloorTileState, shakeTime) == 0x00);
STATIC_ASSERT(offsetof(WcFloorTileState, shakeMag) == 0x04);
STATIC_ASSERT(offsetof(WcFloorTileState, phase) == 0x06);
STATIC_ASSERT(offsetof(WcFloorTileState, flags) == 0x07);
STATIC_ASSERT(sizeof(WcFloorTileSetup) == 0x24);
STATIC_ASSERT(offsetof(WcFloorTileSetup, base.posY) == 0x0C);
STATIC_ASSERT(offsetof(WcFloorTileSetup, eventId) == 0x1A);

extern ObjectDescriptor gWCFloorTileObjDescriptor;

int wcfloortile_getExtraSize(void);
int wcfloortile_getObjectTypeId(void);
void wcfloortile_free(void);
void wcfloortile_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void wcfloortile_hitDetect(void);
void wcfloortile_init(GameObject* obj);
void wcfloortile_release(void);
void wcfloortile_initialise(void);
void wcfloortile_update(int obj);

#endif /* MAIN_DLL_WC_DLL_0298_WCFLOORTILE_H */
