#ifndef MAIN_DLL_DLL_0109_UNK_H_
#define MAIN_DLL_DLL_0109_UNK_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

typedef struct BreakableCarryableState
{
    u8 pad00[0x0A];
    u8 phase;
    u8 pad0B;
    f32 respawnTimer;
} BreakableCarryableState;

typedef enum BreakableCarryablePhase
{
    BREAKABLE_CARRYABLE_PHASE_INTACT = 0,
    BREAKABLE_CARRYABLE_PHASE_BREAKING = 1,
    BREAKABLE_CARRYABLE_PHASE_RESPAWNING = 2,
} BreakableCarryablePhase;

typedef struct BreakableCarryablePlacement
{
    ObjPlacement base;
    u8 pad18[2];
    u8 rotX;
} BreakableCarryablePlacement;

STATIC_ASSERT(sizeof(BreakableCarryableState) == 0x10);
STATIC_ASSERT(offsetof(BreakableCarryableState, phase) == 0x0A);
STATIC_ASSERT(offsetof(BreakableCarryableState, respawnTimer) == 0x0C);
STATIC_ASSERT(sizeof(BreakableCarryablePlacement) == 0x1C);
STATIC_ASSERT(offsetof(BreakableCarryablePlacement, rotX) == 0x1A);

int breakableCarryable_getExtraSize(void);
int breakableCarryable_getObjectTypeId(void);
void breakableCarryable_free(GameObject* obj);
void breakableCarryable_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible);
void breakableCarryable_hitDetect(void);
void breakableCarryable_update(GameObject* obj);
void breakableCarryable_init(GameObject* obj, BreakableCarryablePlacement* placement);
void breakableCarryable_release(void);
void breakableCarryable_initialise(void);

extern ObjectDescriptor gBreakableCarryableObjDescriptor;

#endif /* MAIN_DLL_DLL_0109_UNK_H_ */
