#ifndef DLLS_OBJECTS_265_H_
#define DLLS_OBJECTS_265_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"
#include "main/carryable_state.h"

#define BREAKABLE_CARRYABLE_STATE_SIZE 0x10

typedef enum BreakableCarryablePhase {
    BREAKABLE_CARRYABLE_PHASE_INTACT = 0,
    BREAKABLE_CARRYABLE_PHASE_BREAKING = 1,
    BREAKABLE_CARRYABLE_PHASE_RESPAWNING = 2,
} BreakableCarryablePhase;

/* Only the accessed placement prefix is recovered; the complete retail width is not established. */
typedef struct BreakableCarryablePlacement {
    ObjPlacement base; /* 0x00 */
    u8 pad18[2];       /* 0x18 */
    u8 rotXByte;       /* 0x1A: X rotation in 1/256 turns */
} BreakableCarryablePlacement;

typedef struct BreakableCarryableState {
    CarryableState carryable; /* 0x00 */
    u8 phase;                 /* 0x0A: BreakableCarryablePhase */
    u8 pad0B;                 /* 0x0B */
    f32 respawnTimer;         /* 0x0C */
} BreakableCarryableState;

STATIC_ASSERT(offsetof(BreakableCarryablePlacement, base) == 0x0);
STATIC_ASSERT(offsetof(BreakableCarryablePlacement, pad18) == 0x18);
STATIC_ASSERT(offsetof(BreakableCarryablePlacement, rotXByte) == 0x1A);

STATIC_ASSERT(offsetof(BreakableCarryableState, carryable) == 0x0);
STATIC_ASSERT(offsetof(BreakableCarryableState, phase) == 0xA);
STATIC_ASSERT(offsetof(BreakableCarryableState, pad0B) == 0xB);
STATIC_ASSERT(offsetof(BreakableCarryableState, respawnTimer) == 0xC);
STATIC_ASSERT(sizeof(BreakableCarryableState) == BREAKABLE_CARRYABLE_STATE_SIZE);

int breakableCarryable_getExtraSize(void);
int breakableCarryable_getObjectTypeId(void);
void breakableCarryable_free(GameObject* obj);
void breakableCarryable_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                               s8 visible);
void breakableCarryable_hitDetect(void);
void breakableCarryable_update(GameObject* obj);
void breakableCarryable_init(GameObject* obj, BreakableCarryablePlacement* placement);
void breakableCarryable_release(void);
void breakableCarryable_initialise(void);

extern ObjectDescriptor gBreakableCarryableObjDescriptor;

#endif /* DLLS_OBJECTS_265_H_ */
