#ifndef DLLS_OBJECTS_418_NW_TRICKY_H_
#define DLLS_OBJECTS_418_NW_TRICKY_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"

#define NW_TRICKY_PLAY_BALL_TARGET_ID_COUNT  3
#define NW_TRICKY_PLAY_BALL_TARGET_POOL_SIZE 4

typedef struct ObjSeqState ObjSeqState;

typedef enum NwTrickyPhase {
    NW_TRICKY_PHASE_CHASED_BY_SHARPCLAW = 0,
    NW_TRICKY_PHASE_LEARNING_COMMANDS = 1,
} NwTrickyPhase;

typedef struct NwTrickyState {
    u8 phase;
    u8 unknown01[3];
    f32 phaseTimer;
} NwTrickyState;

STATIC_ASSERT(sizeof(NwTrickyState) == 0x08);
STATIC_ASSERT(offsetof(NwTrickyState, phase) == 0x00);
STATIC_ASSERT(offsetof(NwTrickyState, unknown01) == 0x01);
STATIC_ASSERT(offsetof(NwTrickyState, phaseTimer) == 0x04);

extern const int gNwTrickyPlayBallTargetIds[NW_TRICKY_PLAY_BALL_TARGET_POOL_SIZE];
extern ObjectDescriptor gNWTrickyObjDescriptor;

int nwTricky_processAnimEvents(GameObject* unusedObj, int unusedArg, ObjSeqState* unusedAnimUpdate);
int nwTricky_getExtraSize(void);
void nwTricky_free(GameObject* unusedObj);
void nwTricky_update(GameObject* obj);
void nwTricky_init(GameObject* obj);

#endif /* DLLS_OBJECTS_418_NW_TRICKY_H_ */
