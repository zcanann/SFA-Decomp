#ifndef DLLS_OBJECTS_473_DIM2PRISONM_H_
#define DLLS_OBJECTS_473_DIM2PRISONM_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"
#include "main/dll/baddie_state.h"
#include "main/objprint_character_api.h"

typedef struct ObjSeqState ObjSeqState;
typedef struct ObjModel ObjModel;

/* The active-target snowmines2 placement is a fixed nine-word (0x24-byte) record. */
typedef struct Dim2PrisonMammothPlacement {
    ObjPlacement base;
    s8 rotationXByte;
    s8 spawnVariant;
    u8 unknown1A[0x0A];
} Dim2PrisonMammothPlacement;

/* dim2prisonmammoth_getExtraSize() allocates the complete 0x604-byte state block. */
typedef struct Dim2PrisonMammothState {
    BaddieState baddie;
    CharacterEyeAnimState eyeAnim;
    u8 unknown384[0x08];
    s16 stateTimer;
    u8 unknown38E[0x02];
    f32 hitReactStepScale;
    u8 unknown394[0x5FC - 0x394];
    u8 hitReactState;
    u8 unknown5FD[0x03];
    f32 callTimer;
} Dim2PrisonMammothState;

STATIC_ASSERT(offsetof(Dim2PrisonMammothPlacement, base) == 0x00);
STATIC_ASSERT(offsetof(Dim2PrisonMammothPlacement, rotationXByte) == 0x18);
STATIC_ASSERT(offsetof(Dim2PrisonMammothPlacement, spawnVariant) == 0x19);
STATIC_ASSERT(offsetof(Dim2PrisonMammothPlacement, unknown1A) == 0x1A);
STATIC_ASSERT(sizeof(Dim2PrisonMammothPlacement) == 0x24);

STATIC_ASSERT(offsetof(Dim2PrisonMammothState, baddie) == 0x000);
STATIC_ASSERT(offsetof(Dim2PrisonMammothState, eyeAnim) == 0x35C);
STATIC_ASSERT(offsetof(Dim2PrisonMammothState, unknown384) == 0x384);
STATIC_ASSERT(offsetof(Dim2PrisonMammothState, stateTimer) == 0x38C);
STATIC_ASSERT(offsetof(Dim2PrisonMammothState, unknown38E) == 0x38E);
STATIC_ASSERT(offsetof(Dim2PrisonMammothState, hitReactStepScale) == 0x390);
STATIC_ASSERT(offsetof(Dim2PrisonMammothState, unknown394) == 0x394);
STATIC_ASSERT(offsetof(Dim2PrisonMammothState, hitReactState) == 0x5FC);
STATIC_ASSERT(offsetof(Dim2PrisonMammothState, unknown5FD) == 0x5FD);
STATIC_ASSERT(offsetof(Dim2PrisonMammothState, callTimer) == 0x600);
STATIC_ASSERT(sizeof(Dim2PrisonMammothState) == 0x604);

int dim2prisonmammoth_defaultStateHandler(void);
int dim2prisonmammoth_stateHandler03(GameObject* obj, Dim2PrisonMammothState* state);
int dim2prisonmammoth_stateHandler02(GameObject* obj, Dim2PrisonMammothState* state);
int dim2prisonmammoth_stateHandler01(GameObject* obj, Dim2PrisonMammothState* state);
int dim2prisonmammoth_stateHandler00(GameObject* obj);
int dim2prisonmammoth_SeqFn(GameObject* obj, int unusedState, ObjSeqState* animUpdate);
int dim2prisonmammoth_getExtraSize(void);
int dim2prisonmammoth_getObjectTypeId(void);
void dim2prisonmammoth_free(void);
void dim2prisonmammoth_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                              s8 visible);
void dim2prisonmammoth_hitDetect(void);
void dim2prisonmammoth_update(GameObject* obj);
void dim2prisonmammoth_init(GameObject* obj, const Dim2PrisonMammothPlacement* placement);
void dim2prisonmammoth_release(void);
void dim2prisonmammoth_initialise(void);
void dim2prisonmammoth_updateModelChain(GameObject* obj, int* model);

extern ObjectDescriptor10WithPadding gDIM2PrisonMammothObjDescriptor;

#endif /* DLLS_OBJECTS_473_DIM2PRISONM_H_ */
