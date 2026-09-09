#ifndef MAIN_DLL_DR_DLL_026F_DRGENERATOR_H_
#define MAIN_DLL_DR_DLL_026F_DRGENERATOR_H_

#include "global.h"
#include "game/objects/object.h"
#include "main/objseq.h"
#include "main/dll/DR/dr_types.h"
#include "game/objects/object_setup.h"

typedef struct DrgeneratorPlacement
{
    ObjPlacement base;
    s8 initialYaw;
    u8 pad19;
    s16 timerSeconds;
    u8 pad1C[0x1E - 0x1C];
    s16 completionGameBit; /* 0x1E: completion game bit set when destroyed */
    s16 watchGameBit;      /* 0x20: game bit toggling the generator enabled state */
    u8 pad22[0x28 - 0x22];
} DrgeneratorPlacement;

STATIC_ASSERT(offsetof(DrgeneratorPlacement, completionGameBit) == 0x1E);
STATIC_ASSERT(offsetof(DrgeneratorPlacement, watchGameBit) == 0x20);
STATIC_ASSERT(offsetof(DrgeneratorPlacement, initialYaw) == 0x18);
STATIC_ASSERT(offsetof(DrgeneratorPlacement, timerSeconds) == 0x1A);
STATIC_ASSERT(sizeof(DrgeneratorPlacement) == 0x28);

typedef struct DrgeneratorState
{
    u8 pad0[0x124 - 0x0];
    f32 unk124;
    u8 pad128[0x198 - 0x128];
    s16 timerDurationFrames; /* 0x198: nominal frames handed to a linked timer object */
    u8 hitsRemaining;  /* 0x19A: remaining hit count */
    BitFlags8 flags;
} DrgeneratorState;

STATIC_ASSERT(offsetof(DrgeneratorState, timerDurationFrames) == 0x198);
STATIC_ASSERT(offsetof(DrgeneratorState, hitsRemaining) == 0x19A);
STATIC_ASSERT(offsetof(DrgeneratorState, flags) == 0x19B);
STATIC_ASSERT(sizeof(DrgeneratorState) == 0x19C);

int drgenerator_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate);
int drgenerator_getExtraSize(void);
int drgenerator_getObjectTypeId(void);
void drgenerator_free(GameObject* obj);
void drgenerator_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible);
void drgenerator_hitDetect(GameObject* obj);
void drgenerator_update(GameObject* obj);
void drgenerator_init(GameObject* obj, DrgeneratorPlacement* placement);
void drgenerator_release(void);
void drgenerator_initialise(void);

#endif /* MAIN_DLL_DR_DLL_026F_DRGENERATOR_H_ */
